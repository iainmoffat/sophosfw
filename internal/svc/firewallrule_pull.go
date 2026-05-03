package svc

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// FirewallRulePullResult is what Pull returns to the caller.
type FirewallRulePullResult struct {
	Profile      string
	Rule         string
	DraftPath    string
	SnapshotPath string
	DiffHash     string
	References   []ReferenceSummary
}

// ReferenceSummary groups names of objects referenced by a rule.
type ReferenceSummary struct {
	Type  string
	Names []string
}

// Pull fetches the live FirewallRule, writes a snapshot + draft to
// disk under s.BaseDir, rotates old snapshots, and returns paths +
// hash + references.
func (s *FirewallRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*FirewallRulePullResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	body, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("firewall rule %q: %w", ruleName, sophos.ErrNotFound)
	}

	hash, err := DiffHash(body)
	if err != nil {
		return nil, err
	}

	yamlBytes, err := marshalCanonicalYAML(body)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	snapPath, err := draft.SnapshotPath(s.BaseDir, name, ruleName, now)
	if err != nil {
		return nil, err
	}

	d := &draft.Draft{
		Profile:  name,
		Rule:     ruleName,
		PulledAt: now,
		DiffHash: hash,
		Body:     yamlBytes,
	}

	if err := draft.WriteDraft(snapPath, d); err != nil {
		return nil, err
	}
	if err := draft.WriteDraft(draftPath, d); err != nil {
		return nil, err
	}

	if err := draft.RotateSnapshots(s.BaseDir, name, ruleName, 10); err != nil {
		return nil, err
	}

	if s.Audit != nil {
		_ = s.Audit.Write(AuditEntry{
			Profile:    name,
			Operation:  "firewall_rule_pull",
			ObjectType: "FirewallRule",
			ObjectName: ruleName,
			Result:     "ok",
		})
	}

	return &FirewallRulePullResult{
		Profile:      name,
		Rule:         ruleName,
		DraftPath:    draftPath,
		SnapshotPath: snapPath,
		DiffHash:     hash,
		References:   extractReferences(body),
	}, nil
}

func (s *FirewallRuleSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// marshalCanonicalYAML marshals a value to YAML with alphabetically-
// sorted keys at every map level.
func marshalCanonicalYAML(v any) ([]byte, error) {
	node, err := buildSortedYAMLNode(v)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(node)
}

// buildSortedYAMLNode returns a *yaml.Node for v with map keys sorted.
func buildSortedYAMLNode(v any) (*yaml.Node, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		node := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range keys {
			keyN := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
			valN, err := buildSortedYAMLNode(t[k])
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, keyN, valN)
		}
		return node, nil
	case []any:
		node := &yaml.Node{Kind: yaml.SequenceNode}
		for _, item := range t {
			n, err := buildSortedYAMLNode(item)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, n)
		}
		return node, nil
	default:
		n := &yaml.Node{}
		if err := n.Encode(v); err != nil {
			return nil, err
		}
		return n, nil
	}
}

// extractReferences walks a FirewallRule body looking for known
// reference-bearing fields and returns a deduplicated summary.
func extractReferences(body map[string]any) []ReferenceSummary {
	ipHosts := map[string]struct{}{}
	zones := map[string]struct{}{}
	services := map[string]struct{}{}

	if np, ok := body["NetworkPolicy"].(map[string]any); ok {
		collectNames(np, "SourceNetworks", "Network", ipHosts)
		collectNames(np, "DestinationNetworks", "Network", ipHosts)
		collectNames(np, "Services", "Service", services)
		collectNames(np, "SourceZones", "Zone", zones)
		collectNames(np, "DestinationZones", "Zone", zones)
	}

	out := []ReferenceSummary{}
	if len(ipHosts) > 0 {
		out = append(out, ReferenceSummary{Type: "IPHost", Names: sortedKeys(ipHosts)})
	}
	if len(zones) > 0 {
		out = append(out, ReferenceSummary{Type: "Zone", Names: sortedKeys(zones)})
	}
	if len(services) > 0 {
		out = append(out, ReferenceSummary{Type: "Service", Names: sortedKeys(services)})
	}
	return out
}

func collectNames(policy map[string]any, parent, child string, sink map[string]struct{}) {
	pv, ok := policy[parent].(map[string]any)
	if !ok {
		return
	}
	v, ok := pv[child]
	if !ok {
		return
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			sink[t] = struct{}{}
		}
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				sink[s] = struct{}{}
			}
		}
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FirewallRuleDiffResult is what Diff returns.
type FirewallRuleDiffResult struct {
	Profile        string
	Rule           string
	HasChanges     bool
	UnifiedDiff    string
	StructuredDiff []DiffEntry
}

// DiffEntry is a single key-level change between snapshot and draft.
type DiffEntry struct {
	Path     string `json:"path"`
	Op       string `json:"op"` // added | removed | changed
	OldValue any    `json:"oldValue,omitempty"`
	NewValue any    `json:"newValue,omitempty"`
}

// Diff reads the draft for ruleName, finds the snapshot whose
// diffHash matches the draft's header diffHash, and returns the
// unified-text + structured diff. Local only — no firewall round-trip.
func (s *FirewallRuleSvc) Diff(ctx context.Context, profileName, ruleName string) (*FirewallRuleDiffResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	snaps, err := draft.ListSnapshots(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	var snapBody []byte
	for _, p := range snaps {
		sd, err := draft.ReadDraft(p)
		if err != nil {
			continue
		}
		if sd.DiffHash == d.DiffHash {
			snapBody = sd.Body
			break
		}
	}
	if snapBody == nil {
		return nil, fmt.Errorf("for draft %s: %w", draftPath, draft.ErrSnapshotMissing)
	}

	out := &FirewallRuleDiffResult{
		Profile:        name,
		Rule:           ruleName,
		StructuredDiff: []DiffEntry{},
	}
	out.UnifiedDiff = draft.UnifiedDiff(snapBody, d.Body, "snapshot", "draft")
	out.HasChanges = out.UnifiedDiff != ""
	if out.HasChanges {
		entries, err := structuredDiff(snapBody, d.Body)
		if err != nil {
			return nil, err
		}
		out.StructuredDiff = entries
	}
	return out, nil
}

// structuredDiff parses both YAML bodies and walks the resulting maps
// key-by-key, producing DiffEntry records.
func structuredDiff(a, b []byte) ([]DiffEntry, error) {
	var av, bv map[string]any
	if err := yaml.Unmarshal(a, &av); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &bv); err != nil {
		return nil, err
	}
	var out []DiffEntry
	walkMaps("", av, bv, &out)
	return out, nil
}

func walkMaps(prefix string, a, b map[string]any, out *[]DiffEntry) {
	keys := unionKeys(a, b)
	for _, k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		av, aok := a[k]
		bv, bok := b[k]
		switch {
		case !aok:
			*out = append(*out, DiffEntry{Path: path, Op: "added", NewValue: bv})
		case !bok:
			*out = append(*out, DiffEntry{Path: path, Op: "removed", OldValue: av})
		default:
			am, amok := av.(map[string]any)
			bm, bmok := bv.(map[string]any)
			if amok && bmok {
				walkMaps(path, am, bm, out)
				continue
			}
			if fmt.Sprintf("%v", av) != fmt.Sprintf("%v", bv) {
				*out = append(*out, DiffEntry{Path: path, Op: "changed", OldValue: av, NewValue: bv})
			}
		}
	}
}

func unionKeys(a, b map[string]any) []string {
	seen := map[string]struct{}{}
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FirewallRulePushResult is what Push returns.
type FirewallRulePushResult struct {
	Profile     string
	Rule        string
	Operation   string // "update"
	DryRun      bool
	Preview     *Preview       // dry-run only
	NewDiffHash string         // apply only
	Item        map[string]any // apply only — refetched body
}

// requiredFirewallRuleFields enumerates the top-level YAML keys a
// FirewallRule body MUST carry.
var requiredFirewallRuleFields = []string{"Name", "Status", "IPFamily", "PolicyType"}

// Push validates the draft, checks drift via diff hash, builds and sends a
// <Set operation="update"><FirewallRule>...</FirewallRule></Set> envelope,
// archives the new state, and audits.
func (s *FirewallRuleSvc) Push(ctx context.Context, profileName, ruleName string, ignoreHash, dryRun bool) (out *FirewallRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	// Build the audit entry skeleton early so every pre-flight rejection path
	// is captured in the audit log.
	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "firewall_rule_push",
		ObjectType: "FirewallRule",
		ObjectName: ruleName,
	}

	// Defer a write that fires on any error before an explicit Result is set.
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	// 1. Read draft.
	draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	// Populate ExpectedDiffHash now that we have the draft header.
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	} else {
		entryAudit.ExpectedDiffHash = d.DiffHash
	}

	// 2. Header sanity.
	if d.Rule != ruleName {
		return nil, fmt.Errorf("%w: draft header rule %q does not match cli arg %q", sophos.ErrInvalidRequest, d.Rule, ruleName)
	}
	if d.Profile != name {
		return nil, fmt.Errorf("%w: draft header profile %q does not match active profile %q", sophos.ErrInvalidRequest, d.Profile, name)
	}

	// 3. Parse body + required-field validation.
	parsed, err := parseAndValidateRuleBody(d.Body)
	if err != nil {
		return nil, err
	}

	// 4. Read-only profile.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	// 5. Catalog mutable check.
	catEntry, ok := s.Inner.Catalog.Resolve("FirewallRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: FirewallRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	// 6. Refetch live + diff hash check (unless ignored).
	if !ignoreHash {
		live, err := s.Get(ctx, profileName, ruleName)
		if err != nil {
			return nil, err
		}
		liveHash, err := DiffHash(live)
		if err != nil {
			return nil, err
		}
		if liveHash != d.DiffHash {
			return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, d.DiffHash)
		}
	}

	// 7. Build envelope.
	c, err := s.Inner.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	inner, err := marshalFirewallRule(parsed)
	if err != nil {
		return nil, err
	}
	full, err := sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
	if err != nil {
		return nil, err
	}

	// Populate RedactedXML now that we have the full envelope.
	entryAudit.RedactedXML = string(safety.RedactXML(full))

	// 8. Dry-run path.
	if dryRun {
		mutating, verbs := safety.IsMutating(full)
		pv := &Preview{
			Profile:        name,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    entryAudit.RedactedXML,
			WouldSendBytes: len(full),
		}
		entryAudit.Result = "ok (dry-run)"
		_ = s.Audit.Write(entryAudit)
		return &FirewallRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "update",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	// 9. Apply path.
	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	// 10. Refetch, archive, update draft hash.
	refetched, _ := s.Get(ctx, profileName, ruleName)
	newHash := ""
	if refetched != nil {
		nh, hashErr := DiffHash(refetched)
		if hashErr == nil {
			newHash = nh
		}
	}
	if refetched != nil && newHash != "" {
		now := s.now()
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, ruleName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile: name, Rule: ruleName, PulledAt: now, DiffHash: newHash, Body: yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, ruleName, 10)
			}
		}
		// Update draft header diffHash (keep the user's body edits) so the
		// next push validates against the post-push state.
		d.DiffHash = newHash
		_ = draft.WriteDraft(draftPath, d)
	}

	return &FirewallRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}

// parseAndValidateRuleBody unmarshals the draft body and verifies that
// the four required top-level fields are present and non-empty.
func parseAndValidateRuleBody(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: draft body is not valid YAML: %v", sophos.ErrInvalidRequest, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: draft body is empty", sophos.ErrInvalidRequest)
	}
	for _, k := range requiredFirewallRuleFields {
		v, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("%w: draft body missing required field %q", sophos.ErrInvalidRequest, k)
		}
		if str, isStr := v.(string); isStr && str == "" {
			return nil, fmt.Errorf("%w: draft body field %q is empty", sophos.ErrInvalidRequest, k)
		}
	}
	return m, nil
}

// validXMLName is the allowlist regex for legal XML element names per the spec.
var validXMLName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// validateXMLName checks if a string is a valid XML element name.
func validateXMLName(name string) error {
	if !validXMLName.MatchString(name) {
		return fmt.Errorf("%w: invalid XML element name %q", sophos.ErrInvalidRequest, name)
	}
	return nil
}

// marshalFirewallRule converts the parsed rule body to XML wrapped in
// <FirewallRule>...</FirewallRule>.
func marshalFirewallRule(rule map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<FirewallRule>")
	if err := writeMapChildren(&buf, rule); err != nil {
		return nil, err
	}
	buf.WriteString("</FirewallRule>")
	return buf.Bytes(), nil
}

func writeMapChildren(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeKeyValue(buf, k, m[k]); err != nil {
			return err
		}
	}
	return nil
}

func writeKeyValue(buf *bytes.Buffer, key string, val any) error {
	if err := validateXMLName(key); err != nil {
		return err
	}
	switch v := val.(type) {
	case nil:
		return nil
	case string:
		writeOpen(buf, key)
		if err := xml.EscapeText(buf, []byte(v)); err != nil {
			return err
		}
		writeClose(buf, key)
	case bool:
		writeOpen(buf, key)
		fmt.Fprintf(buf, "%t", v)
		writeClose(buf, key)
	case int, int64, float64:
		writeOpen(buf, key)
		fmt.Fprintf(buf, "%v", v)
		writeClose(buf, key)
	case map[string]any:
		writeOpen(buf, key)
		if err := writeMapChildren(buf, v); err != nil {
			return err
		}
		writeClose(buf, key)
	case []any:
		// Emit one <key>VAL</key> per item.
		for _, item := range v {
			if err := writeKeyValue(buf, key, item); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported value type for key %q: %T", key, val)
	}
	return nil
}

func writeOpen(buf *bytes.Buffer, key string) {
	buf.WriteString("<")
	buf.WriteString(key)
	buf.WriteString(">")
}

func writeClose(buf *bytes.Buffer, key string) {
	buf.WriteString("</")
	buf.WriteString(key)
	buf.WriteString(">")
}

// Delete removes a FirewallRule from the appliance, enforcing expectedHash
// validation and archiving the -deleted snapshot on success.
func (s *FirewallRuleSvc) Delete(ctx context.Context, profileName, ruleName, expectedHash string, ignoreHash, dryRun bool) (out *FirewallRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	// Build the audit entry skeleton early so every pre-flight rejection path
	// is captured in the audit log.
	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "firewall_rule_delete",
		ObjectType: "FirewallRule",
		ObjectName: ruleName,
	}
	if expectedHash != "" {
		entryAudit.ExpectedDiffHash = expectedHash
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}

	// Defer a write that fires on any error before an explicit Result is set.
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	// 1. CLI-side enforcement (defense in depth).
	if expectedHash == "" && !ignoreHash {
		return nil, fmt.Errorf("%w: expectedDiffHash is required for delete (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
	}

	// 2. Read-only profile.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	// 3. Catalog Mutable check.
	catEntry, ok := s.Inner.Catalog.Resolve("FirewallRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: FirewallRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	// 4. Refetch + hash compare (unless ignored).
	live, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if live == nil {
		return nil, fmt.Errorf("firewall rule %q: %w", ruleName, sophos.ErrNotFound)
	}
	if !ignoreHash {
		liveHash, err := DiffHash(live)
		if err != nil {
			return nil, err
		}
		if liveHash != expectedHash {
			return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, expectedHash)
		}
	}

	// 5. Build envelope (XML-escape the rule name).
	c, err := s.Inner.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	var inner bytes.Buffer
	inner.WriteString("<FirewallRule><Name>")
	if err := xml.EscapeText(&inner, []byte(ruleName)); err != nil {
		return nil, err
	}
	inner.WriteString("</Name></FirewallRule>")
	full, err := sophos.BuildRemoveEnvelope(inner.Bytes(), c.Username, c.Password)
	if err != nil {
		return nil, err
	}

	// Populate RedactedXML now that we have the full envelope.
	entryAudit.RedactedXML = string(safety.RedactXML(full))

	// 6. Dry-run.
	if dryRun {
		mutating, verbs := safety.IsMutating(full)
		pv := &Preview{
			Profile:        name,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    entryAudit.RedactedXML,
			WouldSendBytes: len(full),
		}
		entryAudit.Result = "ok (dry-run)"
		_ = s.Audit.Write(entryAudit)
		return &FirewallRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "delete",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	// 7. Apply.
	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	// 8. Archive last-known state with -deleted suffix.
	now := s.now()
	regularPath, _ := draft.SnapshotPath(s.BaseDir, name, ruleName, now)
	deletedPath := strings.TrimSuffix(regularPath, ".yaml") + "-deleted.yaml"
	yamlBytes, merr := marshalCanonicalYAML(live)
	if merr == nil {
		liveHash, _ := DiffHash(live)
		_ = draft.WriteDraft(deletedPath, &draft.Draft{
			Profile: name, Rule: ruleName, PulledAt: now, DiffHash: liveHash, Body: yamlBytes,
		})
		_ = draft.RotateSnapshots(s.BaseDir, name, ruleName, 10)
	}

	return &FirewallRulePushResult{
		Profile:   name,
		Rule:      ruleName,
		Operation: "delete",
		DryRun:    false,
	}, nil
}
