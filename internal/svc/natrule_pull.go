package svc

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// NATRulePullResult is what Pull returns.
type NATRulePullResult struct {
	Profile      string
	Rule         string
	DraftPath    string
	SnapshotPath string
	DiffHash     string
	References   []ReferenceSummary
}

// Pull fetches the live NATRule, writes a snapshot + draft to disk under
// s.BaseDir, rotates old snapshots, audits, and returns paths + hash +
// references.
func (s *NATRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*NATRulePullResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	body, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("NAT rule %q: %w", ruleName, sophos.ErrNotFound)
	}

	hash, err := DiffHash(body)
	if err != nil {
		return nil, err
	}

	yamlBytes, err := marshalCanonicalYAML(body)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	snapPath, err := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
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

	if err := draft.WriteDraft(draftPath, d); err != nil {
		return nil, err
	}
	if err := draft.WriteDraft(snapPath, d); err != nil {
		return nil, err
	}
	if err := draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10); err != nil {
		return nil, err
	}

	if s.Audit != nil {
		_ = s.Audit.Write(AuditEntry{
			Profile:    name,
			Operation:  "nat_rule_pull",
			ObjectType: "NATRule",
			ObjectName: ruleName,
			Result:     "ok",
		})
	}

	return &NATRulePullResult{
		Profile:      name,
		Rule:         ruleName,
		DraftPath:    draftPath,
		SnapshotPath: snapPath,
		DiffHash:     hash,
		References:   extractNATReferences(body),
	}, nil
}

func (s *NATRuleSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// NATRuleDiffResult is what Diff returns.
type NATRuleDiffResult struct {
	Profile        string
	Rule           string
	HasChanges     bool
	UnifiedDiff    string
	StructuredDiff []DiffEntry
}

// Diff reads the draft for ruleName, finds the snapshot whose diffHash
// matches the draft's header diffHash, and returns the unified-text +
// structured diff. Local only — no firewall round-trip.
func (s *NATRuleSvc) Diff(ctx context.Context, profileName, ruleName string) (*NATRuleDiffResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	if d.Operation == "create" {
		return nil, fmt.Errorf("%w: this is a draft for a new rule; no snapshot exists until first successful push", sophos.ErrInvalidRequest)
	}

	snaps, err := draft.ListSnapshots(s.BaseDir, name, "nat", ruleName)
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

	out := &NATRuleDiffResult{
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

// extractNATReferences walks a NATRule body for known reference-bearing
// fields and returns a deduplicated summary. Sentinel values "Original"
// (translation no-op) and "None" (no link) are filtered.
func extractNATReferences(body map[string]any) []ReferenceSummary {
	ipHosts := map[string]struct{}{}
	services := map[string]struct{}{}
	rules := map[string]struct{}{}
	ifaces := map[string]struct{}{}

	collectNames(body, "OriginalSourceNetworks", "Network", ipHosts)
	collectNames(body, "OriginalDestinationNetworks", "Network", ipHosts)
	collectNames(body, "OriginalServices", "Service", services)
	collectNames(body, "InboundInterfaces", "Interface", ifaces)

	addStringIfNot := func(sink map[string]struct{}, key, sentinel string) {
		v, ok := body[key].(string)
		if !ok || v == "" || v == sentinel {
			return
		}
		sink[v] = struct{}{}
	}

	addStringIfNot(ipHosts, "TranslatedSource", "Original")
	addStringIfNot(ipHosts, "TranslatedDestination", "Original")
	addStringIfNot(services, "TranslatedService", "Original")
	addStringIfNot(rules, "LinkedFirewallrule", "None")

	out := []ReferenceSummary{}
	if len(ipHosts) > 0 {
		out = append(out, ReferenceSummary{Type: "IPHost", Names: sortedKeys(ipHosts)})
	}
	if len(services) > 0 {
		out = append(out, ReferenceSummary{Type: "Service", Names: sortedKeys(services)})
	}
	if len(rules) > 0 {
		out = append(out, ReferenceSummary{Type: "FirewallRule", Names: sortedKeys(rules)})
	}
	if len(ifaces) > 0 {
		out = append(out, ReferenceSummary{Type: "Interface", Names: sortedKeys(ifaces)})
	}
	return out
}

// NATRulePushResult is what Push and Delete return.
type NATRulePushResult struct {
	Profile     string
	Rule        string
	Operation   string
	DryRun      bool
	Preview     *Preview
	NewDiffHash string
	Item        map[string]any
}

var requiredNATRuleFields = []string{"Name", "Status", "IPFamily"}

// Push validates the draft and applies it to the firewall. Mirrors
// FirewallRuleSvc.Push with NATRule-specific marshaling and audit op.
func (s *NATRuleSvc) Push(ctx context.Context, profileName, ruleName string, ignoreHash, dryRun bool) (out *NATRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_push",
		ObjectType: "NATRule",
		ObjectName: ruleName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	draftPath, perr := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if perr != nil {
		return nil, perr
	}
	d, perr := draft.ReadDraft(draftPath)
	if perr != nil {
		return nil, perr
	}

	if d.Rule != ruleName {
		return nil, fmt.Errorf("%w: draft header rule %q does not match cli arg %q", sophos.ErrInvalidRequest, d.Rule, ruleName)
	}
	if d.Profile != name {
		return nil, fmt.Errorf("%w: draft header profile %q does not match active profile %q", sophos.ErrInvalidRequest, d.Profile, name)
	}

	parsed, perr := parseAndValidateNATRuleBody(d.Body)
	if perr != nil {
		return nil, perr
	}

	// Determine operation from draft header; default to "update" for legacy drafts.
	operation := d.Operation
	if operation == "" {
		operation = "update"
	}
	if operation == "create" {
		entryAudit.Operation = "nat_rule_create"
	}

	// 4. Read-only profile.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("NATRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: NATRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	entryAudit.ExpectedDiffHash = d.DiffHash
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}

	// 6. Dispatch on operation for diff-hash check.
	switch operation {
	case "update":
		if !ignoreHash {
			live, perr := s.Get(ctx, profileName, ruleName)
			if perr != nil {
				return nil, perr
			}
			liveHash, perr := DiffHash(live)
			if perr != nil {
				return nil, perr
			}
			if liveHash != d.DiffHash {
				return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, d.DiffHash)
			}
		}
	case "create":
		// No diff-hash check — there is no live state.
	default:
		return nil, fmt.Errorf("%w: invalid header operation %q", sophos.ErrInvalidRequest, operation)
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	inner, perr := marshalNATRule(parsed)
	if perr != nil {
		return nil, perr
	}
	sophosOp := "update"
	if operation == "create" {
		sophosOp = "add"
	}
	full, perr := sophos.BuildSetEnvelope(sophosOp, inner, c.Username, c.Password)
	if perr != nil {
		return nil, perr
	}
	entryAudit.RedactedXML = string(safety.RedactXML(full))

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
		return &NATRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: operation,
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

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
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile:   name,
					Rule:      ruleName,
					Operation: "update", // snapshot represents committed state
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10)
			}
		}
		// Flip the working draft to update mode (no-op if already update) and
		// update diffHash so the next push validates against the post-push state.
		d.Operation = "update"
		d.DiffHash = newHash
		d.PulledAt = now
		_ = draft.WriteDraft(draftPath, d)
	}

	return &NATRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   operation,
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}

func parseAndValidateNATRuleBody(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: draft body is not valid YAML: %v", sophos.ErrInvalidRequest, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: draft body is empty", sophos.ErrInvalidRequest)
	}
	for _, k := range requiredNATRuleFields {
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

// marshalNATRule converts the parsed rule body to XML wrapped in
// <NATRule>...</NATRule>. Lower-level helpers (writeMapChildren,
// writeKeyValue, writeOpen, writeClose, validateXMLName) live in
// firewallrule_pull.go and are tag-agnostic; reused as-is.
func marshalNATRule(rule map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<NATRule>")
	if err := writeMapChildren(&buf, rule); err != nil {
		return nil, err
	}
	buf.WriteString("</NATRule>")
	return buf.Bytes(), nil
}

// Delete removes a NATRule by name. Same semantics as FirewallRuleSvc.Delete.
func (s *NATRuleSvc) Delete(ctx context.Context, profileName, ruleName, expectedHash string, ignoreHash, dryRun bool) (out *NATRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_delete",
		ObjectType: "NATRule",
		ObjectName: ruleName,
	}
	if expectedHash != "" {
		entryAudit.ExpectedDiffHash = expectedHash
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	if expectedHash == "" && !ignoreHash {
		return nil, fmt.Errorf("%w: expectedDiffHash is required for delete (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
	}

	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("NATRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: NATRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	live, perr := s.Get(ctx, profileName, ruleName)
	if perr != nil {
		return nil, perr
	}
	if live == nil {
		return nil, fmt.Errorf("NAT rule %q: %w", ruleName, sophos.ErrNotFound)
	}
	if !ignoreHash {
		liveHash, perr := DiffHash(live)
		if perr != nil {
			return nil, perr
		}
		if liveHash != expectedHash {
			return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, expectedHash)
		}
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	var inner bytes.Buffer
	inner.WriteString("<NATRule><Name>")
	if err := xml.EscapeText(&inner, []byte(ruleName)); err != nil {
		return nil, err
	}
	inner.WriteString("</Name></NATRule>")
	full, perr := sophos.BuildRemoveEnvelope(inner.Bytes(), c.Username, c.Password)
	if perr != nil {
		return nil, perr
	}
	entryAudit.RedactedXML = string(safety.RedactXML(full))

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
		return &NATRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "delete",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	now := s.now()
	regularPath, _ := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
	deletedPath := strings.TrimSuffix(regularPath, ".yaml") + "-deleted.yaml"
	yamlBytes, merr := marshalCanonicalYAML(live)
	if merr == nil {
		liveHash, _ := DiffHash(live)
		_ = draft.WriteDraft(deletedPath, &draft.Draft{
			Profile: name, Rule: ruleName, PulledAt: now, DiffHash: liveHash, Body: yamlBytes,
		})
		_ = draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10)
	}

	return &NATRulePushResult{
		Profile:   name,
		Rule:      ruleName,
		Operation: "delete",
		DryRun:    false,
	}, nil
}
