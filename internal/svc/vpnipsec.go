package svc

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// VPNIPsecSvc provides read + draft + mutating coverage for the
// VPNIPsecConnection catalog tag (site-to-site IPsec tunnels). Mirrors
// the Phase 7-9 FirewallRule patterns: full draft cycle (New, Pull,
// Diff, Push) plus body-as-map (CreateInline, UpdateInline, Delete).
type VPNIPsecSvc struct {
	Inner   *ObjectSvc
	Audit   *AuditLog
	BaseDir string
	Now     func() time.Time // injectable for tests; defaults to time.Now()
	Version string
}

// VPNIPsecPullResult is what Pull returns to the caller.
type VPNIPsecPullResult struct {
	Profile      string
	Tunnel       string
	DraftPath    string
	SnapshotPath string
	DiffHash     string
	References   []ReferenceSummary
}

// VPNIPsecNewResult mirrors VPNIPsecPullResult — same fields, reused
// render envelope. SnapshotPath and DiffHash are empty on a fresh new.
type VPNIPsecNewResult = VPNIPsecPullResult

// VPNIPsecPushResult is what Push / CreateInline / UpdateInline /
// Delete return.
type VPNIPsecPushResult struct {
	Profile     string
	Tunnel      string
	Operation   string // "create" | "update" | "delete"
	DryRun      bool
	Preview     *Preview       // dry-run only
	NewDiffHash string         // apply only
	Item        map[string]any // apply only — refetched body
}

// vpnIPsecTemplate is the structurally-valid skeleton emitted by `new`
// when no --from is supplied. Defaults are fail-safe: Status=Disable so
// the tunnel is inert until the user reviews and re-enables.
//
// NOTE: Sophos rejects tunnels lacking real peer config / traffic
// selectors / authentication with "Operation could not be performed on
// Entity". The user is expected to edit the draft and add the real
// fields before pushing. For most users `vpn ipsec new <name> --from
// <existing>` is the more practical starting point.
const vpnIPsecTemplate = `Name: __NAME__
Description: ""
Status: Disable
ConnectionType: SiteToSite
`

// requiredVPNIPsecFields enumerates the top-level YAML keys a
// VPNIPsecConnection body MUST carry. Best-guess based on T2 Get
// output; verified at T10 dry-run against the reference firewall.
var requiredVPNIPsecFields = []string{"Name", "Status", "ConnectionType"}

// Get fetches a single VPNIPsecConnection record by name. The returned
// map includes the `_diffHash` field injected by ObjectSvc.Get for
// mutable catalog entries (Phase 12 T5). Returns an error wrapping
// sophos.ErrNotFound when no record matches.
func (s *VPNIPsecSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
	inner, err := s.Inner.Get(ctx, profileName, "VPNIPsecConnection", name)
	if err != nil {
		return nil, err
	}
	return toMap(inner.Data)
}

func (s *VPNIPsecSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// extractVPNIPsecReferences walks a VPNIPsecConnection body looking
// for known reference-bearing fields (Policy → IPsecPolicy, Profile /
// VPNProfile → VPNProfile) and returns a deduplicated summary.
func extractVPNIPsecReferences(body map[string]any) []ReferenceSummary {
	policies := map[string]struct{}{}
	profiles := map[string]struct{}{}

	if v, ok := body["Policy"].(string); ok && v != "" {
		policies[v] = struct{}{}
	}
	if v, ok := body["IPsecPolicy"].(string); ok && v != "" {
		policies[v] = struct{}{}
	}
	if v, ok := body["Profile"].(string); ok && v != "" {
		profiles[v] = struct{}{}
	}
	if v, ok := body["VPNProfile"].(string); ok && v != "" {
		profiles[v] = struct{}{}
	}

	out := []ReferenceSummary{}
	if len(policies) > 0 {
		out = append(out, ReferenceSummary{Type: "IPsecPolicy", Names: sortedKeys(policies)})
	}
	if len(profiles) > 0 {
		out = append(out, ReferenceSummary{Type: "VPNProfile", Names: sortedKeys(profiles)})
	}
	return out
}

// New writes a new draft for tunnelName at drafts/vpn/<slug>.yaml. If
// fromTunnel is non-empty, the existing tunnel's body is pulled and
// used as the starting template; otherwise vpnIPsecTemplate is used.
//
// Errors:
//   - draft already exists at the resolved path → ErrInvalidRequest.
//   - --from tunnel doesn't exist → ErrNotFound.
//
// Audit: writes "vpn_ipsec_new" entry on success.
func (s *VPNIPsecSvc) New(ctx context.Context, profileName, tunnelName, fromTunnel string) (out *VPNIPsecNewResult, err error) {
	_, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "vpn_ipsec_new",
		ObjectType: "VPNIPsecConnection",
		ObjectName: tunnelName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	// 1. Compose body.
	var bodyMap map[string]any
	if fromTunnel == "" {
		if perr := yaml.Unmarshal([]byte(vpnIPsecTemplate), &bodyMap); perr != nil {
			return nil, fmt.Errorf("template parse: %w", perr)
		}
		bodyMap["Name"] = tunnelName
	} else {
		live, perr := s.Get(ctx, profileName, fromTunnel)
		if perr != nil {
			return nil, perr
		}
		if live == nil {
			return nil, fmt.Errorf("vpn ipsec tunnel %q: %w", fromTunnel, sophos.ErrNotFound)
		}
		// Shallow copy to avoid mutating the map returned by Get.
		bodyMap = make(map[string]any, len(live))
		for k, v := range live {
			if k == "_diffHash" {
				continue
			}
			bodyMap[k] = v
		}
		bodyMap["Name"] = tunnelName
	}

	yamlBytes, perr := marshalCanonicalYAML(bodyMap)
	if perr != nil {
		return nil, perr
	}

	// 2. Resolve draft path; reject if file exists.
	draftPath, perr := draft.DraftPath(s.BaseDir, name, "vpn", tunnelName)
	if perr != nil {
		return nil, perr
	}
	if _, statErr := os.Stat(draftPath); statErr == nil {
		return nil, fmt.Errorf("%w: draft already exists at %s; delete it first or use a different name", sophos.ErrInvalidRequest, draftPath)
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	// 3. Build and write the draft (no snapshot — there's no live state yet).
	now := s.now()
	d := &draft.Draft{
		Profile:   name,
		Rule:      tunnelName,
		Operation: "create",
		PulledAt:  now,
		DiffHash:  "",
		Body:      yamlBytes,
	}
	if perr := draft.WriteDraft(draftPath, d); perr != nil {
		return nil, perr
	}

	// 4. Audit success.
	entryAudit.Result = "ok"
	if s.Audit != nil {
		_ = s.Audit.Write(entryAudit)
	}

	return &VPNIPsecNewResult{
		Profile:    name,
		Tunnel:     tunnelName,
		DraftPath:  draftPath,
		References: extractVPNIPsecReferences(bodyMap),
	}, nil
}

// Pull fetches the live VPNIPsecConnection, writes a snapshot + draft
// to disk under s.BaseDir, rotates old snapshots, and returns paths +
// hash + references.
func (s *VPNIPsecSvc) Pull(ctx context.Context, profileName, tunnelName string) (*VPNIPsecPullResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	body, err := s.Get(ctx, profileName, tunnelName)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("vpn ipsec tunnel %q: %w", tunnelName, sophos.ErrNotFound)
	}
	// Strip the sophosfw-internal `_diffHash` field that ObjectSvc.Get
	// injects for catalog-mutable types, so it never lands in the draft
	// YAML on disk (and therefore never round-trips into the push XML).
	delete(body, "_diffHash")

	hash, err := DiffHash(body)
	if err != nil {
		return nil, err
	}

	yamlBytes, err := marshalCanonicalYAML(body)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, "vpn", tunnelName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	snapPath, err := draft.SnapshotPath(s.BaseDir, name, "vpn", tunnelName, now)
	if err != nil {
		return nil, err
	}

	d := &draft.Draft{
		Profile:  name,
		Rule:     tunnelName,
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

	if err := draft.RotateSnapshots(s.BaseDir, name, "vpn", tunnelName, 10); err != nil {
		return nil, err
	}

	if s.Audit != nil {
		_ = s.Audit.Write(AuditEntry{
			Profile:    name,
			Operation:  "vpn_ipsec_pull",
			ObjectType: "VPNIPsecConnection",
			ObjectName: tunnelName,
			Result:     "ok",
		})
	}

	return &VPNIPsecPullResult{
		Profile:      name,
		Tunnel:       tunnelName,
		DraftPath:    draftPath,
		SnapshotPath: snapPath,
		DiffHash:     hash,
		References:   extractVPNIPsecReferences(body),
	}, nil
}

// VPNIPsecDiffResult is what Diff returns.
type VPNIPsecDiffResult struct {
	Profile        string
	Tunnel         string
	HasChanges     bool
	UnifiedDiff    string
	StructuredDiff []DiffEntry
}

// Diff reads the draft for tunnelName, finds the snapshot whose
// diffHash matches the draft's header diffHash, and returns the
// unified-text + structured diff. Local only — no firewall round-trip.
func (s *VPNIPsecSvc) Diff(ctx context.Context, profileName, tunnelName string) (*VPNIPsecDiffResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, "vpn", tunnelName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	if d.Operation == "create" {
		return nil, fmt.Errorf("%w: this is a draft for a new tunnel; no snapshot exists until first successful push", sophos.ErrInvalidRequest)
	}

	snaps, err := draft.ListSnapshots(s.BaseDir, name, "vpn", tunnelName)
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

	out := &VPNIPsecDiffResult{
		Profile:        name,
		Tunnel:         tunnelName,
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

// Push validates the draft, checks drift via diff hash, builds and sends a
// <Set operation="update"><VPNIPsecConnection>...</VPNIPsecConnection></Set>
// envelope, archives the new state, and audits.
//
// expectedHash, if non-empty, overrides the draft's stored DiffHash for
// the drift check (rare; CLI normally trusts the draft header).
func (s *VPNIPsecSvc) Push(ctx context.Context, profileName, tunnelName, expectedHash string, ignoreHash, dryRun bool) (out *VPNIPsecPushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "vpn_ipsec_push",
		ObjectType: "VPNIPsecConnection",
		ObjectName: tunnelName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	// 1. Read draft.
	draftPath, err := draft.DraftPath(s.BaseDir, name, "vpn", tunnelName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	// Resolve effective expected hash.
	effectiveHash := expectedHash
	if effectiveHash == "" {
		effectiveHash = d.DiffHash
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	} else {
		entryAudit.ExpectedDiffHash = effectiveHash
	}

	// 2. Header sanity.
	if d.Rule != tunnelName {
		return nil, fmt.Errorf("%w: draft header tunnel %q does not match cli arg %q", sophos.ErrInvalidRequest, d.Rule, tunnelName)
	}
	if d.Profile != name {
		return nil, fmt.Errorf("%w: draft header profile %q does not match active profile %q", sophos.ErrInvalidRequest, d.Profile, name)
	}

	// 3. Parse body + required-field validation.
	parsed, err := parseAndValidateVPNIPsecBody(d.Body)
	if err != nil {
		return nil, err
	}

	// Determine operation from draft header; default to "update" for legacy drafts.
	operation := d.Operation
	if operation == "" {
		operation = "update"
	}
	if operation == "create" {
		entryAudit.Operation = "vpn_ipsec_create"
	}

	// 4. Read-only profile.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	// 5. Catalog mutable check.
	catEntry, ok := s.Inner.Catalog.Resolve("VPNIPsecConnection")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: VPNIPsecConnection is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	// 6. Dispatch on operation for diff-hash check.
	switch operation {
	case "update":
		if !ignoreHash {
			live, err := s.Get(ctx, profileName, tunnelName)
			if err != nil {
				return nil, err
			}
			liveHash, err := DiffHash(live)
			if err != nil {
				return nil, err
			}
			if liveHash != effectiveHash {
				return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, effectiveHash)
			}
		}
	case "create":
		// No diff-hash check — there is no live state.
	default:
		return nil, fmt.Errorf("%w: invalid header operation %q", sophos.ErrInvalidRequest, operation)
	}

	// 7. Build envelope.
	c, err := s.Inner.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	inner, err := marshalObjectBody("VPNIPsecConnection", parsed)
	if err != nil {
		return nil, err
	}
	sophosOp := "update"
	if operation == "create" {
		sophosOp = "add"
	}
	full, err := sophos.BuildSetEnvelope(sophosOp, inner, c.Username, c.Password)
	if err != nil {
		return nil, err
	}

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
		return &VPNIPsecPushResult{
			Profile:   name,
			Tunnel:    tunnelName,
			Operation: operation,
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
	refetched, _ := s.Get(ctx, profileName, tunnelName)
	newHash := ""
	if refetched != nil {
		nh, hashErr := DiffHash(refetched)
		if hashErr == nil {
			newHash = nh
		}
	}
	if refetched != nil && newHash != "" {
		now := s.now()
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "vpn", tunnelName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile:   name,
					Rule:      tunnelName,
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "vpn", tunnelName, 10)
			}
		}
		// Flip the working draft to update mode and refresh hash for next push.
		d.Operation = "update"
		d.DiffHash = newHash
		d.PulledAt = now
		_ = draft.WriteDraft(draftPath, d)
	}

	return &VPNIPsecPushResult{
		Profile:     name,
		Tunnel:      tunnelName,
		Operation:   operation,
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}

// parseAndValidateVPNIPsecBody unmarshals the draft body and verifies
// that the required top-level fields are present and non-empty. Strips
// any `_diffHash` left behind by an older or hand-edited draft.
func parseAndValidateVPNIPsecBody(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: draft body is not valid YAML: %v", sophos.ErrInvalidRequest, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: draft body is empty", sophos.ErrInvalidRequest)
	}
	// Defense in depth: strip the sophosfw-internal `_diffHash` field so
	// it cannot reach marshalObjectBody and leak into the XML envelope
	// (Phase 13.x regression guard).
	delete(m, "_diffHash")
	for _, k := range requiredVPNIPsecFields {
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

// CreateInline creates a new VPNIPsecConnection from an in-memory body
// (no draft file). Mirrors Push for the create path. On apply success,
// writes the FIRST snapshot under snapshots/vpn/<slug>-<utc>.yaml so
// subsequent pull/diff have a starting point.
//
// Audit op: vpn_ipsec_create.
func (s *VPNIPsecSvc) CreateInline(ctx context.Context, profileName, tunnelName string, body map[string]any, dryRun bool) (out *VPNIPsecPushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "vpn_ipsec_create",
		ObjectType: "VPNIPsecConnection",
		ObjectName: tunnelName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	// Phase 14 body-clone: clone the caller's map and strip _diffHash on
	// the clone, never the original. CLI/MCP fan-out runs preflight
	// goroutines in parallel against the same body; concurrent delete on
	// a shared map would trip Go's "concurrent map writes" runtime panic.
	if body != nil {
		cloned := make(map[string]any, len(body))
		for k, v := range body {
			if k == "_diffHash" {
				continue
			}
			cloned[k] = v
		}
		body = cloned
	}

	for _, k := range requiredVPNIPsecFields {
		v, ok := body[k]
		if !ok {
			return nil, fmt.Errorf("%w: body missing required field %q", sophos.ErrInvalidRequest, k)
		}
		if str, isStr := v.(string); isStr && str == "" {
			return nil, fmt.Errorf("%w: body field %q is empty", sophos.ErrInvalidRequest, k)
		}
	}

	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("VPNIPsecConnection")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: VPNIPsecConnection is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	inner, perr := marshalObjectBody("VPNIPsecConnection", body)
	if perr != nil {
		return nil, perr
	}
	full, perr := sophos.BuildSetEnvelope("add", inner, c.Username, c.Password)
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
		return &VPNIPsecPushResult{
			Profile:   name,
			Tunnel:    tunnelName,
			Operation: "create",
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

	refetched, _ := s.Get(ctx, profileName, tunnelName)
	newHash := ""
	if refetched != nil {
		nh, hashErr := DiffHash(refetched)
		if hashErr == nil {
			newHash = nh
		}
	}
	if refetched != nil && newHash != "" {
		now := s.now()
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "vpn", tunnelName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile:   name,
					Rule:      tunnelName,
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "vpn", tunnelName, 10)
			}
		}
	}

	return &VPNIPsecPushResult{
		Profile:     name,
		Tunnel:      tunnelName,
		Operation:   "create",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}

// UpdateInline updates an existing VPNIPsecConnection from an in-memory
// body (no draft file). expectedHash is required unless ignoreHash.
// Audit op: vpn_ipsec_push.
func (s *VPNIPsecSvc) UpdateInline(ctx context.Context, profileName, tunnelName string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (out *VPNIPsecPushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "vpn_ipsec_push",
		ObjectType: "VPNIPsecConnection",
		ObjectName: tunnelName,
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

	// CLI-side enforcement: expectedHash required unless ignoreHash.
	if expectedHash == "" && !ignoreHash {
		return nil, fmt.Errorf("%w: expectedDiffHash is required for update (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
	}

	// Phase 14 body-clone (see CreateInline for rationale).
	if body != nil {
		cloned := make(map[string]any, len(body))
		for k, v := range body {
			if k == "_diffHash" {
				continue
			}
			cloned[k] = v
		}
		body = cloned
	}

	for _, k := range requiredVPNIPsecFields {
		v, ok := body[k]
		if !ok {
			return nil, fmt.Errorf("%w: body missing required field %q", sophos.ErrInvalidRequest, k)
		}
		if str, isStr := v.(string); isStr && str == "" {
			return nil, fmt.Errorf("%w: body field %q is empty", sophos.ErrInvalidRequest, k)
		}
	}

	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("VPNIPsecConnection")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: VPNIPsecConnection is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	if !ignoreHash {
		live, perr := s.Get(ctx, profileName, tunnelName)
		if perr != nil {
			return nil, perr
		}
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
	inner, perr := marshalObjectBody("VPNIPsecConnection", body)
	if perr != nil {
		return nil, perr
	}
	full, perr := sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
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
		return &VPNIPsecPushResult{
			Profile:   name,
			Tunnel:    tunnelName,
			Operation: "update",
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

	refetched, _ := s.Get(ctx, profileName, tunnelName)
	newHash := ""
	if refetched != nil {
		nh, hashErr := DiffHash(refetched)
		if hashErr == nil {
			newHash = nh
		}
	}
	if refetched != nil && newHash != "" {
		now := s.now()
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "vpn", tunnelName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile:   name,
					Rule:      tunnelName,
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "vpn", tunnelName, 10)
			}
		}
	}

	return &VPNIPsecPushResult{
		Profile:     name,
		Tunnel:      tunnelName,
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}

// Delete removes a VPNIPsecConnection from the appliance, enforcing
// expectedHash validation and archiving the -deleted snapshot on
// success. Audit op: vpn_ipsec_delete.
func (s *VPNIPsecSvc) Delete(ctx context.Context, profileName, tunnelName, expectedHash string, ignoreHash, dryRun bool) (out *VPNIPsecPushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "vpn_ipsec_delete",
		ObjectType: "VPNIPsecConnection",
		ObjectName: tunnelName,
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

	// 1. CLI-side enforcement.
	if expectedHash == "" && !ignoreHash {
		return nil, fmt.Errorf("%w: expectedDiffHash is required for delete (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
	}

	// 2. Read-only profile.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	// 3. Catalog Mutable check.
	catEntry, ok := s.Inner.Catalog.Resolve("VPNIPsecConnection")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: VPNIPsecConnection is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	// 4. Refetch + hash compare (unless ignored).
	live, err := s.Get(ctx, profileName, tunnelName)
	if err != nil {
		return nil, err
	}
	if live == nil {
		return nil, fmt.Errorf("vpn ipsec tunnel %q: %w", tunnelName, sophos.ErrNotFound)
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

	// 5. Build envelope (XML-escape the tunnel name).
	c, err := s.Inner.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	var inner bytes.Buffer
	inner.WriteString("<VPNIPsecConnection><Name>")
	if err := xml.EscapeText(&inner, []byte(tunnelName)); err != nil {
		return nil, err
	}
	inner.WriteString("</Name></VPNIPsecConnection>")
	full, err := sophos.BuildRemoveEnvelope(inner.Bytes(), c.Username, c.Password)
	if err != nil {
		return nil, err
	}

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
		return &VPNIPsecPushResult{
			Profile:   name,
			Tunnel:    tunnelName,
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
	regularPath, _ := draft.SnapshotPath(s.BaseDir, name, "vpn", tunnelName, now)
	deletedPath := strings.TrimSuffix(regularPath, ".yaml") + "-deleted.yaml"
	yamlBytes, merr := marshalCanonicalYAML(live)
	if merr == nil {
		liveHash, _ := DiffHash(live)
		_ = draft.WriteDraft(deletedPath, &draft.Draft{
			Profile: name, Rule: tunnelName, PulledAt: now, DiffHash: liveHash, Body: yamlBytes,
		})
		_ = draft.RotateSnapshots(s.BaseDir, name, "vpn", tunnelName, 10)
	}

	return &VPNIPsecPushResult{
		Profile:   name,
		Tunnel:    tunnelName,
		Operation: "delete",
		DryRun:    false,
	}, nil
}
