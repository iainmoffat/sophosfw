# sophosfw Phase 10 Implementation Plan

**Goal:** Add 6 mutating MCP tools for FirewallRule and NATRule (3 per rule type) plus modify the existing `<rule>_show` tools to always include `_diffHash`. Brings the agent-facing surface to parity with the cli.

**Architecture:** Stateless MCP — agents pass rule body inline through tool args; no draft files involved. New svc methods `CreateInline`/`UpdateInline` mirror Phase 7-9's `Push`/`New` minus the draft-read step. The existing `Delete` methods are reused as-is. Mirrors the Phase 6 IPHost MCP pattern.

**Tech Stack:** Go 1.26+, `github.com/modelcontextprotocol/go-sdk` v1.5.0 (alias `sdkmcp`). No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-03-sophosfw-phase10-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.8.0-phase9`. Working dir: `/Users/ipm/code/sophosfw`.

```bash
git status
go test ./... -count=1
```
Expected: clean status, all tests pass.

## File structure

**New files:**
- `internal/mcp/firewallrule_mutation.go` — 3 handlers + 3 input types + tool registration helper.
- `internal/mcp/firewallrule_mutation_test.go` — 8 tests for the firewall handlers.
- `internal/mcp/natrule_mutation.go` — 3 NAT handlers + types + registration helper.
- `internal/mcp/natrule_mutation_test.go` — 8 tests for the NAT handlers.

**Modified files:**
- `internal/svc/firewallrule_create.go` — add `CreateInline` method.
- `internal/svc/firewallrule_pull.go` — add `UpdateInline` method.
- `internal/svc/firewallrule_create_test.go` — extend with `CreateInline` tests.
- `internal/svc/firewallrule_pull_test.go` — extend with `UpdateInline` tests.
- `internal/svc/natrule_create.go` — add `CreateInline` method.
- `internal/svc/natrule_pull.go` — add `UpdateInline` method.
- `internal/svc/natrule_create_test.go` — extend with `CreateInline` tests.
- `internal/svc/natrule_pull_test.go` — extend with `UpdateInline` tests.
- `internal/mcp/firewallrule.go` — `handleFirewallRuleShow` injects `_diffHash` in response; register the 3 new tools.
- `internal/mcp/natrule.go` — same for NAT.
- `internal/mcp/firewallrule_test.go` — assert `_diffHash` present in show response.
- `internal/mcp/natrule_test.go` — same.
- `internal/mcp/server.go` (or wherever tool count is asserted) — register the 6 new tools.
- `internal/mcp/server_test.go` — update tool count 24 → 30.
- `internal/testutil/integration_test.go` — append integration tests.
- `docs/api-coverage.md` — update FirewallRule + NATRule MCP cells.
- `docs/roadmap.md` — Phase 10 marked complete.

---

## Task 1: `FirewallRuleSvc.CreateInline` + `UpdateInline`

**Files:**
- Modify: `internal/svc/firewallrule_create.go` (add CreateInline)
- Modify: `internal/svc/firewallrule_pull.go` (add UpdateInline)
- Modify: `internal/svc/firewallrule_create_test.go` (add CreateInline tests)
- Modify: `internal/svc/firewallrule_pull_test.go` (add UpdateInline tests)

Both methods follow the existing draft-driven `Push`/`New` patterns minus the draft-read step.

- [ ] **Step 1: Write failing CreateInline tests**

Append to `/Users/ipm/code/sophosfw/internal/svc/firewallrule_create_test.go`:

```go
func TestFirewallRuleSvc_CreateInline_DryRun(t *testing.T) {
	body := map[string]any{
		"Name":       "X",
		"Status":     "Disable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"NetworkPolicy": map[string]any{
			"Action":         "Drop",
			"SourceNetworks": map[string]any{"Network": "Russian Federation"},
		},
	}
	svc, fc, _ := newFwRuleSvc(t, nil)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestFirewallRuleSvc_CreateInline_Apply(t *testing.T) {
	body := map[string]any{
		"Name":       "X",
		"Status":     "Disable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"NetworkPolicy": map[string]any{
			"Action":         "Drop",
			"SourceNetworks": map[string]any{"Network": "Russian Federation"},
		},
	}
	// Fake's body sets up what s.Get will return AFTER apply (for refetch).
	svc, fc, _ := newFwRuleSvc(t, body)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<FirewallRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)
}

func TestFirewallRuleSvc_CreateInline_Apply_WritesFirstSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	snaps0, err := draft.ListSnapshots(baseDir, "home", "firewall", "X")
	require.NoError(t, err)
	require.Empty(t, snaps0)

	_, err = svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)

	snaps1, err := draft.ListSnapshots(baseDir, "home", "firewall", "X")
	require.NoError(t, err)
	require.Len(t, snaps1, 1)
}

func TestFirewallRuleSvc_CreateInline_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		// PolicyType missing.
	}
	svc, fc, _ := newFwRuleSvc(t, nil)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "PolicyType")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_CreateInline_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, nil)
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_CreateInline_AuditTagsCreate(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_create"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_CreateInline -v
```

- [ ] **Step 3: Implement `CreateInline`**

Append to `/Users/ipm/code/sophosfw/internal/svc/firewallrule_create.go`:

```go
import (
	// add if not present:
	"github.com/iainmoffat/sophosfw/internal/safety"
)

// CreateInline creates a new FirewallRule from an in-memory body (no
// draft file). Mirrors `Push` for the create path but skips the draft-
// read step. On apply success, writes the FIRST snapshot under
// snapshots/firewall/<slug>-<utc>.yaml so subsequent cli pull/diff on
// this rule have a starting point.
//
// Errors:
//   - read-only profile → ErrReadOnlyViolation
//   - catalog Mutable=false → ErrInvalidRequest
//   - body fails required-field validation → ErrInvalidRequest
//   - Sophos rejects → propagated
//
// Audit op: firewall_rule_create.
func (s *FirewallRuleSvc) CreateInline(ctx context.Context, profileName, ruleName string, body map[string]any, dryRun bool) (out *FirewallRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "firewall_rule_create",
		ObjectType: "FirewallRule",
		ObjectName: ruleName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	// Required-field validation.
	for _, k := range requiredFirewallRuleFields {
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

	catEntry, ok := s.Inner.Catalog.Resolve("FirewallRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: FirewallRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	inner, perr := marshalFirewallRule(body)
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
		return &FirewallRulePushResult{
			Profile:   name,
			Rule:      ruleName,
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

	// Refetch + write first snapshot.
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
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "firewall", ruleName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile:   name,
					Rule:      ruleName,
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "firewall", ruleName, 10)
			}
		}
	}

	return &FirewallRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "create",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}
```

- [ ] **Step 4: Run CreateInline tests — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_CreateInline -v
```

- [ ] **Step 5: Write failing UpdateInline tests**

Append to `/Users/ipm/code/sophosfw/internal/svc/firewallrule_pull_test.go`:

```go
func TestFirewallRuleSvc_UpdateInline_DryRun(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "X", body, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_UpdateInline_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestFirewallRuleSvc_UpdateInline_DiffHashMismatch_Rejects(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, live)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	_, err := svc.UpdateInline(context.Background(), "home", "X", body,
		"definitely-wrong-hash-0000000000000000000000000000000000000000",
		false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_UpdateInline_IgnoreHash_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, live)
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	_, err := svc.UpdateInline(context.Background(), "home", "X", body, "", true, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
}

func TestFirewallRuleSvc_UpdateInline_RequiredFieldMissing_Rejects(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		// PolicyType missing.
	}
	_, err = svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "PolicyType")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_UpdateInline_AuditTagsPush(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	_, err = svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.NoError(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	// Audit tag matches existing cli push for updates.
	require.Contains(t, string(logBody), `"operation":"firewall_rule_push"`)
}
```

- [ ] **Step 6: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_UpdateInline -v
```

- [ ] **Step 7: Implement `UpdateInline`**

Append to `/Users/ipm/code/sophosfw/internal/svc/firewallrule_pull.go`:

```go
// UpdateInline updates an existing FirewallRule from an in-memory body
// (no draft file). Mirrors Push for the update path. expectedHash
// semantics identical to Push (required unless ignoreHash). Audit op
// firewall_rule_push.
func (s *FirewallRuleSvc) UpdateInline(ctx context.Context, profileName, ruleName string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (out *FirewallRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "firewall_rule_push",
		ObjectType: "FirewallRule",
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

	// Required-field validation.
	for _, k := range requiredFirewallRuleFields {
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

	catEntry, ok := s.Inner.Catalog.Resolve("FirewallRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: FirewallRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	if !ignoreHash {
		live, perr := s.Get(ctx, profileName, ruleName)
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
	inner, perr := marshalFirewallRule(body)
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
		return &FirewallRulePushResult{
			Profile:   name,
			Rule:      ruleName,
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

	// Refetch + archive snapshot.
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
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "firewall", ruleName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile:   name,
					Rule:      ruleName,
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "firewall", ruleName, 10)
			}
		}
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
```

- [ ] **Step 8: Run UpdateInline tests — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestFirewallRuleSvc_CreateInline|TestFirewallRuleSvc_UpdateInline" -v
go test ./... -count=1
```

- [ ] **Step 9: Commit**

```bash
git add internal/svc/firewallrule_create.go internal/svc/firewallrule_create_test.go internal/svc/firewallrule_pull.go internal/svc/firewallrule_pull_test.go
git commit -m "feat(svc): FirewallRuleSvc CreateInline + UpdateInline (draft-less)"
```

---

## Task 2: `NATRuleSvc.CreateInline` + `UpdateInline`

**Files:**
- Modify: `internal/svc/natrule_create.go`
- Modify: `internal/svc/natrule_pull.go`
- Modify: `internal/svc/natrule_create_test.go`
- Modify: `internal/svc/natrule_pull_test.go`

Mirror of T1 with NAT-specific differences:
- `marshalNATRule` instead of `marshalFirewallRule`.
- `requiredNATRuleFields = ["Name", "Status", "IPFamily"]` (no PolicyType).
- Tag `"nat"` for paths.
- Audit ops `nat_rule_create` / `nat_rule_push`.
- Test helpers from Phase 8: `newNATSvcPull(t, body)`.

- [ ] **Step 1: Write failing CreateInline tests**

Append to `/Users/ipm/code/sophosfw/internal/svc/natrule_create_test.go`:

```go
func TestNATRuleSvc_CreateInline_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		"OriginalSourceNetworks":      map[string]any{"Network": "Any"},
		"OriginalDestinationNetworks": map[string]any{"Network": "Any"},
		"TranslatedSource":            "Original",
		"TranslatedDestination":       "Original",
	}
	svc, fc, _ := newNATSvcPull(t, nil)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_CreateInline_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRuleSvc_CreateInline_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable",
		// IPFamily missing.
	}
	svc, fc, _ := newNATSvcPull(t, nil)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_CreateInline_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, nil)
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_CreateInline_AuditTagsCreate(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_create"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_CreateInline -v
```

- [ ] **Step 3: Implement `CreateInline` for NAT**

Append to `/Users/ipm/code/sophosfw/internal/svc/natrule_create.go`. Use the same structure as `FirewallRuleSvc.CreateInline` (T1 step 3) with these changes:
- `requiredNATRuleFields` instead of `requiredFirewallRuleFields`.
- `marshalNATRule` instead of `marshalFirewallRule`.
- Tag `"nat"` in `draft.SnapshotPath` / `draft.RotateSnapshots`.
- Audit ops `nat_rule_create`.
- ObjectType `"NATRule"`.
- Catalog resolve `"NATRule"`.
- Result struct `NATRulePushResult`.

```go
import (
	// add if not present:
	"github.com/iainmoffat/sophosfw/internal/safety"
)

// CreateInline creates a new NATRule from an in-memory body. See
// FirewallRuleSvc.CreateInline for shape; this is the NAT mirror.
func (s *NATRuleSvc) CreateInline(ctx context.Context, profileName, ruleName string, body map[string]any, dryRun bool) (out *NATRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_create",
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

	for _, k := range requiredNATRuleFields {
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

	catEntry, ok := s.Inner.Catalog.Resolve("NATRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: NATRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	inner, perr := marshalNATRule(body)
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
		return &NATRulePushResult{
			Profile:   name,
			Rule:      ruleName,
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
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10)
			}
		}
	}

	return &NATRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "create",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}
```

- [ ] **Step 4: Run CreateInline NAT tests — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_CreateInline -v
```

- [ ] **Step 5: Write failing UpdateInline NAT tests**

Append to `/Users/ipm/code/sophosfw/internal/svc/natrule_pull_test.go`:

```go
func TestNATRuleSvc_UpdateInline_DryRun(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "X", body, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_UpdateInline_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRuleSvc_UpdateInline_DiffHashMismatch_Rejects(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	_, err := svc.UpdateInline(context.Background(), "home", "X", body,
		"definitely-wrong-hash-0000000000000000000000000000000000000000",
		false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_UpdateInline_IgnoreHash_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	_, err := svc.UpdateInline(context.Background(), "home", "X", body, "", true, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
}

func TestNATRuleSvc_UpdateInline_RequiredFieldMissing_Rejects(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable",
		// IPFamily missing.
	}
	_, err = svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_UpdateInline_AuditTagsPush(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	_, err = svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.NoError(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_push"`)
}
```

- [ ] **Step 6: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_UpdateInline -v
```

- [ ] **Step 7: Implement `UpdateInline` for NAT**

Append to `/Users/ipm/code/sophosfw/internal/svc/natrule_pull.go`:

```go
// UpdateInline updates an existing NATRule from an in-memory body.
// See FirewallRuleSvc.UpdateInline for shape; this is the NAT mirror.
func (s *NATRuleSvc) UpdateInline(ctx context.Context, profileName, ruleName string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (out *NATRulePushResult, err error) {
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

	for _, k := range requiredNATRuleFields {
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

	catEntry, ok := s.Inner.Catalog.Resolve("NATRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: NATRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	if !ignoreHash {
		live, perr := s.Get(ctx, profileName, ruleName)
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
	inner, perr := marshalNATRule(body)
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
		return &NATRulePushResult{
			Profile:   name,
			Rule:      ruleName,
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
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10)
			}
		}
	}

	return &NATRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}
```

- [ ] **Step 8: Run UpdateInline NAT tests — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestNATRuleSvc_CreateInline|TestNATRuleSvc_UpdateInline" -v
go test ./... -count=1
```

- [ ] **Step 9: Commit**

```bash
git add internal/svc/natrule_create.go internal/svc/natrule_create_test.go internal/svc/natrule_pull.go internal/svc/natrule_pull_test.go
git commit -m "feat(svc): NATRuleSvc CreateInline + UpdateInline (draft-less)"
```

---

## Task 3: Modify `<rule>_show` MCP tools to include `_diffHash`

**Files:**
- Modify: `internal/mcp/firewallrule.go`
- Modify: `internal/mcp/firewallrule_test.go`
- Modify: `internal/mcp/natrule.go`
- Modify: `internal/mcp/natrule_test.go`

Both existing show handlers fetch a body and render an envelope. Phase 10 adds `_diffHash` to the rendered body.

- [ ] **Step 1: Read existing show handlers**

```bash
grep -n "handleFirewallRuleShow\|handleNATRuleShow" /Users/ipm/code/sophosfw/internal/mcp/*.go
```

Look at how each handler currently constructs the response — likely calling something like `render.FirewallRuleEnvelope(profile, body)` or directly emitting the body via `jsonResult`.

- [ ] **Step 2: Write failing tests**

Append to `/Users/ipm/code/sophosfw/internal/mcp/firewallrule_test.go`:

```go
func TestFirewallRuleShow_Handler_IncludesDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	s, _ := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleShow(context.Background(), nil, FirewallRuleShowInput{Name: "X"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"_diffHash":`)
}
```

(`mustJSON(t, body)` is a tiny helper that returns `json.RawMessage` — if not already in the package, add it.)

Append to `/Users/ipm/code/sophosfw/internal/mcp/natrule_test.go`:

```go
func TestNATRuleShow_Handler_IncludesDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	s, _ := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleShow(context.Background(), nil, NATRuleShowInput{Name: "X"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"_diffHash":`)
}
```

The exact input-type name (`FirewallRuleShowInput` / `NATRuleShowInput`) and the `newMutMcpServer` helper come from earlier MCP tests; verify by grep:

```bash
grep -n "FirewallRuleShowInput\|NATRuleShowInput\|newMutMcpServer\|newMcpServer" /Users/ipm/code/sophosfw/internal/mcp/*_test.go | head
```

If `newMutMcpServer` doesn't exist, use whatever helper the existing show tests use.

- [ ] **Step 3: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/mcp -run "TestFirewallRuleShow_Handler_IncludesDiffHash|TestNATRuleShow_Handler_IncludesDiffHash" -v
```

- [ ] **Step 4: Modify `handleFirewallRuleShow`**

In `/Users/ipm/code/sophosfw/internal/mcp/firewallrule.go`, find `handleFirewallRuleShow`. After the body is fetched (`body, err := s.firewallRuleSvc().Get(...)`) and the err-check, inject `_diffHash`:

```go
hash, hashErr := svc.DiffHash(body)
if hashErr != nil {
	return s.errorEnvelopeResult(hashErr, profile)
}
body["_diffHash"] = hash
```

Then continue with the existing render path. The injection happens BEFORE the body is marshaled to JSON.

If the existing handler renders via something like `render.FirewallRuleEnvelope(profile, body)`, that helper must accept the modified body. Most likely it just JSON-marshals the map; the new `_diffHash` field will appear at the top level.

If `Get` returns `nil, nil` (Sophos stub-record case from the cleanup phase), guard against nil:

```go
if body == nil {
	return s.errorEnvelopeResult(fmt.Errorf("firewall rule %q: %w", in.Name, sophos.ErrNotFound), profile)
}
```

Update the tool description (in the `sdkmcp.AddTool` registration for `firewall_rule_show`):

```go
Description: "Get one FirewallRule by name. Response always includes _diffHash, which firewall_rule_update and firewall_rule_delete require as expectedDiffHash.",
```

- [ ] **Step 5: Modify `handleNATRuleShow`**

Same change in `/Users/ipm/code/sophosfw/internal/mcp/natrule.go`. Inject `_diffHash` after fetching the body. Update the description with the same wording, swapping firewall→NAT.

- [ ] **Step 6: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/mcp -v -count=1
go test ./... -count=1
```

- [ ] **Step 7: Commit**

```bash
git add internal/mcp/firewallrule.go internal/mcp/firewallrule_test.go internal/mcp/natrule.go internal/mcp/natrule_test.go
git commit -m "feat(mcp): firewall_rule_show + nat_rule_show always include _diffHash"
```

---

## Task 4: MCP `firewall_rule_create/update/delete` tools

**Files:**
- Create: `internal/mcp/firewallrule_mutation.go`
- Create: `internal/mcp/firewallrule_mutation_test.go`
- Modify: `internal/mcp/firewallrule.go` (register the 3 new tools)
- Modify: `internal/mcp/server_test.go` (tool count assertion)

- [ ] **Step 1: Write failing tests**

Create `/Users/ipm/code/sophosfw/internal/mcp/firewallrule_mutation_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestFirewallRuleCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFirewallRuleCreate(context.Background(), nil, FirewallRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
		},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFirewallRuleCreate(context.Background(), nil, FirewallRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
		},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleCreate(context.Background(), nil, FirewallRuleCreateInput{
		Name: "X", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
}

func TestFirewallRuleUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleUpdate(context.Background(), nil, FirewallRuleUpdateInput{
		Name: "X", Body: body, Confirm: true,
		// ExpectedDiffHash empty, IgnoreExpectedDiffHash false.
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleUpdate(context.Background(), nil, FirewallRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, live)},
	})
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	out, _, err := s.handleFirewallRuleUpdate(context.Background(), nil, FirewallRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestFirewallRuleDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFirewallRuleDelete(context.Background(), nil, FirewallRuleDeleteInput{
		Name:    "X",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, live)},
	})
	out, _, err := s.handleFirewallRuleDelete(context.Background(), nil, FirewallRuleDeleteInput{
		Name:             "X",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
}
```

If `mustJSON` doesn't exist in the test package, define it once in a shared test helper file:

```go
func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
```

- [ ] **Step 2: Run — must fail (compile)**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/mcp -run TestFirewallRuleCreate_Handler -v
```

- [ ] **Step 3: Implement handlers + types in `internal/mcp/firewallrule_mutation.go`**

```go
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type FirewallRuleCreateInput struct {
	Profile string         `json:"profile,omitempty"`
	Name    string         `json:"name" jsonschema:"required" jsonschema_description:"the rule name"`
	Body    map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the full FirewallRule body as a JSON object. Required top-level keys: Name, Status, IPFamily, PolicyType. The Name in body must match the name argument. Use firewall_rule_show on an existing rule to learn the shape."`
	Confirm bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun  bool           `json:"dryRun,omitempty"`
}

type FirewallRuleUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys same as create."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior firewall_rule_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

type FirewallRuleDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

func (s *Server) handleFirewallRuleCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	// Body Name sanity. If body has a different Name, reject; otherwise force-set.
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profile)
	}
	in.Body["Name"] = in.Name

	result, err := s.firewallRuleSvc().CreateInline(ctx, profile, in.Name, in.Body, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpFirewallRuleMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleFirewallRuleUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleUpdateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profile)
	}
	in.Body["Name"] = in.Name

	result, err := s.firewallRuleSvc().UpdateInline(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpFirewallRuleMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleFirewallRuleDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}

	result, err := s.firewallRuleSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpFirewallRuleMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

// renderMcpFirewallRuleMutation picks the right envelope based on whether
// the result was a dry-run preview or an applied mutation.
func renderMcpFirewallRuleMutation(r *svc.FirewallRulePushResult) ([]byte, error) {
	if r.DryRun {
		return render.PreviewEnvelope(r.Preview)
	}
	return render.FirewallRulePushEnvelope(r)
}
```

- [ ] **Step 4: Register the 3 new tools**

In `/Users/ipm/code/sophosfw/internal/mcp/firewallrule.go` (or wherever firewall rule tools are registered — likely a `registerFirewallRule()` method), append:

```go
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
	Name:        "firewall_rule_create",
	Description: "Create a new FirewallRule. Requires confirm: true. Use dryRun: true to preview the envelope without sending. Returns sophosfw.v1.firewallRulePush on apply or sophosfw.v1.preview on dry-run. The body must include Name, Status, IPFamily, PolicyType plus a NetworkPolicy object.",
	Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create firewall rule"},
}, s.handleFirewallRuleCreate)
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
	Name:        "firewall_rule_update",
	Description: "Update an existing FirewallRule. Requires confirm: true AND expectedDiffHash from a prior firewall_rule_show. Use dryRun: true to preview.",
	Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update firewall rule"},
}, s.handleFirewallRuleUpdate)
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
	Name:        "firewall_rule_delete",
	Description: "Delete a FirewallRule by name. Requires confirm: true AND expectedDiffHash from a prior firewall_rule_show.",
	Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete firewall rule"},
}, s.handleFirewallRuleDelete)
```

- [ ] **Step 5: Update tool count assertion**

In `/Users/ipm/code/sophosfw/internal/mcp/server_test.go`, find the existing tool-count assertion (`require.Len(t, result.Tools, 24, ...)` or similar). Change `24` to `27` (we added 3 firewall tools; T5 will add 3 more for NAT making 30).

Also append the 3 new firewall tool names to the expected-name list in that test:

```go
"firewall_rule_create",
"firewall_rule_update",
"firewall_rule_delete",
```

- [ ] **Step 6: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/mcp -v -count=1
go test ./... -count=1
```

- [ ] **Step 7: Commit**

```bash
git add internal/mcp/firewallrule.go internal/mcp/firewallrule_mutation.go internal/mcp/firewallrule_mutation_test.go internal/mcp/server_test.go
git commit -m "feat(mcp): firewall_rule_create/update/delete (3 mutating tools)"
```

---

## Task 5: MCP `nat_rule_create/update/delete` tools

**Files:**
- Create: `internal/mcp/natrule_mutation.go`
- Create: `internal/mcp/natrule_mutation_test.go`
- Modify: `internal/mcp/natrule.go` (register the 3 new tools)
- Modify: `internal/mcp/server_test.go` (tool count 27 → 30)

Mirror of T4. Same structure, NAT-specific names + helpers.

- [ ] **Step 1: Write failing tests**

Create `/Users/ipm/code/sophosfw/internal/mcp/natrule_mutation_test.go` with the same 8 tests as T4's firewall mutation tests, swapping:
- `FirewallRule` → `NATRule` in tool/handler/type names
- `firewall_rule` → `nat_rule` in schema and tag assertions
- Body fixtures: drop `PolicyType`, simplify (just `Name`, `Status`, `IPFamily`)
- Response body assertions: `Body: ...` map and `"NATRule"` in fake server's body map

```go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestNATRuleCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleNATRuleCreate(context.Background(), nil, NATRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleNATRuleCreate(context.Background(), nil, NATRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleCreate(context.Background(), nil, NATRuleCreateInput{
		Name: "X", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRuleUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleUpdate(context.Background(), nil, NATRuleUpdateInput{
		Name: "X", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleUpdate(context.Background(), nil, NATRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, live)},
	})
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	out, _, err := s.handleNATRuleUpdate(context.Background(), nil, NATRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestNATRuleDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleNATRuleDelete(context.Background(), nil, NATRuleDeleteInput{
		Name:    "X",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, live)},
	})
	out, _, err := s.handleNATRuleDelete(context.Background(), nil, NATRuleDeleteInput{
		Name:             "X",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRulePush"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/mcp -run TestNATRuleCreate_Handler -v
```

- [ ] **Step 3: Implement handlers + types in `internal/mcp/natrule_mutation.go`**

Mirror of T4 step 3 with NAT names. Specifically:

```go
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type NATRuleCreateInput struct {
	Profile string         `json:"profile,omitempty"`
	Name    string         `json:"name" jsonschema:"required"`
	Body    map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the full NATRule body. Required top-level keys: Name, Status, IPFamily. The Name in body must match the name argument."`
	Confirm bool           `json:"confirm" jsonschema:"required"`
	DryRun  bool           `json:"dryRun,omitempty"`
}

type NATRuleUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required"`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

type NATRuleDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

func (s *Server) handleNATRuleCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in NATRuleCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profile)
	}
	in.Body["Name"] = in.Name

	result, err := s.natRuleMutSvc().CreateInline(ctx, profile, in.Name, in.Body, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpNATRuleMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleNATRuleUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in NATRuleUpdateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profile)
	}
	in.Body["Name"] = in.Name

	result, err := s.natRuleMutSvc().UpdateInline(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpNATRuleMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleNATRuleDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in NATRuleDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}

	result, err := s.natRuleMutSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpNATRuleMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func renderMcpNATRuleMutation(r *svc.NATRulePushResult) ([]byte, error) {
	if r.DryRun {
		return render.PreviewEnvelope(r.Preview)
	}
	return render.NATRulePushEnvelope(r)
}
```

The factory `s.natRuleMutSvc()` mirrors `s.firewallRuleSvc()` — verify the actual name in the existing code with:

```bash
grep -n "func (s \*Server) firewallRuleSvc\|func (s \*Server) natRuleSvc\|func (s \*Server) natRuleMutSvc" /Users/ipm/code/sophosfw/internal/mcp/*.go
```

If the helper for NAT mutations doesn't exist, add a sibling factory in the same file pattern.

- [ ] **Step 4: Register the 3 new NAT tools**

In `/Users/ipm/code/sophosfw/internal/mcp/natrule.go`, append:

```go
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
	Name:        "nat_rule_create",
	Description: "Create a new NATRule. Requires confirm: true. Use dryRun: true to preview without sending. Returns sophosfw.v1.natRulePush on apply or sophosfw.v1.preview on dry-run. The body must include Name, Status, IPFamily.",
	Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create NAT rule"},
}, s.handleNATRuleCreate)
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
	Name:        "nat_rule_update",
	Description: "Update an existing NATRule. Requires confirm: true AND expectedDiffHash from a prior nat_rule_show. Use dryRun: true to preview.",
	Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update NAT rule"},
}, s.handleNATRuleUpdate)
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
	Name:        "nat_rule_delete",
	Description: "Delete a NATRule by name. Requires confirm: true AND expectedDiffHash from a prior nat_rule_show.",
	Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete NAT rule"},
}, s.handleNATRuleDelete)
```

- [ ] **Step 5: Update tool count assertion 27 → 30**

In `/Users/ipm/code/sophosfw/internal/mcp/server_test.go`, change `27` to `30`. Append the 3 new NAT names to the expected-name list:

```go
"nat_rule_create",
"nat_rule_update",
"nat_rule_delete",
```

- [ ] **Step 6: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/mcp -v -count=1
go test ./... -count=1
```

- [ ] **Step 7: Commit**

```bash
git add internal/mcp/natrule.go internal/mcp/natrule_mutation.go internal/mcp/natrule_mutation_test.go internal/mcp/server_test.go
git commit -m "feat(mcp): nat_rule_create/update/delete (3 mutating tools, 30 total)"
```

---

## Task 6: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

- [ ] **Step 1: Append integration tests**

Add to `/Users/ipm/code/sophosfw/internal/testutil/integration_test.go`:

```go
func TestIntegration_MCPFirewallRuleShow_HasDiffHash(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE to a real rule on the testvm")
	}

	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: profileName,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "firewall_rule_show",
		Arguments: map[string]any{"name": ruleName},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	tc, ok := result.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"_diffHash":`)
}

func TestIntegration_MCPFirewallRuleUpdate_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE")
	}

	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: profileName,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	// Step 1: show, capture diffHash.
	showResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "firewall_rule_show",
		Arguments: map[string]any{"name": ruleName},
	})
	require.NoError(t, err)
	tc := showResult.Content[0].(*sdkmcp.TextContent)
	var showBody map[string]any
	require.NoError(t, json.Unmarshal([]byte(tc.Text), &showBody))
	hash, _ := showBody["_diffHash"].(string)
	require.NotEmpty(t, hash)
	delete(showBody, "_diffHash")
	delete(showBody, "schema")

	// Step 2: update dry-run with the same body.
	updateResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "firewall_rule_update",
		Arguments: map[string]any{
			"name":             ruleName,
			"body":             showBody,
			"expectedDiffHash": hash,
			"confirm":          true,
			"dryRun":           true,
		},
	})
	require.NoError(t, err)
	require.False(t, updateResult.IsError)
	tcUpdate := updateResult.Content[0].(*sdkmcp.TextContent)
	require.Contains(t, tcUpdate.Text, `"schema": "sophosfw.v1.preview"`)
}
```

The `encoding/json` import must already be present (added by other tests). Add `"github.com/iainmoffat/sophosfw/internal/mcp"` if not.

(NAT integration tests follow the same pattern; skip them unless time permits — the FirewallRule tests prove the round-trip path works for both rule types since the code is mirrored.)

- [ ] **Step 2: Run integration tests**

```bash
cd /Users/ipm/code/sophosfw && SOPHOSFW_PROFILE=testvm SOPHOSFW_TEST_RULE='Block Countries' go test -tags=integration ./internal/testutil -run "TestIntegration_MCPFirewallRule" -v
```

Expected: both pass.

- [ ] **Step 3: Manual smoke**

There's no canonical command-line "MCP client" baked into sophosfw, so the manual smoke is integration-test-driven plus an audit log inspection:

```bash
# Confirm tool count is 30 in the registered server.
make build
./bin/sophosfw mcp serve &
PID=$!
sleep 1
# A simple way to check tool registration is to look at the integration
# test output above — TestServer_RegistersAllTools asserts 30.
kill $PID 2>/dev/null

# Check audit log after the integration tests ran.
tail -20 ~/.config/sophosfw/audit.log | python3 -c "
import json, sys
for line in sys.stdin.readlines():
    try:
        e = json.loads(line)
        print(f\"{e.get('timestamp','')[:19]} {e.get('operation'):30} {e.get('objectName',''):30} {e.get('result')}\")
    except: pass
"
```

Expected: `firewall_rule_push` (dry-run from update) entries with `result: "ok (dry-run)"`.

- [ ] **Step 4: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "test: phase 10 MCP mutation integration smoke"
```

---

## Task 7: Docs + acceptance + tag v0.9.0-phase10

**Files:**
- Modify: `docs/api-coverage.md`
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update docs/api-coverage.md FirewallRule MCP cell**

Find the FirewallRule row. Update the MCP cell to list the new tools:

Before:
```
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show/new/pull/diff/push/delete | firewall_rule_list/show; object_list/get/search/usage | yes | yes (sophosfw firewall rule new) | yes (sophosfw firewall rule push) | yes (sophosfw firewall rule delete) | n/a | Phase 9 |
```

After:
```
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show/new/pull/diff/push/delete | firewall_rule_list/show/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw firewall rule new; firewall_rule_create) | yes (sophosfw firewall rule push; firewall_rule_update) | yes (sophosfw firewall rule delete; firewall_rule_delete) | n/a | Phase 10 |
```

- [ ] **Step 2: Update docs/api-coverage.md NATRule MCP cell**

Same shape:

Before:
```
| Firewall | NATRule | object list/get NATRule; nat rule list/show/new/pull/diff/push/delete | nat_rule_list/show; object_list/get/search/usage | yes | yes (sophosfw nat rule new) | yes (sophosfw nat rule push) | yes (sophosfw nat rule delete) | n/a | Phase 9 |
```

After:
```
| Firewall | NATRule | object list/get NATRule; nat rule list/show/new/pull/diff/push/delete | nat_rule_list/show/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw nat rule new; nat_rule_create) | yes (sophosfw nat rule push; nat_rule_update) | yes (sophosfw nat rule delete; nat_rule_delete) | n/a | Phase 10 |
```

- [ ] **Step 3: Update docs/roadmap.md**

Find:
```markdown
- Phase 9 — Firewall + NAT rule create workflows (complete; v0.8.0-phase9)
- Phase 10 — MCP-native firewall and NAT rule mutating tools
```

Replace with:
```markdown
- Phase 9 — Firewall + NAT rule create workflows (complete; v0.8.0-phase9)
- Phase 10 — MCP-native firewall and NAT rule mutating tools (complete; v0.9.0-phase10)
```

- [ ] **Step 4: Run final test pass**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```

- [ ] **Step 5: Commit fmt drift if any**

```bash
git status
# If files changed:
git add -A
git commit -m "fix: phase 10 acceptance pass formatting"
```

- [ ] **Step 6: Commit docs**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "docs: phase 10 complete in roadmap and api-coverage"
```

- [ ] **Step 7: Tag**

```bash
git tag -a v0.9.0-phase10 -m "Phase 10 complete (MCP firewall + NAT rule create/update/delete)"
git tag --list | grep -E "(foundation|phase[3-9]|phase10)"
```

Expected output includes `v0.9.0-phase10`.

- [ ] **Step 8: Push to origin**

```bash
git push origin main
git push origin v0.9.0-phase10
```

- [ ] **Step 9: Final sanity**

```bash
git log --oneline -15
```

---

## End of plan

Phase 10 closes out the original Phase 8 deferred list (MCP, create, NATRule). No predetermined Phase 11 — defer scoping until real usage surfaces a need.

## Self-review checklist

- ✅ **Spec coverage:** Section 4 (tool surface) → T4 + T5; Section 5 (svc wrappers) → T1 + T2; Section 6 (modified show) → T3; Section 7 (no new envelopes — reuse) → render helpers in T4 + T5; Section 8 (data flow) → T1-T5; Section 9 (errors) → no new sentinels; Section 10 (audit ops reused) → T1+T2 audit tags; Section 11 (testing) → T1-T6; Section 12 (acceptance) → T7.
- ✅ **No placeholders.** Every step has actual code or commands.
- ✅ **Type consistency.** `FirewallRulePushResult` / `NATRulePushResult` (existing types) used unchanged. `requiredFirewallRuleFields` / `requiredNATRuleFields` (existing) reused. `marshalFirewallRule` / `marshalNATRule` (existing) reused.
- ✅ **No Co-Authored-By trailer.** Every commit step inherits the project convention.
- ✅ **Single passing commit per task.** Each task's tests pass at commit time.
- ✅ **Acceptance.** T7 covers fmt/vet/race, docs, tag, push.
