# sophosfw Phase 9 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `<rule> rule new <name>` to firewall and NAT rule cli surfaces, and extend the existing push pipeline to dispatch `<Set operation="add">` for create drafts.

**Architecture:** A new `Operation` field on `draft.Draft` carries `create` or `update`. `<rule> new` writes a draft with `operation: create` and an empty diffHash; push branches on the operation field to choose `add` vs `update` envelope; on successful create, push refetches and flips the draft header to `update` mode. Diff rejects create drafts with a clear error.

**Tech Stack:** Go 1.26+, `gopkg.in/yaml.v3`, `encoding/xml`. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-02-sophosfw-phase9-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.7.0-phase8`. Working dir: `/Users/ipm/code/sophosfw`.

```bash
git status
go test ./... -count=1
```
Expected: clean status, all tests pass.

## File structure

**New files:**
- `internal/svc/firewallrule_create.go` — `FirewallRuleSvc.New`, template constant.
- `internal/svc/firewallrule_create_test.go` — service-layer tests for New.
- `internal/svc/natrule_create.go` — `NATRuleSvc.New`, template constant.
- `internal/svc/natrule_create_test.go` — service-layer tests for New.

**Modified files:**
- `internal/draft/io.go` — `Draft` struct gets `Operation` field; `ReadDraft`/`WriteDraft` parse and emit the `# operation:` header line; validation rules.
- `internal/draft/io_test.go` — header tests for the new field.
- `internal/svc/firewallrule_pull.go` — `Push` dispatches on `d.Operation`; `Diff` rejects create drafts.
- `internal/svc/firewallrule_pull_test.go` — tests for create-branch push and create-draft diff rejection.
- `internal/svc/natrule_pull.go` — same dispatch as firewall.
- `internal/svc/natrule_pull_test.go` — same tests.
- `internal/cli/firewallrule_mutation.go` — register `newFirewallRuleNewCmd`.
- `internal/cli/firewallrule.go` — add the new subcommand to the firewall rule subtree.
- `internal/cli/firewallrule_mutation_test.go` — cli tests for `firewall rule new`.
- `internal/cli/natrule_mutation.go` — register `newNATRuleNewCmd`.
- `internal/cli/natrule.go` — add the new subcommand to the nat rule subtree.
- `internal/cli/natrule_mutation_test.go` — cli tests for `nat rule new`.
- `internal/testutil/integration_test.go` — append two integration tests.
- `docs/api-coverage.md` — FirewallRule and NATRule rows updated.
- `docs/roadmap.md` — Phase 9 marked complete.

---

## Task 1: `Operation` field on `draft.Draft` + header parsing

**Files:**
- Modify: `internal/draft/io.go`
- Modify: `internal/draft/io_test.go`

The header gains one new key: `operation`. Allowed values `create` and `update`. Missing or empty defaults to `update` (backward-compat with Phase 7/8 drafts on disk).

- [ ] **Step 1: Write failing tests**

Append to `/Users/ipm/code/sophosfw/internal/draft/io_test.go`:

```go
func TestReadDraft_OperationHeader_Create(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "create.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# operation: create\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: \n---\nName: X\n"),
		0o600))
	d, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Empty(t, d.DiffHash)
}

func TestReadDraft_OperationHeader_Update(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# operation: update\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\n---\nName: X\n"),
		0o600))
	d, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, "update", d.Operation)
}

func TestReadDraft_OperationHeader_DefaultsToUpdate(t *testing.T) {
	// Backward-compat: Phase 7/8 drafts have no `# operation:` line.
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\n---\nName: X\n"),
		0o600))
	d, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, "update", d.Operation)
}

func TestReadDraft_OperationHeader_RejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bogus.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# operation: bogus\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "operation")
}

func TestReadDraft_RejectsCreateWithDiffHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# operation: create\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "create")
}

func TestReadDraft_RejectsUpdateWithEmptyDiffHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# operation: update\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: \n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "diffHash")
}

func TestWriteDraft_RoundTripsOperation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "round.yaml")
	d := &Draft{
		Profile:   "home",
		Rule:      "X",
		Operation: "create",
		PulledAt:  mustParseTime(t, "2026-05-02T15:30:00Z"),
		DiffHash:  "",
		Body:      []byte("Name: X\n"),
	}
	require.NoError(t, WriteDraft(path, d))
	got, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, "create", got.Operation)
	require.Empty(t, got.DiffHash)
}
```

- [ ] **Step 2: Run — must fail (compile error or test failures)**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
```

- [ ] **Step 3: Add `Operation` field and update parser/writer**

Edit `/Users/ipm/code/sophosfw/internal/draft/io.go`. Find the `Draft` struct and add `Operation`:

```go
type Draft struct {
	Profile   string
	Rule      string
	Operation string    // "create" | "update". Empty defaults to "update" on read.
	PulledAt  time.Time
	DiffHash  string
	Body      []byte
}
```

In `ReadDraft`, find the existing `switch strings.ToLower(key)` block. Add a case for `operation`:

```go
case "operation":
	d.Operation = val
```

After the existing required-field checks (where `if d.DiffHash == ""` etc. are validated), add the operation validation:

```go
// Operation defaults to "update" for backward compatibility with
// Phase 7/8 drafts.
if d.Operation == "" {
	d.Operation = "update"
}
if d.Operation != "create" && d.Operation != "update" {
	return nil, fmt.Errorf("draft header operation invalid: must be 'create' or 'update', got %q", d.Operation)
}
// Operation/diffHash consistency.
if d.Operation == "create" && d.DiffHash != "" {
	return nil, fmt.Errorf("draft header inconsistency: operation=create requires empty diffHash")
}
```

Also: the existing `if d.DiffHash == ""` check (which currently rejects all empty hashes) needs to be relaxed for create drafts. Find the existing block and replace it:

```go
// Existing:
//   if d.DiffHash == "" {
//       return nil, fmt.Errorf("draft header missing diffHash")
//   }
// New:
if d.Operation == "update" && d.DiffHash == "" {
	return nil, fmt.Errorf("draft header missing diffHash (required for operation=update)")
}
```

In `WriteDraft`, find where the header lines are emitted (after `# rule:` and `# pulledAt:`). Insert the operation line. Order matters for human readability — emit `operation` between `rule` and `pulledAt`:

```go
fmt.Fprintln(&buf, "# sophosfw firewall rule draft v1")
fmt.Fprintf(&buf, "# profile: %s\n", d.Profile)
fmt.Fprintf(&buf, "# rule: %s\n", d.Rule)
op := d.Operation
if op == "" {
	op = "update"
}
fmt.Fprintf(&buf, "# operation: %s\n", op)
fmt.Fprintf(&buf, "# pulledAt: %s\n", d.PulledAt.UTC().Format(time.RFC3339))
fmt.Fprintf(&buf, "# diffHash: %s\n", d.DiffHash)
fmt.Fprintln(&buf, "# DO NOT EDIT ABOVE THIS LINE — push reads this header to verify drift")
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
go test ./... -count=1
```

The full suite should pass: existing Phase 7/8 drafts (no operation header) still parse and write correctly because `Operation` defaults to `"update"`.

- [ ] **Step 5: Commit (NO Co-Authored-By; single passing commit)**

```bash
git add internal/draft/io.go internal/draft/io_test.go
git commit -m "feat(draft): Operation field on Draft for create vs update detection"
```

---

## Task 2: `FirewallRuleSvc.New` + template

**Files:**
- Create: `internal/svc/firewallrule_create.go`
- Create: `internal/svc/firewallrule_create_test.go`

`New` writes a draft with `operation: create`. From-template by default; `--from <existing>` clones the existing rule's body.

- [ ] **Step 1: Write failing tests**

Create `/Users/ipm/code/sophosfw/internal/svc/firewallrule_create_test.go`:

```go
package svc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func TestFirewallRuleSvc_New_FromTemplate(t *testing.T) {
	svc, _, baseDir := newFwRuleSvc(t, nil)
	out, err := svc.New(context.Background(), "home", "MyRule", "")
	require.NoError(t, err)
	require.Equal(t, "MyRule", out.Rule)
	require.NotEmpty(t, out.DraftPath)
	require.Empty(t, out.SnapshotPath)
	require.Empty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Empty(t, d.DiffHash)
	require.Contains(t, string(d.Body), "Name: MyRule")
	require.Contains(t, string(d.Body), "Action: Drop")

	// No snapshot file for a fresh new.
	snaps, err := draft.ListSnapshots(baseDir, "home", "firewall", "MyRule")
	require.NoError(t, err)
	require.Empty(t, snaps)
}

func TestFirewallRuleSvc_New_FromExisting(t *testing.T) {
	body := map[string]any{
		"Name":       "OldRule",
		"Status":     "Enable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"NetworkPolicy": map[string]any{
			"Action":           "Accept",
			"SourceNetworks":   map[string]any{"Network": "LAN-network"},
			"DestinationZones": map[string]any{"Zone": "WAN"},
		},
	}
	svc, _, _ := newFwRuleSvc(t, body)
	out, err := svc.New(context.Background(), "home", "NewRule", "OldRule")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	// Body should reflect the source rule with Name overwritten.
	require.Contains(t, string(d.Body), "Name: NewRule")
	require.NotContains(t, string(d.Body), "Name: OldRule")
	require.Contains(t, string(d.Body), "Action: Accept")
	require.Contains(t, string(d.Body), "LAN-network")
}

func TestFirewallRuleSvc_New_FromExisting_DropsAfterBefore(t *testing.T) {
	body := map[string]any{
		"Name":       "OldRule",
		"Status":     "Enable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"After":      map[string]any{"Name": "SomeRule"},
		"Before":     map[string]any{"Name": "OtherRule"},
	}
	svc, _, _ := newFwRuleSvc(t, body)
	out, err := svc.New(context.Background(), "home", "NewRule", "OldRule")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.NotContains(t, string(d.Body), "After:")
	require.NotContains(t, string(d.Body), "Before:")
}

func TestFirewallRuleSvc_New_RejectsExistingDraft(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil)
	// First call creates the draft.
	_, err := svc.New(context.Background(), "home", "MyRule", "")
	require.NoError(t, err)
	// Second call rejects.
	_, err = svc.New(context.Background(), "home", "MyRule", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "draft already exists")
}

func TestFirewallRuleSvc_New_FromExistingNotFound(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil) // nil body → ErrNotFound on Get
	_, err := svc.New(context.Background(), "home", "NewRule", "Missing")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestFirewallRuleSvc_New_AuditLogged(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil)
	_, err := svc.New(context.Background(), "home", "MyRule", "")
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_new"`)
	require.Contains(t, string(logBody), `"objectName":"MyRule"`)
}
```

- [ ] **Step 2: Run — must fail (compile error)**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_New -v
```

- [ ] **Step 3: Implement `internal/svc/firewallrule_create.go`**

```go
package svc

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// firewallRuleTemplate is the minimal-valid skeleton emitted by `new`
// when no --from is supplied. Defaults to Action=Drop (fail-safe).
const firewallRuleTemplate = `Name: __NAME__
Status: Enable
IPFamily: IPv4
PolicyType: Network
NetworkPolicy:
  Action: Drop
  LogTraffic: Enable
  Schedule: All The Time
  SourceZones:
    Zone: LAN
  DestinationZones:
    Zone: WAN
`

// FirewallRuleNewResult mirrors FirewallRulePullResult — same fields,
// reused render envelope. SnapshotPath and DiffHash are empty.
type FirewallRuleNewResult = FirewallRulePullResult

// New writes a new draft for ruleName at drafts/firewall/<slug>.yaml.
// If fromRule is non-empty, the existing rule's body is pulled and
// used as the starting template; otherwise firewallRuleTemplate is
// used. Errors:
//   - draft already exists at the resolved path → ErrInvalidRequest.
//   - --from rule doesn't exist → ErrNotFound.
//
// Audit: writes "firewall_rule_new" entry on success.
func (s *FirewallRuleSvc) New(ctx context.Context, profileName, ruleName, fromRule string) (out *FirewallRuleNewResult, err error) {
	_, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "firewall_rule_new",
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

	// 1. Compose body.
	var bodyMap map[string]any
	if fromRule == "" {
		// Template path.
		tmpl := strings.ReplaceAll(firewallRuleTemplate, "__NAME__", ruleName)
		if perr := yaml.Unmarshal([]byte(tmpl), &bodyMap); perr != nil {
			return nil, fmt.Errorf("template parse: %w", perr)
		}
	} else {
		// --from existing path.
		live, perr := s.Get(ctx, profileName, fromRule)
		if perr != nil {
			return nil, perr
		}
		if live == nil {
			return nil, fmt.Errorf("firewall rule %q: %w", fromRule, sophos.ErrNotFound)
		}
		bodyMap = live
		bodyMap["Name"] = ruleName
		delete(bodyMap, "After")
		delete(bodyMap, "Before")
	}

	yamlBytes, perr := marshalCanonicalYAML(bodyMap)
	if perr != nil {
		return nil, perr
	}

	// 2. Resolve draft path; reject if file exists.
	draftPath, perr := draft.DraftPath(s.BaseDir, name, "firewall", ruleName)
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
		Rule:      ruleName,
		Operation: "create",
		PulledAt:  now,
		DiffHash:  "",
		Body:      yamlBytes,
	}
	if perr := draft.WriteDraft(draftPath, d); perr != nil {
		return nil, perr
	}

	// 4. Audit.
	entryAudit.Result = "ok"
	if s.Audit != nil {
		_ = s.Audit.Write(entryAudit)
	}

	return &FirewallRuleNewResult{
		Profile:    name,
		Rule:       ruleName,
		DraftPath:  draftPath,
		// SnapshotPath: "" — no snapshot yet
		// DiffHash: "" — no live state
		References: extractReferences(bodyMap),
	}, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_New -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/firewallrule_create.go internal/svc/firewallrule_create_test.go
git commit -m "feat(svc): FirewallRuleSvc.New — template + --from existing"
```

---

## Task 3: `FirewallRuleSvc.Push` create-branch + `Diff` create-rejection

**Files:**
- Modify: `internal/svc/firewallrule_pull.go`
- Modify: `internal/svc/firewallrule_pull_test.go`

`Push` reads `d.Operation` and dispatches: `update` → existing flow, `create` → `<Set operation="add">` skipping the diff-hash check; on success flips header to `update` mode. `Diff` rejects create drafts.

- [ ] **Step 1: Append failing tests**

Append to `/Users/ipm/code/sophosfw/internal/svc/firewallrule_pull_test.go`:

```go
func TestFirewallRuleSvc_Push_CreateOperation_SendsAdd(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<FirewallRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)
}

func TestFirewallRuleSvc_Push_CreateOperation_SkipsDiffHashCheck(t *testing.T) {
	// Even if the live body would yield a different hash, push still
	// succeeds because diff-hash check is skipped for create drafts.
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	// Mutate the fake live body — would normally cause hash mismatch.
	fc.body = map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}

	out, err := svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.Equal(t, "create", out.Operation)
}

func TestFirewallRuleSvc_Push_CreateOperation_FlipsDraftHeader(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	pull, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	// Header before push: operation=create, diffHash="".
	d1, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d1.Operation)
	require.Empty(t, d1.DiffHash)

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	// Header after successful create: operation=update, diffHash populated.
	d2, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "update", d2.Operation)
	require.NotEmpty(t, d2.DiffHash)
	require.Regexp(t, `^[a-f0-9]{64}$`, d2.DiffHash)
}

func TestFirewallRuleSvc_Push_CreateOperation_WritesFirstSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	// No snapshot before push.
	snaps0, err := draft.ListSnapshots(baseDir, "home", "firewall", "X")
	require.NoError(t, err)
	require.Empty(t, snaps0)

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	// One snapshot after push.
	snaps1, err := draft.ListSnapshots(baseDir, "home", "firewall", "X")
	require.NoError(t, err)
	require.Len(t, snaps1, 1)
}

func TestFirewallRuleSvc_Push_CreateOperation_AuditTagsCreate(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_create"`)
}

func TestFirewallRuleSvc_Diff_CreateDraft_Errors(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	_, err = svc.Diff(context.Background(), "home", "X")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "no snapshot")
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestFirewallRuleSvc_Push_CreateOperation|TestFirewallRuleSvc_Diff_CreateDraft" -v
```

- [ ] **Step 3: Modify `internal/svc/firewallrule_pull.go` `Push`**

Find the existing `Push` method. The current flow does (in order): profile → audit skeleton → defer → read draft → header sanity → parseAndValidate → read-only → catalog Mutable → diff-hash check → build envelope → audit RedactedXML → dry-run/apply.

Modify the flow to branch on `d.Operation`:

After the `parseAndValidate` step (and before the read-only check) is unchanged. **Modify the diff-hash check block** so it's skipped for create:

```go
// Existing:
//   if !ignoreHash {
//       live, perr := s.Get(...)
//       ...
//       if liveHash != d.DiffHash { return ErrDiffHashMismatch }
//   }
// New:
operation := d.Operation
if operation == "" {
	operation = "update"
}
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
```

**Modify the envelope build** to use the right Sophos operation:

```go
// Existing:
//   full, perr := sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
// New:
sophosOp := "update"
if operation == "create" {
	sophosOp = "add"
}
full, perr := sophos.BuildSetEnvelope(sophosOp, inner, c.Username, c.Password)
```

**Modify the audit operation tag** to reflect create-vs-update:

```go
// Existing:
//   entryAudit.Operation = "firewall_rule_push"
// New (in the audit-skeleton-build step near the top):
auditOpTag := "firewall_rule_push"
if operation == "create" {
	auditOpTag = "firewall_rule_create"
}
entryAudit.Operation = auditOpTag
```

But note: the audit skeleton is built BEFORE we read the draft (per v0.6.1 deferred-audit pattern). We need to set the op tag AFTER reading the draft. Restructure: the skeleton starts with `firewall_rule_push` (the safe default for the deferred error path); after reading the draft and dispatching on operation, update `entryAudit.Operation` if needed.

Concretely, after the line `entryAudit.Operation = "firewall_rule_push"` was set in the skeleton:

```go
if operation == "create" {
	entryAudit.Operation = "firewall_rule_create"
}
```

Place this right after the `switch operation { ... }` block so the audit op reflects the actual dispatch.

**Modify the apply-success refetch/archive block** to handle the create case (header flip):

```go
// Existing apply-success refetch + archive (at the end of Push):
//   refetched, _ := s.Get(...)
//   ...
//   d.DiffHash = newHash
//   _ = draft.WriteDraft(draftPath, d)

// New version: same, but ensure d.Operation flips to "update" for
// create drafts so subsequent edits go through the update path.
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
				Operation: "update", // snapshot represents committed state
				PulledAt:  now,
				DiffHash:  newHash,
				Body:      yamlBytes,
			})
			_ = draft.RotateSnapshots(s.BaseDir, name, "firewall", ruleName, 10)
		}
	}
	// Flip the working draft to update mode (no-op if already update).
	d.Operation = "update"
	d.DiffHash = newHash
	d.PulledAt = now
	_ = draft.WriteDraft(draftPath, d)
}
```

**Modify the result struct** so the cli/audit see the actual operation:

```go
return &FirewallRulePushResult{
	Profile:     name,
	Rule:        ruleName,
	Operation:   operation, // "create" or "update"
	DryRun:      false,
	NewDiffHash: newHash,
	Item:        refetched,
}, nil
```

(For dry-run, also set `Operation: operation` in the dry-run branch's return.)

- [ ] **Step 4: Modify `internal/svc/firewallrule_pull.go` `Diff` to reject create drafts**

Find `Diff`. Right after `d, err := draft.ReadDraft(draftPath)` and the `nil` error check:

```go
if d.Operation == "create" {
	return nil, fmt.Errorf("%w: this is a draft for a new rule; no snapshot exists until first successful push", sophos.ErrInvalidRequest)
}
```

- [ ] **Step 5: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestFirewallRuleSvc" -v
go test ./... -count=1
```

If existing `TestFirewallRuleSvc_Push_*` tests fail because `out.Operation` is now `"update"` instead of being unset/something-else, update those tests' assertions to match (they should already work because the value was set previously).

- [ ] **Step 6: Commit**

```bash
git add internal/svc/firewallrule_pull.go internal/svc/firewallrule_pull_test.go
git commit -m "feat(svc): FirewallRuleSvc.Push dispatches on operation; Diff rejects create"
```

---

## Task 4: `NATRuleSvc.New` + template

**Files:**
- Create: `internal/svc/natrule_create.go`
- Create: `internal/svc/natrule_create_test.go`

Mirror of T2 with NAT-specific template + `tag="nat"` + audit op `nat_rule_new` + `extractNATReferences` for the summary.

- [ ] **Step 1: Write failing tests**

Create `/Users/ipm/code/sophosfw/internal/svc/natrule_create_test.go`:

```go
package svc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func TestNATRuleSvc_New_FromTemplate(t *testing.T) {
	svc, _, baseDir := newNATSvcPull(t, nil)
	out, err := svc.New(context.Background(), "home", "MyNAT", "")
	require.NoError(t, err)
	require.Equal(t, "MyNAT", out.Rule)
	require.NotEmpty(t, out.DraftPath)
	require.Empty(t, out.SnapshotPath)
	require.Empty(t, out.DiffHash)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Contains(t, string(d.Body), "Name: MyNAT")
	require.Contains(t, string(d.Body), "TranslatedSource: Original")

	snaps, err := draft.ListSnapshots(baseDir, "home", "nat", "MyNAT")
	require.NoError(t, err)
	require.Empty(t, snaps)
}

func TestNATRuleSvc_New_FromExisting(t *testing.T) {
	body := map[string]any{
		"Name":     "OldNAT",
		"Status":   "Enable",
		"IPFamily": "IPv4",
		"OriginalSourceNetworks": map[string]any{"Network": "LAN"},
		"TranslatedSource":       "Original",
	}
	svc, _, _ := newNATSvcPull(t, body)
	out, err := svc.New(context.Background(), "home", "NewNAT", "OldNAT")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Contains(t, string(d.Body), "Name: NewNAT")
	require.NotContains(t, string(d.Body), "Name: OldNAT")
	require.Contains(t, string(d.Body), "Network: LAN")
}

func TestNATRuleSvc_New_FromExisting_DropsAfterBefore(t *testing.T) {
	body := map[string]any{
		"Name":     "OldNAT",
		"Status":   "Enable",
		"IPFamily": "IPv4",
		"After":    map[string]any{"Name": "SomeRule"},
		"Before":   map[string]any{"Name": "OtherRule"},
	}
	svc, _, _ := newNATSvcPull(t, body)
	out, err := svc.New(context.Background(), "home", "NewNAT", "OldNAT")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.NotContains(t, string(d.Body), "After:")
	require.NotContains(t, string(d.Body), "Before:")
}

func TestNATRuleSvc_New_RejectsExistingDraft(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "MyNAT", "")
	require.NoError(t, err)
	_, err = svc.New(context.Background(), "home", "MyNAT", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "draft already exists")
}

func TestNATRuleSvc_New_FromExistingNotFound(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "NewNAT", "Missing")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestNATRuleSvc_New_AuditLogged(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "MyNAT", "")
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_new"`)
	require.Contains(t, string(logBody), `"objectName":"MyNAT"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_New -v
```

- [ ] **Step 3: Implement `internal/svc/natrule_create.go`**

```go
package svc

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// natRuleTemplate is the minimal-valid skeleton emitted by `nat rule
// new` when no --from is supplied. Defaults to all "Original"
// translation sentinels (no-op rule).
const natRuleTemplate = `Name: __NAME__
Status: Enable
IPFamily: IPv4
Position: Bottom
OriginalSourceNetworks:
  Network: Any
OriginalDestinationNetworks:
  Network: Any
OriginalServices:
  Service: Any
TranslatedSource: Original
TranslatedDestination: Original
TranslatedService: Original
`

// NATRuleNewResult mirrors NATRulePullResult — same fields, reused
// render envelope.
type NATRuleNewResult = NATRulePullResult

// New writes a new draft for ruleName at drafts/nat/<slug>.yaml. If
// fromRule is non-empty, the existing rule's body is pulled and used
// as the starting template; otherwise natRuleTemplate is used.
func (s *NATRuleSvc) New(ctx context.Context, profileName, ruleName, fromRule string) (out *NATRuleNewResult, err error) {
	_, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_new",
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

	var bodyMap map[string]any
	if fromRule == "" {
		tmpl := strings.ReplaceAll(natRuleTemplate, "__NAME__", ruleName)
		if perr := yaml.Unmarshal([]byte(tmpl), &bodyMap); perr != nil {
			return nil, fmt.Errorf("template parse: %w", perr)
		}
	} else {
		live, perr := s.Get(ctx, profileName, fromRule)
		if perr != nil {
			return nil, perr
		}
		if live == nil {
			return nil, fmt.Errorf("NAT rule %q: %w", fromRule, sophos.ErrNotFound)
		}
		bodyMap = live
		bodyMap["Name"] = ruleName
		delete(bodyMap, "After")
		delete(bodyMap, "Before")
	}

	yamlBytes, perr := marshalCanonicalYAML(bodyMap)
	if perr != nil {
		return nil, perr
	}

	draftPath, perr := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if perr != nil {
		return nil, perr
	}
	if _, statErr := os.Stat(draftPath); statErr == nil {
		return nil, fmt.Errorf("%w: draft already exists at %s; delete it first or use a different name", sophos.ErrInvalidRequest, draftPath)
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	now := s.now()
	d := &draft.Draft{
		Profile:   name,
		Rule:      ruleName,
		Operation: "create",
		PulledAt:  now,
		DiffHash:  "",
		Body:      yamlBytes,
	}
	if perr := draft.WriteDraft(draftPath, d); perr != nil {
		return nil, perr
	}

	entryAudit.Result = "ok"
	if s.Audit != nil {
		_ = s.Audit.Write(entryAudit)
	}

	return &NATRuleNewResult{
		Profile:    name,
		Rule:       ruleName,
		DraftPath:  draftPath,
		References: extractNATReferences(bodyMap),
	}, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_New -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/natrule_create.go internal/svc/natrule_create_test.go
git commit -m "feat(svc): NATRuleSvc.New — template + --from existing"
```

---

## Task 5: `NATRuleSvc.Push` create-branch + `Diff` create-rejection

**Files:**
- Modify: `internal/svc/natrule_pull.go`
- Modify: `internal/svc/natrule_pull_test.go`

Mirror of T3 for NATRule.

- [ ] **Step 1: Append failing tests to `internal/svc/natrule_pull_test.go`**

```go
func TestNATRuleSvc_Push_CreateOperation_SendsAdd(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRuleSvc_Push_CreateOperation_FlipsDraftHeader(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	pull, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	d1, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d1.Operation)
	require.Empty(t, d1.DiffHash)

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	d2, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "update", d2.Operation)
	require.NotEmpty(t, d2.DiffHash)
}

func TestNATRuleSvc_Push_CreateOperation_WritesFirstSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, baseDir := newNATSvcPull(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	snaps0, err := draft.ListSnapshots(baseDir, "home", "nat", "X")
	require.NoError(t, err)
	require.Empty(t, snaps0)

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	snaps1, err := draft.ListSnapshots(baseDir, "home", "nat", "X")
	require.NoError(t, err)
	require.Len(t, snaps1, 1)
}

func TestNATRuleSvc_Push_CreateOperation_AuditTagsCreate(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_create"`)
}

func TestNATRuleSvc_Diff_CreateDraft_Errors(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	_, err = svc.Diff(context.Background(), "home", "X")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "no snapshot")
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestNATRuleSvc_Push_CreateOperation|TestNATRuleSvc_Diff_CreateDraft" -v
```

- [ ] **Step 3: Modify `internal/svc/natrule_pull.go` Push and Diff**

Apply the same modifications described in Task 3 Steps 3 and 4, but for `NATRuleSvc.Push` and `NATRuleSvc.Diff`. Use:
- Tag: `"nat"` instead of `"firewall"`.
- XML wrapper: emitted by `marshalNATRule` (already used).
- Audit op tags: `nat_rule_push` (default) and `nat_rule_create` (when `operation: create`).

Specifically, in Push:
1. After `parseAndValidateNATRuleBody`, branch on `d.Operation` (create vs update). For `update`, run the existing diff-hash check; for `create`, skip it.
2. Build envelope using `sophosOp` (`"add"` if create, `"update"` if update).
3. Update `entryAudit.Operation` to `nat_rule_create` if `operation == "create"`.
4. In the apply-success block, set the result struct's `Operation` field to the actual operation, and ensure the draft header is flipped to `update` after a create (same code as Task 3 Step 3's apply-success block, with `tag="nat"`).

In Diff, add right after reading the draft:

```go
if d.Operation == "create" {
	return nil, fmt.Errorf("%w: this is a draft for a new rule; no snapshot exists until first successful push", sophos.ErrInvalidRequest)
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/natrule_pull.go internal/svc/natrule_pull_test.go
git commit -m "feat(svc): NATRuleSvc.Push dispatches on operation; Diff rejects create"
```

---

## Task 6: cli `firewall rule new` and `nat rule new`

**Files:**
- Modify: `internal/cli/firewallrule_mutation.go` (append `newFirewallRuleNewCmd`)
- Modify: `internal/cli/firewallrule.go` (register the new subcommand)
- Modify: `internal/cli/firewallrule_mutation_test.go`
- Modify: `internal/cli/natrule_mutation.go` (append `newNATRuleNewCmd`)
- Modify: `internal/cli/natrule.go` (register the new subcommand)
- Modify: `internal/cli/natrule_mutation_test.go`

- [ ] **Step 1: Write failing cli tests**

Append to `/Users/ipm/code/sophosfw/internal/cli/firewallrule_mutation_test.go`:

```go
func TestFwRule_New_WritesDraft_Json(t *testing.T) {
	d, _ := newRootForFwRuleTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "new", "MyRule", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRulePull"`)
	require.Contains(t, out.String(), `"rule": "MyRule"`)
	require.Contains(t, out.String(), `"diffHash": ""`)
}

func TestFwRule_New_FromExisting_CopiesBody(t *testing.T) {
	body := map[string]any{
		"Name": "OldRule", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "new", "NewRule", "--from", "OldRule", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"rule": "NewRule"`)
}

func TestFwRule_New_RejectsExistingDraft(t *testing.T) {
	d, _ := newRootForFwRuleTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	// First call.
	root.SetArgs([]string{"firewall", "rule", "new", "MyRule"})
	require.NoError(t, root.Execute())

	// Second call rejects.
	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "new", "MyRule"})
	err := root2.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}
```

Append to `/Users/ipm/code/sophosfw/internal/cli/natrule_mutation_test.go`:

```go
func TestNATRule_New_WritesDraft_Json(t *testing.T) {
	d, _ := newRootForNATTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "new", "MyNAT", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRulePull"`)
	require.Contains(t, out.String(), `"rule": "MyNAT"`)
	require.Contains(t, out.String(), `"diffHash": ""`)
}

func TestNATRule_New_FromExisting_CopiesBody(t *testing.T) {
	body := map[string]any{
		"Name": "OldNAT", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, _ := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "new", "NewNAT", "--from", "OldNAT", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"rule": "NewNAT"`)
}

func TestNATRule_New_RejectsExistingDraft(t *testing.T) {
	d, _ := newRootForNATTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "new", "MyNAT"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"nat", "rule", "new", "MyNAT"})
	err := root2.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/cli -run "TestFwRule_New|TestNATRule_New" -v
```

- [ ] **Step 3: Add `newFirewallRuleNewCmd` to `internal/cli/firewallrule_mutation.go`**

Append:

```go
func newFirewallRuleNewCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var fromRule string
	c := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a new firewall rule draft (template or --from existing)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := firewallRuleSvc(d, cat).New(cmd.Context(), profile, args[0], fromRule)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.FirewallRulePullEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"Draft written: %s\nOperation:     create\nSnapshot:      (none — first push will create one)\nEdit and run: sophosfw firewall rule push %s --yes\n",
				result.DraftPath, args[0])
			return nil
		},
	}
	c.Flags().StringVar(&fromRule, "from", "", "clone an existing rule's body as the starting template")
	return c
}
```

- [ ] **Step 4: Register the new firewall command**

In `internal/cli/firewallrule.go`, find where the firewall rule subcommands are registered. Add `newFirewallRuleNewCmd(d, cat)` to the `cmd.AddCommand(...)` list alongside the existing pull/diff/push/delete.

- [ ] **Step 5: Add `newNATRuleNewCmd` to `internal/cli/natrule_mutation.go`**

Append (mirror with NAT-specific naming):

```go
func newNATRuleNewCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var fromRule string
	c := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a new NAT rule draft (template or --from existing)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleMutSvc(d, cat).New(cmd.Context(), profile, args[0], fromRule)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePullEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"Draft written: %s\nOperation:     create\nSnapshot:      (none — first push will create one)\nEdit and run: sophosfw nat rule push %s --yes\n",
				result.DraftPath, args[0])
			return nil
		},
	}
	c.Flags().StringVar(&fromRule, "from", "", "clone an existing rule's body as the starting template")
	return c
}
```

(Note: the NAT factory in T9 of Phase 8 was named `natRuleMutSvc`. Verify by `grep -n "func natRuleMutSvc\|func natRuleSvc" internal/cli/natrule_mutation.go` and use whatever the actual name is.)

- [ ] **Step 6: Register the new NAT command**

In `internal/cli/natrule.go`, find where the NAT rule subcommands are registered. Add `newNATRuleNewCmd(d, cat)`.

- [ ] **Step 7: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/cli -run "TestFwRule|TestNATRule" -v
go test ./... -count=1
```

- [ ] **Step 8: Build and verify help text**

```bash
cd /Users/ipm/code/sophosfw && make build && ./bin/sophosfw firewall rule --help && ./bin/sophosfw nat rule --help
```

Both should show `new` subcommand alongside list/show/pull/diff/push/delete.

- [ ] **Step 9: Commit**

```bash
git add internal/cli/firewallrule.go internal/cli/firewallrule_mutation.go internal/cli/firewallrule_mutation_test.go internal/cli/natrule.go internal/cli/natrule_mutation.go internal/cli/natrule_mutation_test.go
git commit -m "feat(cli): firewall rule new + nat rule new"
```

---

## Task 7: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

- [ ] **Step 1: Append integration tests**

Add to `/Users/ipm/code/sophosfw/internal/testutil/integration_test.go`:

```go
func TestIntegration_FirewallRuleNew_FromTemplate_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	svcInst, _ := newFwRuleSvcForIntegration(t)
	const tname = "sophosfw-integration-test-new"

	// Cleanup: ensure the draft file is removed after the test even
	// if assertions fail. The svc.BaseDir is a tempDir so the file
	// goes away automatically. We don't push, so no firewall mutation
	// to revert.
	out, err := svcInst.New(context.Background(), profileName, tname, "")
	require.NoError(t, err)
	require.FileExists(t, out.DraftPath)

	pushOut, err := svcInst.Push(context.Background(), profileName, tname, false, true) // dryRun=true
	require.NoError(t, err)
	require.True(t, pushOut.DryRun)
	require.Equal(t, "create", pushOut.Operation)
	require.NotNil(t, pushOut.Preview)
	require.True(t, pushOut.Preview.Mutating)
	require.Contains(t, pushOut.Preview.RedactedXML, `<Set operation="add">`)
}

func TestIntegration_NATRuleNew_FromTemplate_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	svcInst, _ := newNATRuleSvcForIntegration(t)
	const tname = "sophosfw-integration-test-nat-new"

	out, err := svcInst.New(context.Background(), profileName, tname, "")
	require.NoError(t, err)
	require.FileExists(t, out.DraftPath)

	pushOut, err := svcInst.Push(context.Background(), profileName, tname, false, true)
	require.NoError(t, err)
	require.True(t, pushOut.DryRun)
	require.Equal(t, "create", pushOut.Operation)
	require.NotNil(t, pushOut.Preview)
	require.True(t, pushOut.Preview.Mutating)
	require.Contains(t, pushOut.Preview.RedactedXML, `<Set operation="add">`)
}
```

- [ ] **Step 2: Run integration tests**

```bash
cd /Users/ipm/code/sophosfw && SOPHOSFW_PROFILE=testvm go test -tags=integration ./internal/testutil -run "TestIntegration_FirewallRuleNew|TestIntegration_NATRuleNew" -v
```

Expected: both pass. Each does pull-style work locally then a dry-run push that emits the preview envelope without sending.

- [ ] **Step 3: Manual smoke — firewall rule create**

```bash
make build

# 1. New from template, push dry-run, then apply.
./bin/sophosfw firewall rule new sophosfw-smoke-create --profile testvm
cat ~/.config/sophosfw/profiles/testvm/drafts/firewall/sophosfw-smoke-create.yaml | head -8
# ↑ confirm operation: create header, empty diffHash

./bin/sophosfw firewall rule push sophosfw-smoke-create --profile testvm --json | head -15
# ↑ confirm <Set operation="add"> in redactedXml

./bin/sophosfw firewall rule push sophosfw-smoke-create --profile testvm --yes
# ↑ confirm "applied: ... operation: create"

cat ~/.config/sophosfw/profiles/testvm/drafts/firewall/sophosfw-smoke-create.yaml | head -8
# ↑ confirm header now has operation: update + populated diffHash

./bin/sophosfw firewall rule list --profile testvm | grep sophosfw-smoke-create
# ↑ rule exists on the firewall

# 2. Cleanup: delete the test rule.
HASH=$(./bin/sophosfw firewall rule show sophosfw-smoke-create --profile testvm --json 2>/dev/null | grep '_diffHash' | sed 's/.*"\([a-f0-9]*\)".*/\1/')
./bin/sophosfw firewall rule delete sophosfw-smoke-create --profile testvm --expected-diff-hash "$HASH" --yes
./bin/sophosfw firewall rule list --profile testvm | grep sophosfw-smoke-create || echo "OK: deleted"
```

- [ ] **Step 4: Manual smoke — firewall rule new --from**

```bash
# Pick an existing safe rule to clone. Block Countries is read-only-friendly.
./bin/sophosfw firewall rule new sophosfw-smoke-clone --from 'Block Countries' --profile testvm
cat ~/.config/sophosfw/profiles/testvm/drafts/firewall/sophosfw-smoke-clone.yaml | head -20
# ↑ body should contain Block Countries' fields with Name overwritten

# Don't push this — just verify the draft exists with the right body, then clean up.
rm ~/.config/sophosfw/profiles/testvm/drafts/firewall/sophosfw-smoke-clone.yaml
```

- [ ] **Step 5: Manual smoke — nat rule create**

```bash
./bin/sophosfw nat rule new sophosfw-smoke-nat-create --profile testvm
./bin/sophosfw nat rule push sophosfw-smoke-nat-create --profile testvm --json | head -15
# ↑ confirm <Set operation="add"> for NATRule

# Don't apply — the template's "Original" sentinels make this a no-op rule
# but we don't need to clutter the firewall. Just verify the dry-run.
rm ~/.config/sophosfw/profiles/testvm/drafts/nat/sophosfw-smoke-nat-create.yaml
```

- [ ] **Step 6: Verify audit log**

```bash
tail -20 ~/.config/sophosfw/audit.log | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        print(f\"{e.get('timestamp','')[:19]} {e.get('operation'):30} {e.get('objectName',''):30} {e.get('result')}\")
    except: pass
"
```

Expected entries (recent): `firewall_rule_new`, `firewall_rule_create`, `firewall_rule_delete`, `nat_rule_new`. Each has the right `result` field.

- [ ] **Step 7: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "test: phase 9 create-workflow integration smoke"
```

---

## Task 8: Docs + acceptance + tag v0.8.0-phase9

**Files:**
- Modify: `docs/api-coverage.md`
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update docs/api-coverage.md FirewallRule row**

Find:
```
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show/pull/diff/push/delete | firewall_rule_list/show; object_list/get/search/usage | yes | Phase 8 | yes (sophosfw firewall rule push) | yes (sophosfw firewall rule delete) | n/a | Phase 7 |
```

Replace with:
```
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show/new/pull/diff/push/delete | firewall_rule_list/show; object_list/get/search/usage | yes | yes (sophosfw firewall rule new) | yes (sophosfw firewall rule push) | yes (sophosfw firewall rule delete) | n/a | Phase 9 |
```

- [ ] **Step 2: Update docs/api-coverage.md NATRule row**

Find:
```
| Firewall | NATRule | object list/get NATRule; nat rule list/show/pull/diff/push/delete | nat_rule_list/show; object_list/get/search/usage | yes | Phase 9 | yes (sophosfw nat rule push) | yes (sophosfw nat rule delete) | n/a | Phase 8 |
```

Replace with:
```
| Firewall | NATRule | object list/get NATRule; nat rule list/show/new/pull/diff/push/delete | nat_rule_list/show; object_list/get/search/usage | yes | yes (sophosfw nat rule new) | yes (sophosfw nat rule push) | yes (sophosfw nat rule delete) | n/a | Phase 9 |
```

- [ ] **Step 3: Update docs/roadmap.md**

Find:
```markdown
- Phase 8 — NATRule draft workflow (complete; v0.7.0-phase8)
- Phase 9 — `firewall rule new` and `nat rule new` create workflows
- Phase 10 — MCP-native firewall and NAT rule mutating tools
```

Replace with:
```markdown
- Phase 8 — NATRule draft workflow (complete; v0.7.0-phase8)
- Phase 9 — Firewall + NAT rule create workflows (complete; v0.8.0-phase9)
- Phase 10 — MCP-native firewall and NAT rule mutating tools
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
git commit -m "fix: phase 9 acceptance pass formatting"
```

- [ ] **Step 6: Commit docs**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "docs: phase 9 complete in roadmap and api-coverage"
```

- [ ] **Step 7: Tag**

```bash
git tag -a v0.8.0-phase9 -m "Phase 9 complete (firewall + NAT rule create workflows)"
git tag --list | grep -E "(foundation|phase[3-9])"
```

Expected output:
```
v0.1.0-foundation
v0.2.0-phase3
v0.3.0-phase4
v0.4.0-phase5
v0.5.0-phase6
v0.6.0-phase7
v0.7.0-phase8
v0.8.0-phase9
```

- [ ] **Step 8: Push to origin**

```bash
git push origin main
git push origin v0.8.0-phase9
```

- [ ] **Step 9: Final sanity**

```bash
git log --oneline -15
```

---

## End of plan

Phase 10 (provisional): MCP-native firewall and NAT rule mutating tools.

## Self-review checklist

- ✅ **Spec coverage:** Section 4 (CLI surface) → T6; Section 5 (draft format change) → T1; Section 7.2/7.3 (Create services) → T2 + T4; Section 7.4 (push dispatch) → T3 + T5; Section 7.5 (diff dispatch) → T3 + T5; Section 7.6 (cli) → T6; Section 9 (errors) → no new sentinels needed; Section 10 (audit) → T2/T3/T4/T5; Section 11 (testing) → T2-T7; Section 12 (acceptance) → T8.
- ✅ **No placeholders.** Every step has actual code or commands.
- ✅ **Type consistency.** `FirewallRuleNewResult = FirewallRulePullResult` (alias) defined in T2 and used unchanged. `Operation` field on `Draft` defined in T1 and used in T2-T6. `firewallRuleTemplate` and `natRuleTemplate` constants defined where first used.
- ✅ **No Co-Authored-By trailer.** Every commit step inherits the project convention.
- ✅ **Single passing commit per task.** Each task's tests pass at commit time.
- ✅ **Acceptance.** T8 covers fmt/vet/race, docs, tag, push.
