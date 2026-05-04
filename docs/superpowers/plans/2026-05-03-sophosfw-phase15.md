# sophosfw Phase 15 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read + mutating coverage for site-to-site IPsec VPN: `VPNIPsecConnection` (full draft workflow), `IPsecPolicy` (Phase 2 / body-as-map), `VPNProfile` (Phase 1 / body-as-map). 15 new MCP tools (count 52 → 67). 17 new CLI sub-commands under a new `vpn` parent. Ship as `v0.13.0`.

**Architecture:** Three svc files, each mirroring an existing pattern. `VPNIPsecConnection` follows Phase 7-9 firewall_rule (draft cycle with snapshots, diff hash, body-as-map inline create/update). `IPsecPolicy` and `VPNProfile` follow Phase 12 iphostgroup (body-as-map only). Drafts at `drafts/vpn/`; snapshots at `snapshots/vpn/`. Catalog entries with `mutable: true`; column metadata best-guess (verified at T1).

**Tech Stack:** Go 1.26+, gopkg.in/yaml.v3, github.com/modelcontextprotocol/go-sdk v1.5.0. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-03-sophosfw-phase15-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.12.0`. Working dir: `/Users/ipm/code/sophosfw`. Testvm auth confirmed working.

```bash
git status
go test ./... -count=1 -race
golangci-lint run ./...
```

Expected: clean status, all tests pass, lint clean.

## File structure

**New files:**
- `internal/svc/vpnipsec.go` — VPNIPsecConnection draft cycle + body-as-map.
- `internal/svc/vpnipsec_test.go`.
- `internal/svc/ipsecpolicy.go` — IPsecPolicy body-as-map.
- `internal/svc/ipsecpolicy_test.go`.
- `internal/svc/vpnprofile.go` — VPNProfile body-as-map.
- `internal/svc/vpnprofile_test.go`.
- `internal/render/vpnipsec.go` — VPNIPsec push/pull envelopes (or extend `internal/render/object_mutation.go`).
- `internal/cli/vpn.go` — `vpn` parent + sub-parent registrations.
- `internal/cli/vpnipsec.go` — `vpn ipsec list/show/new/pull/diff/push/delete` cobra commands.
- `internal/cli/vpnipsec_test.go`.
- `internal/cli/ipsecpolicy_mutation.go` — `vpn policy list/show/create/update/delete`.
- `internal/cli/ipsecpolicy_mutation_test.go`.
- `internal/cli/vpnprofile_mutation.go` — `vpn ike-profile list/show/create/update/delete`.
- `internal/cli/vpnprofile_mutation_test.go`.
- `internal/mcp/vpnipsec.go` — 5 MCP tools.
- `internal/mcp/vpnipsec_test.go`.
- `internal/mcp/ipsecpolicy_mutation.go` — 5 MCP tools.
- `internal/mcp/ipsecpolicy_mutation_test.go`.
- `internal/mcp/vpnprofile_mutation.go` — 5 MCP tools.
- `internal/mcp/vpnprofile_mutation_test.go`.

**Modified files:**
- `internal/catalog/objects.yaml` — 3 new entries (VPNIPsecConnection, IPsecPolicy, VPNProfile).
- `internal/catalog/catalog_test.go` — `TestCatalog_Phase15NewlyMutable`.
- `internal/draft/paths.go` — add `"vpn"` to `validTags`.
- `internal/draft/paths_test.go` — verify `"vpn"` accepted.
- `internal/cli/root.go` — register `newVPNCmd(d)`.
- `internal/mcp/server.go` — register the 3 new tool sets.
- `internal/mcp/server_test.go` — tool count 52 → 67; add 15 names.
- `internal/render/object_mutation.go` — add 3 new schema names (vpnIpsecMutation, ipsecPolicyMutation, vpnProfileMutation).
- `docs/api-coverage.md` — 3 new VPN rows.
- `docs/roadmap.md` — Phase 15 complete (final task).

---

## Task 1: Catalog + draft tag allowlist + API verification probe

**Files:**
- Modify: `internal/catalog/objects.yaml`
- Modify: `internal/catalog/catalog_test.go`
- Modify: `internal/draft/paths.go`
- Modify: `internal/draft/paths_test.go`
- Modify: `internal/render/object_mutation.go` (add 3 schema names)

- [ ] **Step 1: API verification probe (against testvm)**

Before committing scope, verify each of the three types accepts mutations via the XML API:

```bash
cd /Users/ipm/code/sophosfw
# Read works for all three? (sanity)
go run ./cmd/sophosfw raw get VPNIPsecConnection --profile testvm 2>&1 | head -20
go run ./cmd/sophosfw raw get IPsecPolicy --profile testvm 2>&1 | head -20
go run ./cmd/sophosfw raw get VPNProfile --profile testvm 2>&1 | head -20
```

Expected: each returns either `<status code="200">` with a body, or `<status code="500">` with "No matching records" if none exist. Either is fine (read works).

If a type returns "Operation could not be performed on Entity" or similar, document the gap and adjust scope: drop that type to read-only-only mode (still add the catalog entry but skip Create/Update/Delete in svc + CLI + MCP). Update the spec out-of-scope section. STOP and report findings before proceeding.

- [ ] **Step 2: Add 3 catalog entries**

Append to `internal/catalog/objects.yaml`:

```yaml
- tag: VPNIPsecConnection
  aliases: [vpn-ipsec, ipsec-tunnel, ipsec-connection]
  description: "Site-to-site IPsec VPN tunnels"
  columns: [Name, Status, ConnectionType, AuthenticationType, Strategy]
  filterable: [Name, Status, ConnectionType]
  usageTag: ""
  typedParser: ""
  mutable: true

- tag: IPsecPolicy
  aliases: [ipsec-policy, vpn-ipsec-policy]
  description: "IPsec (Phase 2) encryption policies"
  columns: [Name, KeyLifetime, KeyNegotiationTries]
  filterable: [Name]
  usageTag: ""
  typedParser: ""
  mutable: true

- tag: VPNProfile
  aliases: [ike-profile, vpn-ike-profile, vpn-profile]
  description: "IKE (Phase 1) policies / VPN profiles"
  columns: [Name, AuthenticationMode]
  filterable: [Name]
  usageTag: ""
  typedParser: ""
  mutable: true
```

The column lists are best-guess. After Step 1 sees a real response body, update the columns to match the actual response keys (e.g. if the response uses `Type` instead of `ConnectionType`, fix that here).

- [ ] **Step 3: Catalog test**

Append to `internal/catalog/catalog_test.go`:

```go
func TestCatalog_Phase15NewlyMutable(t *testing.T) {
    c, err := NewDefault()
    require.NoError(t, err)
    for _, tag := range []string{"VPNIPsecConnection", "IPsecPolicy", "VPNProfile"} {
        entry, ok := c.Resolve(tag)
        require.True(t, ok, "tag %q should exist", tag)
        require.True(t, entry.Mutable, "tag %q must be mutable as of Phase 15", tag)
    }
}
```

- [ ] **Step 4: Add `"vpn"` to draft validTags**

Find `validTags` in `internal/draft/paths.go`:

```bash
grep -n "validTags" internal/draft/paths.go
```

Append `"vpn"` to the slice.

Add a test case in `internal/draft/paths_test.go` (or extend the existing tag-validation test) asserting `"vpn"` is accepted by `DraftPath` / `SnapshotPath`:

```go
func TestPaths_VPNTagAccepted(t *testing.T) {
    p, err := DraftPath("/base", "home", "vpn", "tunnel-name")
    require.NoError(t, err)
    require.Contains(t, p, "vpn/")
}
```

- [ ] **Step 5: Add 3 schema names to render envelope**

In `internal/render/object_mutation.go::schemaForObjectType`, add 3 cases:

```go
case "VPNIPsecConnection":
    return "sophosfw.v1.vpnIpsecMutation"
case "IPsecPolicy":
    return "sophosfw.v1.ipsecPolicyMutation"
case "VPNProfile":
    return "sophosfw.v1.vpnProfileMutation"
```

- [ ] **Step 6: Run + commit**

```bash
go test ./internal/catalog ./internal/draft ./internal/render -count=1 -race -v
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/catalog/objects.yaml internal/catalog/catalog_test.go internal/draft/paths.go internal/draft/paths_test.go internal/render/object_mutation.go
git commit -m "$(cat <<'EOF'
phase15: catalog + draft tag + render schema for VPN types

Three new catalog entries (VPNIPsecConnection, IPsecPolicy,
VPNProfile) flagged mutable. validTags adds "vpn" so DraftPath /
SnapshotPath accept the new tag. ObjectMutationEnvelope gains 3 new
schema names for the body-as-map mutating types. Column metadata is
best-guess from Sophos 22.x API docs; verify against actual list
output during T2 read-side implementation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Do NOT push.

---

## Task 2: VPNIPsecSvc — read-side (List, Get)

**Files:**
- Create: `internal/svc/vpnipsec.go` (read-only methods only in this task)
- Create: `internal/svc/vpnipsec_test.go`

VPNIPsecConnection's read methods delegate cleanly to ObjectSvc.List / ObjectSvc.Get (which already injects `_diffHash` for mutable types per Phase 12 T5). T2 sets up the service struct and the read-side methods only; T3 adds the draft cycle + mutating methods.

- [ ] **Step 1: Verify the actual response shape**

```bash
go run ./cmd/sophosfw object list VPNIPsecConnection --profile testvm 2>&1 | head -30
go run ./cmd/sophosfw object get VPNIPsecConnection --filter Name:eq:<some-tunnel> --profile testvm -o yaml 2>&1 | head -50
```

(If no tunnels are configured on testvm, generate sample output via a known tunnel name from web UI, OR add via web UI temporarily — operator-driven.)

Compare the actual top-level keys against the column whitelist in T1 step 2's catalog entry. If `Status`, `ConnectionType`, `AuthenticationType`, `Strategy` aren't the real names, update the catalog entry in a follow-up commit before T3.

- [ ] **Step 2: Write `internal/svc/vpnipsec.go` (read-side only)**

Mirror `internal/svc/firewallrule.go` structure (the file that contains FirewallRuleSvc.Get). The struct + read methods:

```go
package svc

import (
    "context"
    "time"

    "github.com/iainmoffat/sophosfw/internal/catalog"
)

type VPNIPsecSvc struct {
    Inner   *ObjectSvc
    Audit   *AuditLog
    BaseDir string
    Now     func() time.Time
    Version string
}

func (s *VPNIPsecSvc) now() time.Time {
    if s.Now != nil { return s.Now() }
    return time.Now().UTC()
}

func (s *VPNIPsecSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
    obj, err := s.Inner.Get(ctx, profileName, "VPNIPsecConnection", "Name", name)
    if err != nil {
        return nil, err
    }
    if obj == nil {
        return nil, nil
    }
    return toMap(obj.Data), nil  // mirror firewallrule.go's toMap usage
}
```

(Verify exact `ObjectSvc.Get` signature and `toMap` helper; mirror what `firewallrule.go` does.)

- [ ] **Step 3: Tests for the read-side**

Mirror the `firewallrule_test.go` patterns. At minimum:

```go
func TestVPNIPsec_Get_ReturnsBody(t *testing.T)
func TestVPNIPsec_Get_NotFound_ReturnsNil(t *testing.T)
func TestVPNIPsec_Get_InjectsDiffHash(t *testing.T)  // confirms Phase 12 T5 still works for the new tag
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/svc -run TestVPNIPsec_Get -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/vpnipsec.go internal/svc/vpnipsec_test.go
git commit -m "$(cat <<'EOF'
svc: VPNIPsecSvc read-side (Get; List delegates to ObjectSvc)

Phase 15 read-only foundation for VPNIPsecConnection. Get returns
the body with _diffHash injected by ObjectSvc (Phase 12 T5). Read
tests confirm the integration. Mutating methods land in T3.
EOF
)"
```

---

## Task 3: VPNIPsecSvc — draft workflow + mutating methods

**Files:**
- Modify: `internal/svc/vpnipsec.go` (extend with draft + mutating methods)
- Modify: `internal/svc/vpnipsec_test.go` (~25 new tests)

This is the meaty task. Mirror Phase 7 `firewallrule_pull.go` + Phase 9 `firewallrule_create.go` with VPNIPsecConnection-specific:
- XML tag: `VPNIPsecConnection`
- Draft tag: `vpn` (added to validTags in T1)
- Required fields: `Name`, `Status`, `ConnectionType` (verify at T2 step 1; adjust if needed)
- Audit op prefix: `vpn_ipsec_`

- [ ] **Step 1: Add result types + template**

```go
type VPNIPsecPushResult = ObjectMutationResult  // structurally identical to FirewallRulePushResult

type VPNIPsecNewResult struct {
    Profile     string
    Tunnel      string
    DraftPath   string
    SnapshotPath string
    DiffHash    string
    References  []string
}

type VPNIPsecPullResult = VPNIPsecNewResult  // same shape

const vpnIPsecTemplate = `Name: __NAME__
Status: Disable
ConnectionType: SiteToSite
# IMPORTANT: this template is fail-safe. Status=Disable; the user must
# fill in real peer config and traffic selectors before pushing. For
# most users 'sophosfw vpn ipsec new <name> --from <existing-tunnel>'
# is the more practical starting point.
`

var requiredVPNIPsecFields = []string{"Name", "Status", "ConnectionType"}
```

(Adjust required fields based on T2 step 1 findings.)

- [ ] **Step 2: Add the draft + mutating methods**

Methods to add (mirror Phase 7-9 firewall_rule):

```go
func (s *VPNIPsecSvc) New(ctx, profile, name, fromName string) (*VPNIPsecNewResult, error)
func (s *VPNIPsecSvc) Pull(ctx, profile, name string) (*VPNIPsecPullResult, error)
func (s *VPNIPsecSvc) Diff(profile, name string) (string, error)
func (s *VPNIPsecSvc) Push(ctx, profile, name string, expectedHash string, ignoreHash, dryRun bool) (*VPNIPsecPushResult, error)
func (s *VPNIPsecSvc) CreateInline(ctx, profile, name string, body map[string]any, dryRun bool) (*VPNIPsecPushResult, error)
func (s *VPNIPsecSvc) UpdateInline(ctx, profile, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*VPNIPsecPushResult, error)
func (s *VPNIPsecSvc) Delete(ctx, profile, name string, expectedHash string, ignoreHash, dryRun bool) (*VPNIPsecPushResult, error)
```

For each method: copy the corresponding firewallrule method body, substitute:
- `"FirewallRule"` → `"VPNIPsecConnection"` (XML tag)
- `"firewall"` → `"vpn"` (draft path tag)
- `"firewall_rule_"` → `"vpn_ipsec_"` (audit op prefix)
- `firewallRuleTemplate` → `vpnIPsecTemplate`
- `requiredFirewallRuleFields` → `requiredVPNIPsecFields`

The `_diffHash` strip protections from Phase 13.x (in `Pull` and in `parseAndValidateRuleBody`) — copy these into the VPN equivalents. Tests must include the regression check (assert no `_diffHash` leaks into XML push envelope).

- [ ] **Step 3: Tests**

Mirror `firewallrule_create_test.go` + `firewallrule_pull_test.go`. ~25 tests:

```
TestVPNIPsec_New_FromTemplate
TestVPNIPsec_New_FromExisting
TestVPNIPsec_New_RejectsExistingDraft
TestVPNIPsec_Pull_WritesSnapshotAndDraft
TestVPNIPsec_Pull_StripsDiffHashFromDraft
TestVPNIPsec_Diff_NoDraft_Empty
TestVPNIPsec_Diff_DraftDiffersFromSnapshot
TestVPNIPsec_Push_RejectsMissingDraft
TestVPNIPsec_Push_RejectsHashMismatch
TestVPNIPsec_Push_DryRun_EmitsPreview
TestVPNIPsec_Push_Apply_RefetchAndArchive
TestVPNIPsec_Push_StripsDiffHashFromHandEditedDraft   (regression)
TestVPNIPsec_CreateInline_RejectsMissingRequiredField
TestVPNIPsec_CreateInline_DryRun
TestVPNIPsec_CreateInline_Apply
TestVPNIPsec_UpdateInline_RejectsMissingExpectedDiffHash
TestVPNIPsec_UpdateInline_DryRun
TestVPNIPsec_UpdateInline_Apply
TestVPNIPsec_UpdateInline_StripsInjectedDiffHashFromBody  (regression)
TestVPNIPsec_Delete_RejectsMissingExpectedDiffHash
TestVPNIPsec_Delete_DiffHashMatch_Applies
TestVPNIPsec_Create_DoesNotMutateCallerBody              (Phase 14 regression)
TestVPNIPsec_Update_DoesNotMutateCallerBody              (Phase 14 regression)
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/svc -run TestVPNIPsec -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/vpnipsec.go internal/svc/vpnipsec_test.go
git commit -m "$(cat <<'EOF'
svc: VPNIPsecSvc draft workflow + mutating methods

Mirror of Phase 7 firewall_rule_pull + Phase 9 firewall_rule_create
for VPNIPsecConnection. Methods: New (template or --from), Pull,
Diff, Push (with snapshot rotation + expectedDiffHash gate),
CreateInline, UpdateInline, Delete. Drafts at drafts/vpn/<slug>.yaml,
snapshots at snapshots/vpn/<slug>-<utc>.yaml.

_diffHash strip protections (Phase 13.x) replicated for the VPN path
in Pull and in body marshal. Body-clone (Phase 14) inherited via the
same clone-and-skip pattern used by the body-as-map svcs.
EOF
)"
```

---

## Task 4: IPsecPolicySvc — body-as-map

**Files:**
- Create: `internal/svc/ipsecpolicy.go`
- Create: `internal/svc/ipsecpolicy_test.go`

Pure mirror of `internal/svc/iphostgroup.go` (Phase 12 T6). Substitutions per the substitution table:

| Field | Value |
|---|---|
| XML tag | `IPsecPolicy` |
| Required keys | `Name` |
| svc type | `IPsecPolicySvc` |
| Audit op prefix | `ipsec_policy_` |
| Schema | `sophosfw.v1.ipsecPolicyMutation` (added in T1) |

- [ ] **Step 1: Copy iphostgroup as the closest template**

```bash
cp internal/svc/iphostgroup.go internal/svc/ipsecpolicy.go
cp internal/svc/iphostgroup_test.go internal/svc/ipsecpolicy_test.go
```

Substitute:
- `IPHostGroup` → `IPsecPolicy` (struct names, type names, marshal tag)
- `requiredIPHostGroupFields` → `requiredIPsecPolicyFields = []string{"Name"}`
- Audit op prefix `ip_host_group_` → `ipsec_policy_`

Body fixtures in tests use minimal `{Name: "policy-name"}`. The actual IPsecPolicy body has many fields (encryption algorithm, hash, DH group, key lifetime, etc.) but most have Sophos defaults — minimal body should work for create. Verify at integration time.

- [ ] **Step 2: Run + commit**

```bash
go test ./internal/svc -run TestIPsecPolicy -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/ipsecpolicy.go internal/svc/ipsecpolicy_test.go
git commit -m "$(cat <<'EOF'
svc: IPsecPolicySvc — body-as-map create/update/delete

Pure mirror of Phase 12 IPHostGroupSvc with IPsecPolicy substitutions.
Required: Name. Other fields default to Sophos defaults; minimal
bodies should work for create. Audit ops: ipsec_policy_create/update/delete.
EOF
)"
```

---

## Task 5: VPNProfileSvc — body-as-map

**Files:**
- Create: `internal/svc/vpnprofile.go`
- Create: `internal/svc/vpnprofile_test.go`

Mirror of T4. Substitutions:

| Field | Value |
|---|---|
| XML tag | `VPNProfile` |
| Required keys | `Name`, `AuthenticationMode` (verify at impl) |
| svc type | `VPNProfileSvc` |
| Audit op prefix | `vpn_profile_` |
| Schema | `sophosfw.v1.vpnProfileMutation` |

- [ ] **Step 1: Copy ipsecpolicy.go (T4) as template**

```bash
cp internal/svc/ipsecpolicy.go internal/svc/vpnprofile.go
cp internal/svc/ipsecpolicy_test.go internal/svc/vpnprofile_test.go
```

Substitute:
- `IPsecPolicy` → `VPNProfile`
- `requiredIPsecPolicyFields` → `requiredVPNProfileFields = []string{"Name", "AuthenticationMode"}`
- `ipsec_policy_` → `vpn_profile_`

- [ ] **Step 2: Run + commit**

```bash
go test ./internal/svc -run TestVPNProfile -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/vpnprofile.go internal/svc/vpnprofile_test.go
git commit -m "$(cat <<'EOF'
svc: VPNProfileSvc — body-as-map create/update/delete

Pure mirror of T4 IPsecPolicySvc with VPNProfile substitutions.
Required: Name, AuthenticationMode. Audit ops: vpn_profile_create/
update/delete.
EOF
)"
```

---

## Task 6: CLI — `vpn` parent + `vpn ipsec` sub-tree

**Files:**
- Create: `internal/cli/vpn.go` — `newVPNCmd(d)` parent
- Create: `internal/cli/vpnipsec.go` — `vpn ipsec list/show/new/pull/diff/push/delete`
- Create: `internal/cli/vpnipsec_test.go`
- Modify: `internal/cli/root.go` — register `newVPNCmd(d)`

- [ ] **Step 1: Write the `vpn` parent**

```go
// internal/cli/vpn.go
package cli

import "github.com/spf13/cobra"

func newVPNCmd(d RootDeps) *cobra.Command {
    cmd := &cobra.Command{Use: "vpn", Short: "VPN commands"}
    cmd.AddCommand(newVPNIPsecCmd(d))
    cmd.AddCommand(newIPsecPolicyCmd(d))      // T7
    cmd.AddCommand(newVPNProfileCmd(d))       // T7
    return cmd
}
```

- [ ] **Step 2: Write `vpn ipsec` sub-tree**

Mirror `internal/cli/firewallrule.go` (Phase 7-9) — that file has list/show/new/pull/diff/push/delete commands for firewall rules. Copy structure with VPNIPsecConnection substitutions.

Required CLI helpers per Phase 14:
- `AddProfileSetFlag(cmd)` on push/delete (and CreateInline-equivalent path if exposed via CLI — for VPN, push handles both create and update via the draft cycle; the inline body path is the fan-out target)
- `resolveTargetProfiles(cmd, d.Config)` for push/delete
- `printObjectMutation` / `printFanout` from Phase 12+14

Sub-commands:
- `vpn ipsec list` — wraps ObjectSvc.List with column whitelist from catalog
- `vpn ipsec show <name>` — `ObjectSvc.Get` with `_diffHash` injected (Phase 12 T5 already handles this)
- `vpn ipsec new <name> [--from <existing>]` — VPNIPsecSvc.New
- `vpn ipsec pull <name>` — VPNIPsecSvc.Pull
- `vpn ipsec diff <name>` — VPNIPsecSvc.Diff
- `vpn ipsec push <name> [--expected-diff-hash] [--ignore-hash] [--dry-run] [--yes] [--profile-set]` — VPNIPsecSvc.Push (when draft exists) OR a separate inline path
- `vpn ipsec delete <name> [--expected-diff-hash] [--ignore-hash] [--dry-run] [--yes] [--profile-set]` — VPNIPsecSvc.Delete

Note: `firewall rule push` reads from a draft; `vpn ipsec push` should do the same. The body-as-map inline path (CreateInline / UpdateInline) is exposed via MCP only (T9) — CLI sticks with the draft workflow for symmetry with `firewall rule push`.

- [ ] **Step 3: Wire `newVPNCmd(d)` into root**

```bash
grep -n "newFirewallCmd\|cmd.AddCommand" internal/cli/root.go | head
```

Add `cmd.AddCommand(newVPNCmd(d))` next to existing top-level commands.

- [ ] **Step 4: Tests + commit**

```go
TestCmd_VPNIPsec_List_DryShape
TestCmd_VPNIPsec_New_FromTemplate
TestCmd_VPNIPsec_Push_DryRun
TestCmd_VPNIPsec_Delete_DryRun
```

```bash
go test ./internal/cli -run TestCmd_VPNIPsec -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
go run ./cmd/sophosfw vpn ipsec --help    # smoke
git add internal/cli/vpn.go internal/cli/vpnipsec.go internal/cli/vpnipsec_test.go internal/cli/root.go
git commit -m "$(cat <<'EOF'
cli: vpn parent + vpn ipsec list/show/new/pull/diff/push/delete

Mirror of Phase 7-9 firewall rule CLI for VPNIPsecConnection. Drafts
under drafts/vpn/<slug>.yaml; snapshots under snapshots/vpn/. push
and delete inherit Phase 14 --profile-set fan-out support.
EOF
)"
```

---

## Task 7: CLI — `vpn policy` + `vpn ike-profile`

**Files:**
- Create: `internal/cli/ipsecpolicy_mutation.go`
- Create: `internal/cli/ipsecpolicy_mutation_test.go`
- Create: `internal/cli/vpnprofile_mutation.go`
- Create: `internal/cli/vpnprofile_mutation_test.go`

Both are pure mirrors of `internal/cli/iphostgroup_mutation.go` (Phase 12 T6) — body-as-map create/update/delete with `--body @file`, `--expected-diff-hash`, `--ignore-hash`, `--dry-run`, `--yes`, `--profile-set`.

- [ ] **Step 1: ipsec policy CLI**

Copy `internal/cli/iphostgroup_mutation.go` → `internal/cli/ipsecpolicy_mutation.go`. Substitute:
- `IPHostGroup` → `IPsecPolicy`, `iphostGroup` → `ipsecPolicy`
- Cobra parent name `host group` → `vpn policy` (the parent is registered in T6's `newVPNCmd`; this file just provides `newIPsecPolicyCmd(d)`)
- Use existing `vpn policy` sub-name format

Same for tests — copy `iphostgroup_mutation_test.go`.

- [ ] **Step 2: VPN ike-profile CLI**

Same copy pattern, this time for VPNProfile → `internal/cli/vpnprofile_mutation.go`. CLI sub-name: `ike-profile`.

- [ ] **Step 3: Tests + commit**

```bash
go test ./internal/cli -run "TestCmd_VPNPolicy\|TestCmd_VPNIKE" -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
go run ./cmd/sophosfw vpn policy --help
go run ./cmd/sophosfw vpn ike-profile --help
git add internal/cli/ipsecpolicy_mutation.go internal/cli/ipsecpolicy_mutation_test.go internal/cli/vpnprofile_mutation.go internal/cli/vpnprofile_mutation_test.go
git commit -m "$(cat <<'EOF'
cli: vpn policy + vpn ike-profile body-as-map create/update/delete

Pure mirrors of Phase 12 host group CLI for IPsecPolicy and VPNProfile.
Required keys per type: IPsecPolicy { Name }; VPNProfile { Name,
AuthenticationMode }. All Phase 14 fan-out support inherited via the
template.
EOF
)"
```

---

## Task 8: MCP — `vpn_ipsec_*` tools

**Files:**
- Create: `internal/mcp/vpnipsec.go`
- Create: `internal/mcp/vpnipsec_test.go`
- Modify: `internal/mcp/server.go` — register
- Modify: `internal/mcp/server_test.go` — count 52 → 57

5 tools:
- `vpn_ipsec_list` (read)
- `vpn_ipsec_show` (read; injects `_diffHash`)
- `vpn_ipsec_create` (mutating; CreateInline)
- `vpn_ipsec_update` (mutating; UpdateInline)
- `vpn_ipsec_delete` (mutating; Delete)

Mirror `internal/mcp/firewallrule.go` (read tools) + `internal/mcp/firewallrule_mutation.go` (mutating tools).

- [ ] **Step 1: Read tools**

Copy patterns from `internal/mcp/firewallrule.go` for `firewall_rule_list/show`. Substitute names.

- [ ] **Step 2: Mutating tools**

Copy `internal/mcp/firewallrule_mutation.go` and substitute. Each Input struct gets the Phase 14 `ProfileSet` field. Each handler routes through the resolveTargetProfilesMcp + svc.Run pattern from Phase 14 T7.

- [ ] **Step 3: Register + count**

`s.registerVPNIPsec()` in `registerAll`. Count in server_test.go: 52 → 57. Add 5 tool names.

- [ ] **Step 4: Tests + commit**

8 mutating handler tests + ~3 read handler tests.

```bash
go test ./internal/mcp -count=1 -race
golangci-lint run ./...
git add internal/mcp/vpnipsec.go internal/mcp/vpnipsec_test.go internal/mcp/server.go internal/mcp/server_test.go
git commit -m "$(cat <<'EOF'
mcp: vpn_ipsec_list/show/create/update/delete (count 52 to 57)

5 new MCP tools for VPNIPsecConnection. Read tools mirror
firewall_rule_list/show; mutating tools follow the body-as-map
pattern with Phase 14 profileSet field for fan-out. show injects
_diffHash via the Phase 12 T5 generic object_get path.
EOF
)"
```

---

## Task 9: MCP — `vpn_policy_*` and `vpn_ike_profile_*` tools

**Files:**
- Create: `internal/mcp/ipsecpolicy_mutation.go` + `_test.go`
- Create: `internal/mcp/vpnprofile_mutation.go` + `_test.go`
- Modify: `internal/mcp/server.go` — register
- Modify: `internal/mcp/server_test.go` — count 57 → 67

10 tools:
- `vpn_policy_list / show / create / update / delete`
- `vpn_ike_profile_list / show / create / update / delete`

Pure mirrors of Phase 12 `internal/mcp/iphostgroup_mutation.go`. Each gets a `_list` and `_show` companion (read).

- [ ] **Step 1: Copy iphostgroup MCP files as templates**

```bash
cp internal/mcp/iphostgroup_mutation.go internal/mcp/ipsecpolicy_mutation.go
cp internal/mcp/iphostgroup_mutation_test.go internal/mcp/ipsecpolicy_mutation_test.go
```

Substitute: `IPHostGroup` → `IPsecPolicy`, tool prefixes `host_group_` → `vpn_policy_`, audit ops, etc.

Same for `vpnprofile_mutation.go` with `VPNProfile` / `vpn_ike_profile_`.

- [ ] **Step 2: Add `_list` and `_show` tools per type**

These don't exist for IPHostGroup. Mirror `internal/mcp/firewallrule.go`'s `firewall_rule_list` + `firewall_rule_show` patterns (which DO inject `_diffHash`).

For each type:
- `vpn_policy_list` — wraps `ObjectSvc.List("IPsecPolicy", ...)` 
- `vpn_policy_show` — wraps `ObjectSvc.Get("IPsecPolicy", "Name", name)` (already injects `_diffHash` via Phase 12 T5)
- Same for `vpn_ike_profile_list` / `_show`

Two new tools per type × 2 types = 4 read tools. Plus 3 mutating tools per type × 2 = 6 mutating tools. Total 10 new tools. Tool count 57 → 67.

- [ ] **Step 3: Register + count + commit**

```bash
go test ./internal/mcp -count=1 -race
golangci-lint run ./...
git add internal/mcp/ipsecpolicy_mutation.go internal/mcp/ipsecpolicy_mutation_test.go internal/mcp/vpnprofile_mutation.go internal/mcp/vpnprofile_mutation_test.go internal/mcp/server.go internal/mcp/server_test.go
git commit -m "$(cat <<'EOF'
mcp: vpn_policy + vpn_ike_profile tools (count 57 to 67)

10 new tools (5 per type): list/show/create/update/delete for
IPsecPolicy and VPNProfile. Read tools (list/show) mirror Phase 10
firewall_rule_list/show with _diffHash injection. Mutating tools
mirror Phase 12 host_group_create/update/delete with Phase 14
profileSet field. Final tool count: 67.
EOF
)"
```

---

## Task 10: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

- [ ] **Step 1: Add read-only smokes**

```go
TestIntegration_VPNIPsec_List_ReturnsValidShape
TestIntegration_IPsecPolicy_List_ReturnsValidShape
TestIntegration_VPNProfile_List_ReturnsValidShape
TestIntegration_VPNIPsec_ObjectGet_InjectsDiffHash
```

These run any time `SOPHOSFW_PROFILE` is set (no extra env required).

- [ ] **Step 2: Add dry-run mutating smokes**

```go
TestIntegration_MCPVPNIPsecCreate_DryRun
TestIntegration_MCPIPsecPolicyCreate_DryRun
TestIntegration_MCPVPNProfileCreate_DryRun
```

Each builds a minimal valid body (using best-guess required fields), calls the MCP tool with `dryRun: true`, asserts a `sophosfw.v1.preview` envelope. NO live mutations — testvm is cloned-prod.

- [ ] **Step 3: Run against testvm**

```bash
SOPHOSFW_PROFILE=testvm go test -tags=integration ./internal/testutil -run "TestIntegration_(VPNIPsec|IPsecPolicy|VPNProfile|MCPVPNIPsec|MCPIPsecPolicy|MCPVPNProfile)" -v
```

Expected: 7 PASS.

If any fail with "Operation could not be performed on Entity" on a Create-DryRun, that's the API rejecting that mutation — drop the failing type's mutating support per the spec section 9 fallback. Document in the commit message; update spec section 8 (out-of-scope) accordingly.

- [ ] **Step 4: Manual smoke (operator-driven)**

```bash
sophosfw vpn ipsec list
sophosfw vpn policy list
sophosfw vpn ike-profile list

sophosfw vpn ipsec show <existing-tunnel> -o yaml | head -20
# Verify _diffHash present in JSON output:
sophosfw vpn ipsec show <existing-tunnel> -o json | jq ._diffHash

# Draft cycle smoke (don't actually push)
sophosfw vpn ipsec new test-tunnel --from <existing-tunnel>
ls ~/.config/sophosfw/profiles/testvm/drafts/vpn/
sophosfw vpn ipsec diff test-tunnel
sophosfw vpn ipsec push test-tunnel --dry-run
rm ~/.config/sophosfw/profiles/testvm/drafts/vpn/test-tunnel.yaml
```

- [ ] **Step 5: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "$(cat <<'EOF'
test: phase 15 VPN integration smokes

7 tests gated by SOPHOSFW_PROFILE: 4 read-only smokes (list per type
+ object_get with _diffHash injection) and 3 dry-run mutating smokes
(create with minimal valid body for each type). NO live mutations
since testvm is cloned-prod.

If a dry-run mutating smoke fails with the API rejecting the
Set add envelope, the failing type drops to read-only mode per the
Phase 15 spec section 9 fallback path.
EOF
)"
```

---

## Task 11: Docs + tag v0.13.0 + verify release

**Files:**
- Modify: `docs/api-coverage.md`
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update `docs/api-coverage.md`**

Add 3 new VPN rows to the table:

```
| VPN | VPNIPsecConnection | object list/get; vpn ipsec list/show/new/pull/diff/push/delete | vpn_ipsec_list/show/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw vpn ipsec new; vpn_ipsec_create) | yes (sophosfw vpn ipsec push; vpn_ipsec_update) | yes (sophosfw vpn ipsec delete; vpn_ipsec_delete) | n/a | Phase 15 |
| VPN | IPsecPolicy | object list/get; vpn policy list/show/create/update/delete | vpn_policy_list/show/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw vpn policy create; vpn_policy_create) | yes (sophosfw vpn policy update; vpn_policy_update) | yes (sophosfw vpn policy delete; vpn_policy_delete) | n/a | Phase 15 |
| VPN | VPNProfile | object list/get; vpn ike-profile list/show/create/update/delete | vpn_ike_profile_list/show/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw vpn ike-profile create; vpn_ike_profile_create) | yes (sophosfw vpn ike-profile update; vpn_ike_profile_update) | yes (sophosfw vpn ike-profile delete; vpn_ike_profile_delete) | n/a | Phase 15 |
```

(If T10 dropped any type to read-only per the fallback path, adjust those cells accordingly.)

- [ ] **Step 2: Update `docs/roadmap.md`**

Append after Phase 14 line:

```
- Phase 15 — Site-to-site IPsec VPN (complete; v0.13.0)
```

- [ ] **Step 3: Final test pass**

```bash
go fmt ./... && go vet ./... && golangci-lint run ./... && go test -race ./...
```

- [ ] **Step 4: Commit + push**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "$(cat <<'EOF'
docs: phase 15 complete in roadmap and api-coverage

Three new VPN object types (VPNIPsecConnection, IPsecPolicy,
VPNProfile) with full CLI + MCP coverage. 15 new MCP tools
(count 52 to 67). Tag v0.13.0.
EOF
)"
git push origin main
```

Wait for CI:

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

- [ ] **Step 5: Tag**

```bash
git tag -a v0.13.0 -m "v0.13.0 — Phase 15: site-to-site IPsec VPN

CLI + MCP coverage for VPNIPsecConnection (full draft workflow),
IPsecPolicy (body-as-map), VPNProfile (body-as-map). 17 new CLI
sub-commands under a new vpn parent; 15 new MCP tools (count 52 to
67). Drafts at drafts/vpn/, snapshots at snapshots/vpn/. Phase 14
fan-out support inherited.

Out of scope: remote access VPN, certificate management,
operational commands (connect/disconnect/status). Deferred to
Phase 15.x or later."
git push origin v0.13.0
```

- [ ] **Step 6: Watch release**

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

- [ ] **Step 7: Verify**

```bash
gh release view v0.13.0 --repo iainmoffat/sophosfw --json name,assets
gh api repos/iainmoffat/homebrew-sophosfw/contents/sophosfw.rb --jq '.content' | base64 -d | grep '^  version'
brew update
brew upgrade sophosfw
sophosfw version

# Smoke
sophosfw vpn --help
sophosfw vpn ipsec --help
sophosfw vpn policy --help
sophosfw vpn ike-profile --help
```

Expected: all green; `sophosfw 0.13.0`; all 4 helps render.

---

## End of plan

## Self-review checklist

- ✅ **Spec coverage:** Section 3.1 (catalog) → T1; Section 3.2 (VPNIPsecSvc) → T2 + T3; Section 3.3 (IPsecPolicySvc + VPNProfileSvc) → T4 + T5; Section 3.4 (CLI) → T6 + T7; Section 3.5 (MCP) → T8 + T9; Section 3.6 (drafts) → T1; Section 3.7 (body validation) → T3 + T4 + T5; Section 7 (acceptance) → T11.
- ✅ **No placeholders.** Every task has concrete code references or copy-from instructions.
- ✅ **Tool count math.** 52 + 5 + 10 = 67. T8 (52→57), T9 (57→67).
- ✅ **Mechanical via mirroring.** T3 mirrors Phases 7-9 firewall_rule. T4/T5/T7/T9 mirror Phase 12 iphostgroup. T6 mirrors Phase 7-9 firewall CLI. T8 mirrors Phase 10 firewall_rule MCP.
- ✅ **API verification gated by T1 step 1.** Read-only probe for each type. T10 step 3 catches any per-type fallback at integration time. Spec section 9 documents the fallback path.
- ✅ **Phase 13.x leak protection.** T3 explicitly replicates the `_diffHash` strip in Pull and parseAndValidateRuleBody-equivalent.
- ✅ **Phase 14 body-clone protection.** Inherited by T3/T4/T5 via the same clone-and-skip pattern.

## Notes for the implementer

- **API-rejection fallback**: if T1 step 1 or T10 step 3 finds Sophos rejects mutations on a type, drop that type to read-only and document in the spec's out-of-scope section. Don't try to work around — the API surface is what it is.
- **Required-field guesses**: the lists in T3/T4/T5 are best-guess. T10 dry-run smokes will validate by sending minimal bodies. If a "required" field turns out to be optional (or vice-versa), update the validator and re-run tests.
- **Column metadata**: T2 step 1 verifies. If columns are wrong, fix in T2 step 1 before T3 starts.
- **Token handling**: T11 release zero-touch (`HOMEBREW_TAP_TOKEN` in repo secrets).
- **Subagent flow**: T1 small (verification + 5 small files). T3 is the meaty implementer task — full draft cycle with ~25 tests. T4/T5/T7/T9 are mechanical mirrors. T6 is moderate (new parent + 7 sub-commands). T11 is release.
