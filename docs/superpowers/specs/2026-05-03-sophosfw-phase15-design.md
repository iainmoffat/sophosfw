# Phase 15 — Site-to-site IPsec VPN (design)

**Date:** 2026-05-03
**Status:** Design (pre-implementation)
**Goal:** Add read + mutating coverage for the three Sophos site-to-site IPsec VPN object types: `VPNIPsecConnection` (full draft workflow), `IPsecPolicy` (Phase 2 / body-as-map), `VPNProfile` (Phase 1 / body-as-map). 15 new MCP tools (count 52 → 67). Ship as `v0.13.0`.

---

## 1. Motivation

After Phase 14, sophosfw covers the firewall's host/service/rule object surface across single firewalls and fleets. The largest remaining greenfield is VPN — a high-value, frequently-edited subsystem that has zero current coverage. Production firewalls run site-to-site IPsec tunnels, IPsec encryption policies, and IKE profiles; today, none of that is reachable via sophosfw.

Phase 15 closes that gap for the most common VPN use case: **site-to-site IPsec**. Remote access (SSL VPN, IPsec remote, L2TP/PPTP), certificate management, and operational control (connect/disconnect/status) are deferred — see section 8.

The three object types in scope:

- **`VPNIPsecConnection`** — the tunnel itself. References Phase 1 + Phase 2 profiles, peer addresses, traffic selectors, authentication. Body is deeply nested; users edit it iteratively. Gets the full draft workflow (mirror Phase 7 `firewall rule`).
- **`IPsecPolicy`** — Phase 2 / IPsec encryption policy. Smaller body; users typically pick from a small set. Body-as-map (mirror Phase 12).
- **`VPNProfile`** — Phase 1 / IKE policy. Same shape considerations as IPsecPolicy. Body-as-map.

Sophos terminology note: the API tag `VPNProfile` corresponds to "IKE policy" in the web UI; `IPsecPolicy` corresponds to "IPsec policy". CLI uses the web-UI terminology (`vpn ike-profile`, `vpn policy`) since that's what operators see day-to-day; catalog aliases bridge to the XML tag names.

## 2. Architecture

Three new svc files, each mirroring an existing pattern:

- `internal/svc/vpnipsec.go` — full draft workflow per Phase 7 `firewallrule_pull.go` + Phase 9 `firewallrule_create.go`. Methods: `List`, `Get`, `New`, `Pull`, `Diff`, `Push`, `Delete`. Drafts at `drafts/vpn/<slug>.yaml`; snapshots at `snapshots/vpn/<slug>-<utc>.yaml`. Reuses existing `internal/draft/paths.go` per-tag directory support.
- `internal/svc/ipsecpolicy.go` — body-as-map per Phase 12 `iphostgroup.go`. Methods: `List`, `Get`, `Create`, `Update`, `Delete`.
- `internal/svc/vpnprofile.go` — body-as-map. Same shape.

CLI extends the root with a new `vpn` parent command. MCP gains 15 new tools.

Catalog gets three new entries with `mutable: true` and column metadata for predictable table output.

No new sentinels, no new envelope shapes (reuses `sophosfw.v1.objectMutation` for the body-as-map types and per-type push envelopes for VPNIPsecConnection — same shape as `firewallRulePush`).

## 3. Components

### 3.1 Catalog entries

Add to `internal/catalog/objects.yaml`:

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

The `columns` arrays are best-guess based on Sophos 22.x XML API; verify against the actual response shape during implementation (Task 1) and adjust.

Catalog test (`TestCatalog_Phase15NewlyMutable`) added to assert the three are flagged mutable.

### 3.2 svc — `VPNIPsecConnection` (draft workflow)

Mirror `internal/svc/firewallrule_pull.go` + `internal/svc/firewallrule_create.go`. Public surface:

```go
type VPNIPsecSvc struct {
    Inner   *ObjectSvc
    Audit   *AuditLog
    BaseDir string
    Now     func() time.Time
    Version string
}

// Read-side
func (s *VPNIPsecSvc) Get(ctx, profile, name) (map[string]any, error)
// (List delegates to ObjectSvc.List with tag="VPNIPsecConnection")

// New: write a draft (from template OR --from existing)
func (s *VPNIPsecSvc) New(ctx, profile, name, fromName string) (*VPNIPsecNewResult, error)

// Pull: fetch live state to draft + snapshot
func (s *VPNIPsecSvc) Pull(ctx, profile, name string) (*VPNIPsecPullResult, error)

// Diff: snapshot vs current draft
func (s *VPNIPsecSvc) Diff(profile, name string) (string, error)

// Push: apply draft (with expectedDiffHash gate)
func (s *VPNIPsecSvc) Push(ctx, profile, name string, expectedHash string, ignoreHash, dryRun bool) (*VPNIPsecPushResult, error)

// CreateInline / UpdateInline: body-as-map paths for MCP (no draft needed)
func (s *VPNIPsecSvc) CreateInline(ctx, profile, name string, body map[string]any, dryRun bool) (*VPNIPsecPushResult, error)
func (s *VPNIPsecSvc) UpdateInline(ctx, profile, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*VPNIPsecPushResult, error)

// Delete: remove (with expectedDiffHash gate)
func (s *VPNIPsecSvc) Delete(ctx, profile, name string, expectedHash string, ignoreHash, dryRun bool) (*VPNIPsecPushResult, error)
```

Result types `VPNIPsecPullResult`, `VPNIPsecPushResult`, `VPNIPsecNewResult` mirror their `FirewallRule` counterparts.

Required fields validator: `Name`, `Status`, `ConnectionType` (the rest of the body shape varies — pass-through to Sophos).

Audit ops: `vpn_ipsec_new`, `vpn_ipsec_pull`, `vpn_ipsec_push`, `vpn_ipsec_create`, `vpn_ipsec_delete` (matching the firewall_rule audit op convention).

Drafts/snapshots: per-tag directory `vpn/`. The existing `internal/draft/paths.go::DraftPath(baseDir, profile, "vpn", ruleName)` works as-is once `"vpn"` is added to the `validTags` allowlist.

Default template (when `New` is called without `--from`): a fail-safe skeleton with `Status: Disable`, no peer config, no traffic selectors. User MUST edit before push or Sophos rejects. Mirrors the firewall_rule template pattern from Phase 9.

### 3.3 svc — `IPsecPolicy` and `VPNProfile` (body-as-map)

Mirror `internal/svc/iphostgroup.go` (Phase 12). Public surface per type:

```go
type IPsecPolicySvc struct {
    Inner *ObjectSvc
    Audit *AuditLog
    Now   func() time.Time
}

func (s *IPsecPolicySvc) Create(ctx, profile, name string, body map[string]any, dryRun bool) (*ObjectMutationResult, error)
func (s *IPsecPolicySvc) Update(ctx, profile, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error)
func (s *IPsecPolicySvc) Delete(ctx, profile, name string, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error)
```

Same shape for `VPNProfileSvc`.

Required fields per type (best-guess; verify at impl):
- `IPsecPolicy`: `Name`. Other fields default to Sophos defaults if omitted.
- `VPNProfile`: `Name`, `AuthenticationMode`. Other fields default.

Audit ops: `ipsec_policy_create / _update / _delete`, `vpn_profile_create / _update / _delete`.

`_diffHash` strip from body before XML marshal (Phase 14 fan-out fix pattern — body cloned to fresh map, `_diffHash` skipped). Inherits Phase 14 protection.

### 3.4 CLI tree

New top-level `vpn` parent under root:

```
vpn
├── ipsec                         (sub-parent for VPNIPsecConnection)
│   ├── list
│   ├── show <name>
│   ├── new <name> [--from <existing>]    (writes draft)
│   ├── pull <name>                       (writes draft + snapshot)
│   ├── diff <name>                       (snapshot vs draft, unified)
│   ├── push <name> [--expected-diff-hash <h>] [--ignore-hash] [--dry-run] [--yes] [--profile-set <s>]
│   └── delete <name> [--expected-diff-hash <h>] [--ignore-hash] [--dry-run] [--yes] [--profile-set <s>]
│
├── policy                        (sub-parent for IPsecPolicy)
│   ├── list
│   ├── show <name>
│   ├── create <name> --body @file [--dry-run] [--yes] [--profile-set <s>]
│   ├── update <name> --body @file [--expected-diff-hash <h>] [--ignore-hash] [--dry-run] [--yes] [--profile-set <s>]
│   └── delete <name> [--expected-diff-hash <h>] [--ignore-hash] [--dry-run] [--yes] [--profile-set <s>]
│
└── ike-profile                   (sub-parent for VPNProfile)
    ├── list
    ├── show <name>
    ├── create <name> --body @file [--dry-run] [--yes] [--profile-set <s>]
    ├── update <name> --body @file [--expected-diff-hash <h>] [--ignore-hash] [--dry-run] [--yes] [--profile-set <s>]
    └── delete <name> [--expected-diff-hash <h>] [--ignore-hash] [--dry-run] [--yes] [--profile-set <s>]
```

`--profile-set` flag inherited from Phase 14 — every mutating sub-command supports it via `AddProfileSetFlag`.

CLI body-source: `--body @path` / `--body -` / inline (per Phase 12's `LoadBody` helper).

Tree placement: `vpn` is a new top-level parent (sibling of `firewall`, `nat`, `host`, `service`, `object`, `auth`, `backup`, `drift`, `mcp`, `raw`).

### 3.5 MCP tools (15 new)

Mirror the CLI 1:1 (read-only `_list / _show` plus mutating tools per type):

| Tool | Type | Purpose |
|---|---|---|
| `vpn_ipsec_list` | read | List IPsec tunnels (matches `object_list` for VPNIPsecConnection but with first-class column metadata) |
| `vpn_ipsec_show` | read | Show one tunnel's body + injected `_diffHash` (mirror `firewall_rule_show`) |
| `vpn_ipsec_create` | mutating | Body-as-map create (no draft) |
| `vpn_ipsec_update` | mutating | Body-as-map update with expectedDiffHash gate |
| `vpn_ipsec_delete` | mutating | Delete with expectedDiffHash gate |
| `vpn_policy_list` | read | List IPsec policies |
| `vpn_policy_show` | read | Show one policy + `_diffHash` |
| `vpn_policy_create` | mutating | |
| `vpn_policy_update` | mutating | |
| `vpn_policy_delete` | mutating | |
| `vpn_ike_profile_list` | read | |
| `vpn_ike_profile_show` | read | |
| `vpn_ike_profile_create` | mutating | |
| `vpn_ike_profile_update` | mutating | |
| `vpn_ike_profile_delete` | mutating | |

Tool count: **52 → 67**.

Every mutating tool gains the `profileSet` field (Phase 14 fan-out pattern). One `confirm: true` covers the fleet.

CLI's `pull` / `diff` / `new` are NOT exposed as MCP tools — agents drive the body-as-map create/update path directly with `expectedDiffHash` from `_*_show`.

### 3.6 Draft / snapshot paths

Add `"vpn"` to `internal/draft/paths.go::validTags`:

```go
var validTags = []string{"firewall", "nat", "vpn"}  // existing + "vpn"
```

Existing `DraftPath`, `SnapshotPath`, `RotateSnapshots` work unchanged once the tag is allowlisted.

Existing slug + collision handling from Phase 7-8 applies.

### 3.7 Body validation

Per type, the Create/Update gate validates required fields (string-non-empty for required scalars):

```go
var requiredVPNIPsecFields    = []string{"Name", "Status", "ConnectionType"}
var requiredIPsecPolicyFields = []string{"Name"}
var requiredVPNProfileFields  = []string{"Name", "AuthenticationMode"}
```

Body Name must match the positional/argument name (sanity check + force-set). Mirrors firewall_rule.

Required field lists are best-guess; verify against the actual API at Task 1 implementation. Adjust before T2 if needed.

## 4. Data flow

Identical to Phase 7-9 firewall_rule for VPNIPsecConnection (draft workflow), and Phase 12 for the body-as-map types. No new patterns.

```
CLI: sophosfw vpn ipsec push my-tunnel --expected-diff-hash <h> --yes
  ↓
VPNIPsecSvc.Push: read draft → fetch live → compare hash → marshal → BuildSetEnvelope("update") → DoRaw → refetch → return result

CLI: sophosfw vpn policy create my-policy --body @body.yaml --yes
  ↓
IPsecPolicySvc.Create: required-field check → marshal → BuildSetEnvelope("add") → DoRaw → refetch → return ObjectMutationResult
```

## 5. Errors

No new sentinels. Reuses `sophos.ErrNotFound`, `sophos.ErrInvalidRequest`, `sophos.ErrReadOnlyViolation`, `svc.ErrDiffHashMismatch`.

## 6. Testing strategy

### Unit tests

Per type:

- VPNIPsecConnection (mirror `firewallrule_create_test.go` + `firewallrule_pull_test.go`): ~25 tests covering New (template + from-existing), Pull, Diff, Push, CreateInline, UpdateInline, Delete, plus required-field rejections, profile read-only, hash mismatches, body Name mismatch, `_diffHash` leak prevention (Phase 13.x lessons).
- IPsecPolicy: ~12 tests mirroring `iphostgroup_test.go`.
- VPNProfile: ~12 tests mirroring `iphostgroup_test.go`.
- CLI per type: ~3-5 smoke tests each (dry-run, body-name mismatch, fan-out smoke).
- MCP per type: 8 handler tests for VPNIPsecConnection's mutating handlers, 8 for IPsecPolicy, 8 for VPNProfile (mirror Phase 10/12 mutation_test.go layout).
- Catalog: `TestCatalog_Phase15NewlyMutable`.
- Draft path: extend `validTags` test to include `"vpn"`.

### Integration tests (build-tagged, against testvm)

**Read-only smokes** (always run if `SOPHOSFW_PROFILE` set):

```go
TestIntegration_VPNIPsec_List_ReturnsValidShape
TestIntegration_IPsecPolicy_List_ReturnsValidShape
TestIntegration_VPNProfile_List_ReturnsValidShape
TestIntegration_VPNIPsec_ObjectGet_InjectsDiffHash
```

**Dry-run mutating smokes** (always safe; no firewall state changed):

```go
TestIntegration_MCPVPNIPsecCreate_DryRun
TestIntegration_MCPIPsecPolicyCreate_DryRun
TestIntegration_MCPVPNProfileCreate_DryRun
```

**No live mutating tests.** The testvm is cloned-prod; we don't create or delete real VPN tunnels in CI. Live mutation testing is a manual smoke step (operator-driven) per section 6.3 below.

### Manual smoke (post-implementation, operator-driven)

Operator picks a non-production-critical VPN object on the testvm:

```bash
sophosfw vpn ipsec list
sophosfw vpn ipsec show <existing-tunnel-name> -o yaml > /tmp/tunnel.yaml

# New from existing
sophosfw vpn ipsec new test-tunnel --from <existing-tunnel-name>
ls drafts/vpn/

# Edit /Users/ipm/.config/sophosfw/profiles/testvm/drafts/vpn/test-tunnel.yaml manually
sophosfw vpn ipsec diff test-tunnel
sophosfw vpn ipsec push test-tunnel --dry-run

# (Don't actually apply unless the operator wants to)

# Cleanup
rm /Users/ipm/.config/sophosfw/profiles/testvm/drafts/vpn/test-tunnel.yaml
```

Same flow for `vpn policy` and `vpn ike-profile` create/update/delete with `--dry-run`.

## 7. Acceptance

- [ ] Catalog has 3 new entries with `mutable: true`; column metadata produces reasonable list output.
- [ ] svc layer: VPNIPsecSvc with full draft workflow + IPsecPolicySvc + VPNProfileSvc body-as-map. ~50 unit tests pass.
- [ ] CLI: `vpn ipsec list/show/new/pull/diff/push/delete`, `vpn policy list/show/create/update/delete`, `vpn ike-profile list/show/create/update/delete` — 17 sub-commands all show cobra help cleanly.
- [ ] MCP: 15 new tools registered; tool count 52 → 67. Every mutating tool has `profileSet` field.
- [ ] Drafts under `drafts/vpn/`, snapshots under `snapshots/vpn/`. `validTags` allowlist updated.
- [ ] All read-side integration tests PASS against testvm.
- [ ] All dry-run mutating integration tests PASS (no firewall state change).
- [ ] Manual smoke: `vpn ipsec new --from <existing>` produces an editable draft; `vpn ipsec diff` shows clean output; `vpn ipsec push --dry-run` produces a valid Set envelope.
- [ ] `docs/api-coverage.md` updated: 3 new VPN rows.
- [ ] `docs/roadmap.md`: Phase 15 marked complete.
- [ ] `v0.13.0` tagged + released; `brew upgrade sophosfw` reports 0.13.0.

## 8. Out of scope

- **Remote access VPN** — SSL VPN, IPsec remote, L2TP, PPTP. Each adds user/group/cert references. Defer to Phase 15.x or later.
- **Certificate management** — `Certificate`, `CertificateAuthority`. Inter-locks with VPN config (cert-based auth) but is its own object family. Defer.
- **Operational commands** — `vpn ipsec connect/disconnect/status`. Sophos XML API exposure of VPN runtime control is unverified; many lifecycle ops require web UI or different RPC. Defer.
- **VPN traffic selectors as first-class objects** — currently part of the IPsec connection body; if the API exposes them as separate addressable objects, they'd warrant their own type. Defer until the API surface is verified.
- **Connection failover / redundancy config** — multi-peer, primary/backup tunnels. May be expressible within the existing body shape; if not, defer.
- **Live mutating integration tests** — testvm is cloned-prod; we don't risk live tunnels in CI. Manual smoke only.

## 9. Risks

- **API may not support mutations on one or more types.** Sophos has historically restricted some VPN config to web UI. **Mitigation**: at Task 1 (catalog + API verification), run a Preview-only mutation test (`raw request --dry-run` or via `IPsecPolicySvc.Create` with `dryRun=true`) against each type. If the firewall returns "Operation could not be performed on Entity" (Sophos's standard "not supported" error), drop that type to read-only and document the gap. Spec scope adjusts before T2 begins.
- **Required-field guesses may be wrong.** The required-field lists are best-guess from Sophos 22.x docs. **Mitigation**: T2 implementation runs each Create against a known-incomplete body to learn what Sophos rejects; updates the lists. Cheap to fix.
- **Column metadata may not match API response shape.** `Status` / `ConnectionType` / `AuthenticationMode` field names are best-guess. **Mitigation**: T1 implementation verifies against actual `object list` responses; adjusts.
- **Body-Name leak protection.** Phase 13.x found `_diffHash` leaks from Pull → draft → Push for firewall_rule. Phase 15's VPNIPsecConnection follows the same pattern; the strip-on-pull and strip-on-marshal protections from `firewallrule_pull.go` must be replicated in `vpnipsec.go`. Tests must include the regression check.
- **Body-clone for parallel preflight (Phase 14 fan-out).** The body-as-map types (IPsecPolicy, VPNProfile) inherit the Phase 14 svc-layer body-clone pattern automatically — but the implementer must remember to use it (clone-and-skip in `mutate`). Phase 14 reviewed it; Phase 15 just follows the established template.
- **Draft template for VPNIPsecConnection.** The default template (when `vpn ipsec new` is called without `--from`) must be a "fail-safe" skeleton — Status: Disable, no peer references — to avoid the user accidentally pushing a half-configured tunnel that activates against a wrong peer.

## 10. Decision log

- **Q1 — Scope: site-to-site IPsec only (option A).** Three object types: VPNIPsecConnection, IPsecPolicy, VPNProfile. Remote access (B), read-only (C), and other middles deferred.
- **Q2 — CLI shape: full draft cycle for VPNIPsecConnection + body-as-map for the two profile types (option A).** Mirror Phase 7 firewall_rule + Phase 12 iphostgroup. Each type's pattern fits its complexity.
- **Q3 — Operational commands: config-only (option A).** No `vpn ipsec connect/disconnect/status` in v1. Operational control deferred.
- **Q4 — Defaults (all confirmed):** No typed parsers (untyped map[string]any throughout); MCP mirrors CLI 1:1 (15 new tools); catalog metadata with best-guess columns; drafts at `drafts/vpn/` and snapshots at `snapshots/vpn/`; integration tests dry-run only; release tag `v0.13.0`; risk fallback to read-only-per-type if Sophos rejects mutations.

## 11. References

- Sophos 22.x XML API VPN documentation (per-tag schemas)
- Existing draft cycle pattern: `internal/svc/firewallrule_pull.go`, `firewallrule_create.go` (Phases 7-9)
- Existing body-as-map mutating pattern: `internal/svc/iphostgroup.go` (Phase 12)
- Existing per-tag draft path: `internal/draft/paths.go::DraftPath` + `validTags`
- Diff hash strip protection: Phase 13.x findings — `firewallrule_pull.go` `parseAndValidateRuleBody`
- Body-clone parallel-preflight protection: Phase 14 T6 fix in svc-layer mutate helpers
- Phase 14 fan-out wiring pattern: `internal/cli/profileset.go` + `internal/mcp/profileset.go`
