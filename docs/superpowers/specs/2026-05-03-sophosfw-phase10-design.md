# sophosfw Phase 10 — MCP-native firewall + NAT rule mutating tools

**Status:** approved (2026-05-03)
**Predecessors:** Phase 7 (`v0.6.0-phase7`) — FirewallRule pull/diff/push/delete via cli. Phase 8 (`v0.7.0-phase8`) — NATRule via cli + per-tag draft layout. Phase 9 (`v0.8.0-phase9`) — `firewall rule new` and `nat rule new` cli surfaces. Phase 6 (`v0.5.0-phase6`) — IPHost mutating MCP tools (`host_ip_create/update/delete`) — the precedent shape.
**Successor:** TBD. Phase 10 closes out the original Phase 8 deferred list (MCP, create, NATRule). Future phases TBD per real usage.

## 1. Goal

Add MCP-native mutating tools for FirewallRule and NATRule, completing the agent-facing surface that earlier phases delivered to humans via cli. Mirrors the Phase 6 IPHost pattern: stateless MCP tools that take rule body + name + confirm + (for update/delete) expectedDiffHash; server-side validation, audit logging, dry-run support; no draft files involved.

This is the smallest possible Phase 10 scope. Per Q1: stateless MCP, 6 new tools (3 per rule type). Per Q2: single `body: object` arg per tool. Per Q3: existing `<rule>_show` tools modified to always include `_diffHash`.

## 2. In scope

- 6 new MCP tools:
  - `firewall_rule_create`, `firewall_rule_update`, `firewall_rule_delete`
  - `nat_rule_create`, `nat_rule_update`, `nat_rule_delete`
- 2 modified MCP tools:
  - `firewall_rule_show` always includes `_diffHash` in response.
  - `nat_rule_show` same.
- 4 new svc methods (2 per rule type):
  - `FirewallRuleSvc.CreateInline`, `FirewallRuleSvc.UpdateInline`
  - `NATRuleSvc.CreateInline`, `NATRuleSvc.UpdateInline`
- (Existing `Delete` methods reused as-is — they already accept rule name directly, no draft involved.)
- Tool count: 24 → 30.
- No new render envelopes — reuse `sophosfw.v1.firewallRulePush` / `sophosfw.v1.natRulePush` / `sophosfw.v1.preview`.
- No new audit operation tags — reuse the Phase 7-9 cli ops (`firewall_rule_create`, `firewall_rule_push`, `firewall_rule_delete`, NAT equivalents).

## 3. Out of scope (deferred / not planned)

- Filesystem-backed MCP draft model (mirroring cli pull/diff/push/delete). Per Q1 decision: stateless is the right shape for MCP.
- A separate `firewall_rule_pull` MCP tool. Per Q3: agents use modified `_show` instead.
- Renaming the existing `firewall_rule_push` audit tag to `_update` for clarity. Stable since Phase 7; not worth touching.
- Bulk operations.
- Cross-rule semantic validation.
- Generalizing the two rule services into a shared `RuleSvc` (rule-of-three; revisit if a third rule type appears).

## 4. MCP tool surface

### `firewall_rule_create`

```go
type FirewallRuleCreateInput struct {
    Profile string         `json:"profile,omitempty"`
    Name    string         `json:"name" jsonschema:"required" jsonschema_description:"the rule name"`
    Body    map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the full FirewallRule body as a JSON object. Required top-level keys: Name, Status, IPFamily, PolicyType. The Name in body must match the name argument. Use firewall_rule_show on an existing rule to learn the shape."`
    Confirm bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
    DryRun  bool           `json:"dryRun,omitempty"`
}
```

Tool registration (in `internal/mcp/firewallrule_mutation.go`):

```go
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
    Name:        "firewall_rule_create",
    Description: "Create a new FirewallRule. Requires confirm: true. Use dryRun: true to preview the envelope without sending. Returns sophosfw.v1.firewallRulePush on apply or sophosfw.v1.preview on dry-run. The body must include Name, Status, IPFamily, PolicyType plus a NetworkPolicy object.",
    Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create firewall rule"},
}, s.handleFirewallRuleCreate)
```

### `firewall_rule_update`

```go
type FirewallRuleUpdateInput struct {
    Profile                string         `json:"profile,omitempty"`
    Name                   string         `json:"name" jsonschema:"required"`
    Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys same as create."`
    ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior firewall_rule_show; required unless ignoreExpectedDiffHash=true"`
    IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty"`
    Confirm                bool           `json:"confirm" jsonschema:"required"`
    DryRun                 bool           `json:"dryRun,omitempty"`
}
```

### `firewall_rule_delete`

```go
type FirewallRuleDeleteInput struct {
    Profile                string `json:"profile,omitempty"`
    Name                   string `json:"name" jsonschema:"required"`
    ExpectedDiffHash       string `json:"expectedDiffHash,omitempty"`
    IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
    Confirm                bool   `json:"confirm" jsonschema:"required"`
    DryRun                 bool   `json:"dryRun,omitempty"`
}
```

Tool annotations: `ReadOnlyHint: false` for all three. Delete additionally has `DestructiveHint: ptrBool(true)` (matching Phase 6 `host_ip_delete`).

### NAT equivalents

`NATRuleCreateInput`, `NATRuleUpdateInput`, `NATRuleDeleteInput` are structurally identical to the firewall variants (just renamed). Tool descriptions reference NATRule shape: required keys are `Name`, `Status`, `IPFamily` (no PolicyType).

### Confirm + hash gates (all six)

Every mutating handler runs:

```go
if !in.Confirm {
    return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
}
```

`update` and `delete` add:

```go
if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
    return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
}
```

`create` and `update` defensively force `body["Name"] = in.Name` after a sanity-check that any pre-set `body["Name"]` matches the `name` arg (mismatch → ErrInvalidRequest).

## 5. Service-layer wrappers

Phase 7-9's existing `Push`/`Delete`/`New` methods are draft-driven (they read a draft file by path). MCP needs draft-less variants that take the body directly.

### `FirewallRuleSvc.CreateInline` (new)

```go
func (s *FirewallRuleSvc) CreateInline(ctx context.Context, profileName, ruleName string, body map[string]any, dryRun bool) (out *FirewallRulePushResult, err error)
```

Reuses helpers from Phase 7-9: `parseAndValidateFirewallRuleBody`, `marshalFirewallRule`, `sophos.BuildSetEnvelope("add", ...)`, `safety.RedactXML`, the deferred-audit pattern. On apply success, writes the FIRST snapshot under `snapshots/firewall/<slug>-<utc>.yaml` (so subsequent cli pull/diff workflows have a starting point) but does NOT write a draft (the caller never asked for one). Audit op `firewall_rule_create`.

### `FirewallRuleSvc.UpdateInline` (new)

```go
func (s *FirewallRuleSvc) UpdateInline(ctx context.Context, profileName, ruleName string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (out *FirewallRulePushResult, err error)
```

Same flow as `Push` for `operation: update`, minus the draft-read step. Diff-hash semantics identical: `expectedHash` checked against live state unless `ignoreHash`. Audit op `firewall_rule_push`.

### `FirewallRuleSvc.Delete` (reused as-is)

The existing `Delete(ctx, profile, ruleName, expectedHash, ignoreHash, dryRun)` from Phase 7 already takes the rule name directly — no draft involved. The MCP `firewall_rule_delete` handler calls it directly. No new method needed.

### NAT mirrors

`NATRuleSvc.CreateInline` and `UpdateInline` — same shape, NAT helpers (`marshalNATRule`, `extractNATReferences`, etc.). `NATRuleSvc.Delete` reused as-is. Audit ops `nat_rule_create` / `nat_rule_push` / `nat_rule_delete`.

## 6. Modified read tools

### `firewall_rule_show` and `nat_rule_show`

The existing handlers fetch the body and render the envelope. Phase 10 modifies them to compute `DiffHash(body)` and inject `_diffHash` at the top level of the rendered body — exact mirror of Phase 6's `host_ip_show` change.

Implementation: simplest path is to add a `_diffHash` key to the body map before rendering. Existing schema names (`sophosfw.v1.firewallRule`, `sophosfw.v1.natRule`) unchanged; `_diffHash` is just a new top-level field.

Tool descriptions get a small addendum: `"Response always includes _diffHash, which firewall_rule_update and firewall_rule_delete require as expectedDiffHash."`

## 7. Render envelopes (no new ones)

Reuse:
- `render.PreviewEnvelope` (Phase 6) for dry-run results.
- `render.FirewallRulePushEnvelope` (Phase 7) for apply results.
- `render.NATRulePushEnvelope` (Phase 8) for NAT apply results.

Phase 10 adds two small helper functions inside `internal/mcp/`:

```go
func renderMcpFirewallRuleMutation(r *svc.FirewallRulePushResult) ([]byte, error) {
    if r.DryRun {
        return render.PreviewEnvelope(r.Preview)
    }
    return render.FirewallRulePushEnvelope(r)
}

func renderMcpNATRuleMutation(r *svc.NATRulePushResult) ([]byte, error) {
    if r.DryRun {
        return render.PreviewEnvelope(r.Preview)
    }
    return render.NATRulePushEnvelope(r)
}
```

(Mirrors `renderMcpHostIpMutation` from Phase 6.)

## 8. Data flow

### create (firewall or NAT)

1. Handler receives input. Verify `Confirm == true`; if not, error envelope.
2. Verify body's Name matches name arg (or empty); force-set `body["Name"] = name`.
3. Call `s.<rule>RuleSvc().CreateInline(ctx, profile, name, body, dryRun)`.
4. Render via `renderMcp<Rule>RuleMutation(result)`.

`CreateInline` flow:

1. Resolve profile + build audit entry skeleton + defer.
2. Parse + required-field validation.
3. Read-only profile check.
4. Catalog Mutable check.
5. Marshal body to XML via `marshal<Rule>Rule`.
6. Build envelope: `sophos.BuildSetEnvelope("add", inner, c.Username, c.Password)`.
7. Audit RedactedXML set.
8. Dry-run path: emit Preview, audit "ok (dry-run)", return.
9. Apply path: send DoRaw. Audit on failure with kind. On success: refetch, write FIRST snapshot under `snapshots/<tag>/`, audit "ok".
10. Return PushResult with `Operation: "create"`, `NewDiffHash`, `Item`.

### update (firewall or NAT)

1. Handler verifies Confirm + ExpectedDiffHash gates.
2. Force-set `body["Name"] = name`.
3. Call `s.<rule>RuleSvc().UpdateInline(ctx, profile, name, body, expectedHash, ignoreHash, dryRun)`.
4. Render result.

`UpdateInline` flow: same as Push but with body passed in (skips draft read). Diff-hash check + envelope build + dry-run/apply identical. On apply success: archive snapshot, return.

### delete (firewall or NAT)

1. Handler verifies Confirm + ExpectedDiffHash gates.
2. Call existing `s.<rule>RuleSvc().Delete(ctx, profile, name, expectedHash, ignoreHash, dryRun)`.
3. Render result.

No svc-layer changes for delete.

### show (modified)

1. Existing flow: resolve profile, fetch body via `s.<rule>RuleSvc().Get(ctx, profile, name)`.
2. New step: compute `hash := DiffHash(body)`. Inject `body["_diffHash"] = hash`.
3. Render envelope unchanged.

## 9. Error handling

No new sentinels, no new exit codes. All errors flow through `errorEnvelopeResult`:

| Trigger | Sentinel | Kind |
|---|---|---|
| `confirm: false` on any mutating tool | `sophos.ErrInvalidRequest` | `invalid_request` |
| `expectedDiffHash` empty + `ignoreExpectedDiffHash: false` on update/delete | `sophos.ErrInvalidRequest` | `invalid_request` |
| body Name mismatches name arg | `sophos.ErrInvalidRequest` | `invalid_request` |
| Required field missing in body | `sophos.ErrInvalidRequest` | `invalid_request` |
| Read-only profile | `sophos.ErrReadOnlyViolation` | `read_only_violation` |
| Catalog Mutable=false | `sophos.ErrInvalidRequest` | `invalid_request` |
| Live hash ≠ expectedDiffHash on update | `ErrDiffHashMismatch` | `diff_hash_mismatch` |
| Live rule not found on update/delete | `sophos.ErrNotFound` | `not_found` |
| Sophos rejects envelope | passes through | varies |
| XML element name validation | `sophos.ErrInvalidRequest` | `invalid_request` |

The deferred-audit pattern from v0.6.1 catches all early-rejection paths automatically, since `CreateInline`/`UpdateInline` mirror the Phase 7-9 `Push`/`Delete` structure.

## 10. Audit log

**No new operation tags.** The audit operation names the firewall action, not the calling surface:

- `firewall_rule_create` (existing from Phase 9) — written by both cli `firewall rule push` (operation: create) AND MCP `firewall_rule_create`.
- `firewall_rule_push` (existing from Phase 7) — written by cli `firewall rule push` (operation: update) AND MCP `firewall_rule_update`.
- `firewall_rule_delete` (existing from Phase 7) — written by cli `firewall rule delete` AND MCP `firewall_rule_delete`.
- NAT equivalents (`nat_rule_create`, `nat_rule_push`, `nat_rule_delete`) reused.

Distinguishing cli-vs-MCP origin in the audit log is not Phase 10's problem; defer if it becomes a real audit need.

## 11. Testing strategy

### 11.1 Unit tests

- `internal/svc/firewallrule_create_test.go` — extend with 6 `TestFirewallRuleSvc_CreateInline_*` tests mirroring `New_*` but without the draft-write step.
- `internal/svc/firewallrule_pull_test.go` — extend with 6 `TestFirewallRuleSvc_UpdateInline_*` tests mirroring `Push_*`.
- `internal/svc/natrule_create_test.go` and `natrule_pull_test.go` — same for NAT.
- `internal/mcp/firewallrule_mutation_test.go` (new):
  - `TestFirewallRuleCreate_Handler_RequiresConfirm`
  - `TestFirewallRuleCreate_Handler_DryRun`
  - `TestFirewallRuleCreate_Handler_Apply`
  - `TestFirewallRuleUpdate_Handler_RequiresExpectedDiffHash`
  - `TestFirewallRuleUpdate_Handler_DryRun`
  - `TestFirewallRuleUpdate_Handler_Apply`
  - `TestFirewallRuleDelete_Handler_RequiresExpectedDiffHash`
  - `TestFirewallRuleDelete_Handler_DiffHashMatch_Applies`
- `internal/mcp/natrule_mutation_test.go` (new) — 8 mirror tests for NAT.
- `internal/mcp/firewallrule_test.go` (extend): assert `_diffHash` present in `firewall_rule_show` response.
- `internal/mcp/natrule_test.go` (extend): same for NAT.
- `internal/mcp/server_test.go` — update tool count assertion 24 → 30; add the 6 new names to the expected-name list.

### 11.2 Integration tests (build tag `integration`, against testvm)

- `TestIntegration_MCPFirewallRuleShow_HasDiffHash` — call show, assert `_diffHash` present.
- `TestIntegration_MCPFirewallRuleCreate_DryRun` — call MCP create with body, dryRun=true. Assert preview envelope, no firewall mutation.
- `TestIntegration_MCPFirewallRuleUpdate_DryRun` — show + capture diffHash + update with edited body + dryRun=true. Assert preview.
- Same trio for NAT.

No live-mutation integration tests — same conservative posture as Phase 7-9.

### 11.3 Manual smoke (final task)

1. Programmatic MCP call (or `sophosfw mcp serve` + a test client): `firewall_rule_show 'Block Countries'` → confirm `_diffHash` in response.
2. `firewall_rule_update` with the captured hash + a `LogTraffic` toggle, dryRun=true → confirm `<Set operation="update">` envelope.
3. `firewall_rule_create` with a body for a new test rule, dryRun=true → confirm `<Set operation="add">` envelope.
4. `firewall_rule_delete` with a stale hash → confirm `kind: diff_hash_mismatch` error envelope.
5. Audit log check: entries appear with `result: "ok (dry-run)"`.
6. Apply a real create then delete (cleanup): `firewall_rule_create --confirm true` (no dryRun) for a test rule, verify it appears in `firewall_rule_list`, then `firewall_rule_delete` with the right hash.
7. Same flow for NAT (with cleanup).

## 12. Acceptance criteria

- All unit tests pass.
- All integration tests pass against testvm.
- Manual smoke checklist passes end-to-end.
- `go fmt` / `go vet` / `go test -race` clean.
- Tool count: `TestServer_RegistersAllTools` asserts 30.
- New tag `v0.9.0-phase10`.

## 13. Conventions inherited from earlier phases

- No `Co-Authored-By` trailer on implementation commits.
- Single passing commit per task.
- Module path `github.com/iainmoffat/sophosfw`. Working directory `/Users/ipm/code/sophosfw`. Branch `main`.
- SDK alias `sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"`.
- `jsonschema_description` (NOT `jsonschema:"description=..."`) for tool input field docs.
- `ReadOnlyHint` is bare `bool`; `DestructiveHint` is `*bool` (use `ptrBool(true)`).
- v0.6.1 deferred-audit pattern (named return + defer) inherited automatically by mirroring existing svc structure.

## 14. Deferred to future phases

- MCP tool that exposes the cli's draft model (filesystem-backed pull/diff/push) for human-agent collaboration. Per Q1: not now.
- Renaming `firewall_rule_push` audit tag to `_update`. Stable since Phase 7; not worth touching.
- Generalizing `FirewallRuleSvc` and `NATRuleSvc` into a shared `RuleSvc`. Rule-of-three; revisit if a third rule type appears.
- Bulk operations (multi-rule transactions).
- Cross-rule semantic validation.
