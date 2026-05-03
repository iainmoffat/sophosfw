# sophosfw Phase 9 — firewall rule + NAT rule create workflows

**Status:** approved (2026-05-02)
**Predecessors:** Phase 7 (`v0.6.0-phase7`) — FirewallRule pull/diff/push/delete. Phase 8 (`v0.7.0-phase8`) — NATRule extension with per-tag draft layout. Cleanup release `v0.6.1` — pre-flight audit pattern, `--insecure-skip-verify` wiring, Sophos stub-record fixes.
**Successor:** Phase 10 (provisional) — MCP-native rule mutating tools (firewall + NAT, including create).

## 1. Goal

Add `<rule> rule new <name>` to both `firewall rule` and `nat rule` cli surfaces, and extend the existing push pipeline to dispatch `<Set operation="add">` for create drafts. Validates that the Phase 7/8 draft-edit machinery generalizes to new-from-scratch workflows; ships an immediately-useful CLI surface for creating new rules.

This is the smallest possible Phase 9 scope. Both create flows ship together because the create pipeline shares >90% of its code with the existing update pipeline; bundling adds maybe 30% more code than firewall-only and saves a phase. The MCP-native exposure of mutating tools is deferred to Phase 10 as a third coherent piece.

## 2. In scope

- New CLI verbs:
  - `sophosfw firewall rule new <name> [--from <existing-rule>]`
  - `sophosfw nat rule new <name> [--from <existing-rule>]`
- New service methods on existing structs:
  - `FirewallRuleSvc.New(ctx, profile, ruleName, fromRule string)`
  - `NATRuleSvc.New(ctx, profile, ruleName, fromRule string)`
- New `Operation` field on `draft.Draft` with header parsing and validation.
- Push dispatch on `d.Operation` selecting `Set operation="add"` (create) vs `update` (existing path).
- Diff dispatch rejecting create drafts with a clear error message.
- Audit log entries for `<rule>_new` (cli local op) and `<rule>_create` (push apply op).
- Hardcoded minimal-valid rule templates per type (no configurability — YAGNI).
- Backward compatibility: existing Phase 7/8 drafts (no `operation` header) continue to work as `update` drafts.

## 3. Out of scope (deferred)

- MCP-native rule mutating tools (Phase 10).
- Configurable templates / template repositories.
- Bulk operations (creating multiple rules in one transaction).
- Cross-rule semantic validation (e.g., does the SourceZones reference a real Zone?).
- Rule reordering at create time (the user can edit `Position` later).

## 4. CLI surface

```
sophosfw firewall rule new <name> [--from <existing-rule>] [--json]
sophosfw nat rule new <name>      [--from <existing-rule>] [--json]
```

Flag shapes:

- `<name>` is positional and required. Slugged for the draft path.
- `--from <existing-rule>` (optional) — clone the existing rule's body into the new draft and rename `Name`.
- `--json` emits the same envelope schema as `pull` (`sophosfw.v1.firewallRulePull` / `sophosfw.v1.natRulePull`) since the result shape is identical (DraftPath, SnapshotPath, DiffHash, References). `SnapshotPath` is empty and `DiffHash` is empty for a fresh `new`.

`new` is non-mutating: it only writes a local file. No `--yes` flag; push is the gated step.

Conflict detection: if a draft already exists at the resolved DraftPath, `new` errors with `kind: invalid_request`. The user must explicitly delete the existing draft (or pull again with a different name).

Human-readable output:

```
Draft written: ~/.config/sophosfw/profiles/home/drafts/firewall/my-new-rule.yaml
Operation:     create
Snapshot:      (none — first push will create one)
Edit and run: sophosfw firewall rule push my-new-rule --yes
```

## 5. Draft file format change

The existing header gains one new key: `operation`. Allowed values: `create`, `update`. Missing or empty defaults to `update` (backward-compatible with Phase 7/8 drafts).

```yaml
# sophosfw firewall rule draft v1
# profile: home
# rule: My-New-Rule
# operation: create
# pulledAt: 2026-05-02T15:30:00Z
# diffHash: 
# DO NOT EDIT ABOVE THIS LINE — push reads this header to verify drift
---
Name: My-New-Rule
Status: Enable
IPFamily: IPv4
PolicyType: Network
NetworkPolicy:
  Action: Drop
  ...
```

**Validation rules** (parsed by `draft.ReadDraft`):

- `operation` is one of `create` / `update`. Any other value → `kind: invalid_request`.
- `(operation == "create")` requires `diffHash == ""`. Mixed → `kind: invalid_request`.
- `(operation == "update")` requires `diffHash` matches `^[a-f0-9]{64}$`. Empty hash on update → `kind: invalid_request`.
- A draft missing the `operation` line is treated as `update` (backward-compat with Phase 7/8 disk state).

**Header lifecycle on a create-then-edit flow:**

1. `firewall rule new my-rule` → header has `operation: create`, `diffHash: ` (empty), `pulledAt` = now.
2. User edits body locally.
3. `firewall rule push my-rule --yes` → push reads `operation: create`, sends `<Set operation="add">`, refetches, computes new diffHash, **rewrites the draft header** with `operation: update`, populates `diffHash`, updates `pulledAt`.
4. Future edits + pushes on this draft are now standard Phase 7/8 update flow.

**Snapshot semantics on create:**

- `new` writes JUST the draft (no snapshot — there's nothing to snapshot from yet).
- `push` apply path on a create draft: refetches, computes hash, writes the FIRST snapshot at `snapshots/<tag>/<slug>-<post-create-utc>.yaml`. `RotateSnapshots(keep: 10)` runs as in Phase 7/8.

## 6. CLI flow examples

### Create from scratch (template default):

```
$ sophosfw firewall rule new MyRule --profile testvm
Draft written: ~/.config/sophosfw/profiles/testvm/drafts/firewall/myrule.yaml
Operation:     create

$ vim ~/.config/sophosfw/profiles/testvm/drafts/firewall/myrule.yaml

$ sophosfw firewall rule push MyRule --profile testvm --json
# (dry-run preview shows <Set operation="add">)

$ sophosfw firewall rule push MyRule --profile testvm --yes
applied: MyRule (operation: create, newDiffHash: abc123...)
```

### Create from existing (clone-and-tweak):

```
$ sophosfw firewall rule new MyRule-v2 --from MyRule --profile testvm
Draft written: ~/.config/sophosfw/profiles/testvm/drafts/firewall/myrule-v2.yaml
Operation:     create

$ vim ...   # tweak the cloned body

$ sophosfw firewall rule push MyRule-v2 --profile testvm --yes
applied: MyRule-v2 (operation: create, newDiffHash: ...)
```

### Diff on a create draft (rejected):

```
$ sophosfw firewall rule diff MyRule --profile testvm
error (invalid_request): this is a draft for a new rule; no snapshot exists until first successful push
```

## 7. Components

### 7.1 `internal/draft/io.go` (modified)

```go
type Draft struct {
    Profile   string
    Rule      string
    Operation string  // NEW: "create" | "update". Empty defaults to "update" on read.
    PulledAt  time.Time
    DiffHash  string
    Body      []byte
}
```

`ReadDraft` parses `# operation:` line into `Operation`. If missing, defaults to `"update"`. `WriteDraft` emits `# operation: <value>` (writes whatever's in the field; empty becomes `update` via `if d.Operation == "" { d.Operation = "update" }` normalization at parse time).

Validation:

```go
if d.Operation != "" && d.Operation != "create" && d.Operation != "update" {
    return nil, fmt.Errorf("draft header operation invalid: must be 'create' or 'update', got %q", d.Operation)
}
if d.Operation == "create" && d.DiffHash != "" {
    return nil, fmt.Errorf("draft header inconsistency: operation=create requires empty diffHash")
}
if d.Operation == "" || d.Operation == "update" {
    if d.DiffHash == "" {
        return nil, fmt.Errorf("draft header missing diffHash (required for operation=update)")
    }
}
```

### 7.2 `internal/svc/firewallrule_create.go` (new)

```go
package svc

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

// New writes a new draft for ruleName. If fromRule is non-empty, the
// existing rule's body is pulled and used as the template; otherwise
// firewallRuleTemplate is used.
//
// Errors:
//   - draft already exists at target path → ErrInvalidRequest
//   - --from rule doesn't exist → ErrNotFound
//   - profile resolution / creds load failure → propagates
//
// Auditing: writes "firewall_rule_new" entry on success.
func (s *FirewallRuleSvc) New(ctx context.Context, profileName, ruleName, fromRule string) (*FirewallRuleNewResult, error)
```

Body construction:

- Template path: substring-replace `__NAME__` with `ruleName` (XML-escape for safety even though YAML permits most chars).
- `--from` path: `s.Get(ctx, profile, fromRule)` to fetch existing body. Set `body["Name"] = ruleName`. Drop `body["After"]` and `body["Before"]` keys (ordering metadata; new rule defaults to bottom of stack — user can re-set Position via subsequent edits).
- Marshal canonical YAML.
- Resolve `draft.DraftPath(s.BaseDir, name, "firewall", ruleName)`. `os.Stat` the path; if exists → return `kind: invalid_request` early (no audit-write needed; this is a pre-create check).
- Build the `Draft` with `Operation: "create"`, `DiffHash: ""`, `PulledAt: s.now()`.
- `draft.WriteDraft`. (Don't write a snapshot — there's no live state to snapshot from.)
- Audit `firewall_rule_new` with `result: ok`.
- Return `FirewallRuleNewResult` with the paths and reference summary (`extractReferences(parsedBody)`).

### 7.3 `internal/svc/natrule_create.go` (new)

```go
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

type NATRuleNewResult = NATRulePullResult

func (s *NATRuleSvc) New(ctx context.Context, profileName, ruleName, fromRule string) (*NATRuleNewResult, error)
```

Same logic as `FirewallRuleSvc.New` with NAT-specific template + tag `"nat"` + audit op `nat_rule_new` + `extractNATReferences` for the summary.

### 7.4 Push dispatch (modified — both rule types)

In `internal/svc/firewallrule_pull.go` `Push` and `internal/svc/natrule_pull.go` `Push`, after reading the draft:

```go
operation := d.Operation
if operation == "" {
    operation = "update"
}

switch operation {
case "update":
    // existing Phase 7/8 flow: validate diffHash, refetch, compare, build "update" envelope.
case "create":
    // skip diffHash check (no live state).
    // (still apply read-only-profile check + catalog Mutable check.)
    // build "add" envelope: sophos.BuildSetEnvelope("add", inner, c.Username, c.Password)
    // audit operation tag: "firewall_rule_create" (or "nat_rule_create")
default:
    return nil, fmt.Errorf("%w: invalid header operation %q", sophos.ErrInvalidRequest, operation)
}
```

After successful create apply:

```go
// Refetch new state, write first snapshot, flip header to update mode.
refetched, _ := s.Get(ctx, profileName, ruleName)
newHash, _ := DiffHash(refetched)
now := s.now()

snapPath, _ := draft.SnapshotPath(s.BaseDir, name, "firewall", ruleName, now)
yamlBytes, _ := marshalCanonicalYAML(refetched)
_ = draft.WriteDraft(snapPath, &draft.Draft{
    Profile: name, Rule: ruleName, Operation: "update", PulledAt: now,
    DiffHash: newHash, Body: yamlBytes,
})
_ = draft.RotateSnapshots(s.BaseDir, name, "firewall", ruleName, 10)

// Flip the working draft to update mode.
d.Operation = "update"
d.DiffHash = newHash
d.PulledAt = now
_ = draft.WriteDraft(draftPath, d)
```

The existing apply-success archive flow (snapshot, rotate, header update) for `update` operations is unchanged.

`FirewallRulePushResult.Operation` reflects the actual op tag (`"create"` or `"update"`) so cli/audit/render see the right value.

### 7.5 Diff dispatch (modified — both rule types)

`Diff` reads the draft. If `d.Operation == "create"`:

```go
return nil, fmt.Errorf("%w: this is a draft for a new rule; no snapshot exists until first successful push", sophos.ErrInvalidRequest)
```

Otherwise, existing Phase 7/8 flow.

### 7.6 CLI subcommands (new)

`internal/cli/firewallrule_mutation.go` and `internal/cli/natrule_mutation.go` each gain a `newFirewallRuleNewCmd` / `newNATRuleNewCmd` function:

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
            fmt.Fprintf(cmd.OutOrStdout(), "Draft written: %s\nOperation:     create\nSnapshot:      (none — first push will create one)\nEdit and run: sophosfw firewall rule push %s --yes\n",
                result.DraftPath, args[0])
            return nil
        },
    }
    c.Flags().StringVar(&fromRule, "from", "", "clone an existing rule's body as the starting template")
    return c
}
```

NAT version is parallel. Both register into existing `<rule> rule` subtrees.

### 7.7 Catalog and render envelopes

No catalog changes (Phase 7/8 already flagged FirewallRule and NATRule mutable). No new render envelopes — `New` returns the same shape as `Pull`, so `FirewallRulePullEnvelope` and `NATRulePullEnvelope` are reused.

## 8. Data flow

### 8.1 New (template path)

1. Resolve active profile.
2. Compose body from `firewallRuleTemplate` (or `natRuleTemplate`), substituting `ruleName` for `__NAME__`.
3. Parse to `map[string]any`.
4. Marshal canonical YAML.
5. Resolve `draft.DraftPath(baseDir, profile, "firewall", ruleName)`. Stat-check; if exists → ErrInvalidRequest.
6. Build `Draft{Operation: "create", DiffHash: "", PulledAt: now, Body: yamlBytes}`.
7. `draft.WriteDraft`.
8. Audit `firewall_rule_new` with result: ok.
9. Return result with paths and reference summary.

### 8.2 New (--from existing)

Same as 8.1, but step 2 is replaced:

2a. `s.Get(ctx, profile, fromRule)` → live body. Not found → ErrNotFound.
2b. `body["Name"] = ruleName`. Delete `body["After"]` and `body["Before"]`.
2c. Continue from step 4 (marshal, write, audit).

### 8.3 Push (modified, with create branch)

1. Resolve profile + build audit entry skeleton + defer.
2. Read draft via `draft.DraftPath(tag)`.
3. Header sanity (rule, profile match cli args).
4. Parse + required-field validation.
5. Read-only profile + Catalog Mutable checks.
6. **Branch on `d.Operation`:**
   - `update` (or empty): existing Phase 7/8 flow. `BuildSetEnvelope("update", ...)`. Diff-hash check. Audit op tag `<rule>_push`.
   - `create`: skip diff-hash check. `BuildSetEnvelope("add", ...)`. Audit op tag `<rule>_create`.
7. Audit RedactedXML set after envelope built.
8. Dry-run path: emit Preview, audit "ok (dry-run)", return.
9. Apply path: `cl.DoRaw`. On error: audit "error:<kind>". On success: audit "ok".
10. **Post-apply (apply only):** refetch, write snapshot, rotate.
    - For `create`: also flip draft header to `Operation: update` with the new hash.
    - For `update`: just update the draft header's `DiffHash` (existing behavior).
11. Return result with `Operation: "create"` or `"update"` to match the dispatch.

### 8.4 Diff (modified, with create rejection)

1. Resolve profile.
2. Read draft via `draft.DraftPath(tag)`.
3. **If `d.Operation == "create"`:** return ErrInvalidRequest with the friendly message.
4. Otherwise: existing Phase 7/8 flow (find matching snapshot, compute unified + structured diff).

## 9. Error handling

No new sentinels, no new exit codes.

| Trigger | Sentinel | Kind | Exit |
|---|---|---|---|
| Draft already exists at target path on `new` | `sophos.ErrInvalidRequest` | `invalid_request` | 6 |
| `--from <existing>` rule not found | `sophos.ErrNotFound` | `not_found` | 1 |
| Header `operation` is unknown value | `sophos.ErrInvalidRequest` | `invalid_request` | 6 |
| Header inconsistency (create+hash, or update+empty hash) | `sophos.ErrInvalidRequest` | `invalid_request` | 6 |
| `diff` on a create draft | `sophos.ErrInvalidRequest` | `invalid_request` | 6 |
| Required field missing | `sophos.ErrInvalidRequest` | `invalid_request` | 6 |
| Read-only profile on push | `sophos.ErrReadOnlyViolation` | `read_only_violation` | 4 |
| Catalog `Mutable: false` on push | `sophos.ErrInvalidRequest` | `invalid_request` | 6 |
| Sophos rejects the create envelope (e.g., name collision) | passes through | varies | 1/2/3 |
| XML element name validation (malicious key in body) | `sophos.ErrInvalidRequest` | `invalid_request` | 6 |

The collision case (a rule with this name already exists when push tries `Set operation="add"`) is caught by Sophos. We don't pre-check by reading; that would be a TOCTOU race.

## 10. Audit log

New operation tags on top of Phase 7/8's:

- `firewall_rule_new` — written by `firewall rule new`. Result always `ok` (local-only). RedactedXML empty (no envelope built).
- `firewall_rule_create` — written by `push` when `operation: create`. Same shape as `firewall_rule_push` (RedactedXML, ExpectedDiffHash="" since none required, Result).
- `nat_rule_new` — same shape, NAT.
- `nat_rule_create` — same.

Pre-flight rejection paths inherit the v0.6.1 deferred-audit pattern: any path that returns an error after the audit-entry skeleton is built fires the deferred write with `result: "error:<kind>"`. Specifically: `New` with an existing draft writes a `*_new` audit entry with `result: "error:invalid_request"`; push on a malformed header writes a `*_push` (or `*_create`) audit entry with the rejection reason.

## 11. Testing strategy

### 11.1 Unit tests

- `internal/draft/io_test.go`:
  - `TestReadDraft_OperationHeader_Create`
  - `TestReadDraft_OperationHeader_Update`
  - `TestReadDraft_OperationHeader_DefaultsToUpdate` (backward-compat)
  - `TestReadDraft_OperationHeader_RejectsUnknown`
  - `TestReadDraft_RejectsCreateWithDiffHash`
  - `TestReadDraft_RejectsUpdateWithEmptyDiffHash`
  - `TestWriteDraft_RoundTripsOperation`

- `internal/svc/firewallrule_create_test.go` (new):
  - `TestFirewallRuleSvc_New_FromTemplate`
  - `TestFirewallRuleSvc_New_FromExisting`
  - `TestFirewallRuleSvc_New_FromExisting_DropsAfterBefore`
  - `TestFirewallRuleSvc_New_RejectsExistingDraft`
  - `TestFirewallRuleSvc_New_FromExistingNotFound`
  - `TestFirewallRuleSvc_New_AuditLogged`

- `internal/svc/firewallrule_pull_test.go` extensions:
  - `TestFirewallRuleSvc_Push_CreateOperation_SendsAdd`
  - `TestFirewallRuleSvc_Push_CreateOperation_SkipsDiffHashCheck`
  - `TestFirewallRuleSvc_Push_CreateOperation_FlipsDraftHeader`
  - `TestFirewallRuleSvc_Push_CreateOperation_WritesFirstSnapshot`
  - `TestFirewallRuleSvc_Diff_CreateDraft_Errors`
  - `TestFirewallRuleSvc_Push_RejectsHeaderInconsistency` (mock a manually-corrupted draft)

- `internal/svc/natrule_create_test.go` (new) — full mirror of firewallrule_create_test.go.
- `internal/svc/natrule_pull_test.go` extensions — mirror of firewallrule_pull_test.go's create extensions.

- `internal/cli/firewallrule_mutation_test.go` extensions:
  - `TestFwRule_New_WritesDraft_Json`
  - `TestFwRule_New_FromExisting_CopiesBody`
  - `TestFwRule_New_RejectsExistingDraft`
- `internal/cli/natrule_mutation_test.go` extensions — same trio for `nat rule new`.

### 11.2 Integration tests (build tag `integration`, against testvm)

- `TestIntegration_FirewallRuleNew_FromTemplate_DryRun` — `New` writes a draft locally; immediately `Push` with dryRun=true. Assert preview envelope with `<Set operation="add">`. No firewall mutation. `t.Cleanup` removes the draft file.
- `TestIntegration_NATRuleNew_FromTemplate_DryRun` — same for NAT.
- **No live-create round-trip integration test** — even on a cloned-prod VM, creating a brand-new live rule risks misconfiguration if cleanup doesn't run. Manual smoke covers that path with explicit revert.

### 11.3 Manual smoke (final task)

1. `sophosfw firewall rule new sophosfw-smoke-test --profile testvm` → confirm draft at `drafts/firewall/sophosfw-smoke-test.yaml` with `operation: create` header.
2. Edit the body (tweak Action, src/dst zones to something safe).
3. `sophosfw firewall rule push sophosfw-smoke-test --profile testvm --json` (dry-run) → confirm `<Set operation="add">` in the redacted envelope.
4. `sophosfw firewall rule push sophosfw-smoke-test --profile testvm --yes` → applies; confirm draft header now has `operation: update` and a populated `diffHash`.
5. Verify `firewall rule list` shows the new rule.
6. `sophosfw firewall rule pull <some-existing-rule> --profile testvm` to capture; then `sophosfw firewall rule new sophosfw-smoke-test-2 --from <some-existing-rule> --profile testvm`. Confirm body matches with `Name` overwritten.
7. **Cleanup**: capture the diffHash for both new rules via `firewall rule show`, then `firewall rule delete <name> --expected-diff-hash <hex> --yes` for each. Verify they're gone via `list`.
8. `tail -10 ~/.config/sophosfw/audit.log` → confirm `firewall_rule_new` and `firewall_rule_create` entries.
9. Repeat steps 1–7 for `nat rule new`. Pick a no-op safe NAT rule (e.g., a DNAT that points at an unreachable IP so it can't accidentally activate).

## 12. Acceptance criteria

- All unit tests pass.
- All integration tests pass against testvm.
- Manual smoke checklist passes end-to-end.
- `go fmt` / `go vet` / `go test -race` clean.
- Backward compat: a Phase 8 disk state (drafts at `drafts/firewall/<slug>.yaml` with no `operation` header) still works after upgrade.
- New tag `v0.8.0-phase9`.

## 13. Conventions inherited from earlier phases

- No `Co-Authored-By` trailer on implementation commits.
- Single passing commit per task.
- Module path `github.com/iainmoffat/sophosfw`. Working directory `/Users/ipm/code/sophosfw`. Branch `main`.
- Snapshot retention default 10.
- v0.6.1 deferred-audit pattern (named return + defer) inherited automatically by mirroring existing structure.
- XML element name validation (`validateXMLName`) reused via `writeMapChildren` for both create and update marshaling.

## 14. Deferred to Phase 10 or later

- MCP-native firewall and NAT rule mutating tools (the third coherent piece of the original Phase 8 deferred list).
- Configurable templates / template repositories.
- Cross-rule semantic validation.
- Generalizing `FirewallRuleSvc` and `NATRuleSvc` into a shared `RuleSvc` (rule-of-three; revisit when a third rule type appears).
