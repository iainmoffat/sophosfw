# sophosfw Phase 8 — NATRule draft workflow

**Status:** approved (2026-05-02)
**Predecessors:** Phase 7 (`v0.6.0-phase7`, plus cleanup release `v0.6.1`) — FirewallRule pull/diff/push/delete + audit/draft/snapshot machinery.
**Successor:** Phase 9 (provisional) — `firewall rule new` and `nat rule new` create workflows. Phase 10 (provisional) — MCP-native rule mutating tools.

## 1. Goal

Extend the Phase 7 draft-edit pipeline (pull/diff/push/delete) to a second object type, `NATRule`, with no architectural changes. Validates that the Phase 7 design generalizes; pressure-tests `internal/draft/` and the audit/diff-hash/dry-run machinery against a structurally similar but distinct rule shape; ships an immediately-useful CLI surface for editing NAT rules.

This is deliberately the smallest possible Phase 8 scope. Per the Q1 decision: NATRule extension only; firewall rule create deferred to Phase 9; MCP exposure deferred to Phase 10. Each later phase gets its own brainstorm → spec → plan → implementation cycle.

## 2. In scope

- New CLI verbs under `nat rule`: `pull`, `diff`, `push`, `delete`. Same flag shapes as Phase 7's `firewall rule` equivalents.
- New `internal/svc/natrule_pull.go` containing `NATRuleSvc` (mirroring `FirewallRuleSvc`) plus `marshalNATRule` and `extractNATReferences` helpers.
- New `internal/cli/natrule_mutation.go` registering the four cobra subcommands on the existing `nat rule` subtree.
- Three new render envelopes: `sophosfw.v1.natRulePull`, `sophosfw.v1.natRuleDiff`, `sophosfw.v1.natRulePush`.
- Catalog change: flag `NATRule` as `mutable: true`.
- On-disk layout change: `internal/draft.DraftPath` and `SnapshotPath` (and the snapshot list/rotate helpers) gain a `tag` parameter that selects a per-tag subdirectory. New layout is `drafts/<tag>/<slug>.yaml` and `snapshots/<tag>/<slug>-<ts>.yaml`.
- One-time migration in `internal/draft.MigrateLegacyLayout` that moves any pre-Phase-8 flat-layout files into the `firewall/` subdirectory. Idempotent; runs at `nat rule` and `firewall rule` cli startup.
- Integration tests against the testvm (Pull + Push dry-run + migration verification — no live mutation).
- New audit-log operation tags: `nat_rule_pull`, `nat_rule_push`, `nat_rule_delete`.

## 3. Out of scope (deferred)

- Generalizing `FirewallRuleSvc` and `NATRuleSvc` into a shared `RuleSvc` abstraction. Per Q2: rule of three — duplicate now (we have two instances), generalize when a third rule type appears.
- `firewall rule new` / `nat rule new` create workflows (Phase 9).
- MCP-native firewall/NAT rule tools (Phase 10).
- VPN, IPSec, SSL-VPN, or other complex multi-section types.
- Cross-rule semantic validation (e.g., does `LinkedFirewallrule` actually exist?).
- Bulk operations (multi-rule transactions).

## 4. CLI surface

```
sophosfw nat rule pull <name>
sophosfw nat rule diff <name> [--json]
sophosfw nat rule push <name> [--yes] [--ignore-diff-hash] [--json]
sophosfw nat rule delete <name> --expected-diff-hash <hex> [--ignore-diff-hash] [--yes] [--json]
```

Flag shapes are identical to Phase 7's `firewall rule` equivalents. Default behavior: `pull` and `diff` are read-only/local; `push` and `delete` default to dry-run, `--yes` applies. Delete requires `--expected-diff-hash` unless `--ignore-diff-hash` is also set.

`pull` writes:
- `~/.config/sophosfw/profiles/<profile>/snapshots/nat/<slug>-<ISO8601-utc>.yaml` (immutable, `0600`)
- `~/.config/sophosfw/profiles/<profile>/drafts/nat/<slug>.yaml` (mutable, `0600`, overwrites prior draft)

Reference summary printed at pull time covers IPHosts (Original Source/Destination Networks, Translated Source/Destination), Services (Original Services, Translated Service), and Linked Firewall Rule.

Human-readable `pull` output (matching Phase 7's format):

```
Draft written: ~/.config/sophosfw/profiles/home/drafts/nat/dnat-to-http-proxy01.yaml
Snapshot:      ~/.config/sophosfw/profiles/home/snapshots/nat/dnat-to-http-proxy01-2026-05-02T15-30-00Z.yaml
Diff hash:     8b3bc27f...
References:
  IPHost:        #Port4, http-proxy01 - 192.168.1.19
  Service:       HTTPS
  FirewallRule:  None
```

## 5. On-disk layout and migration

```
~/.config/sophosfw/profiles/<profile>/
├── drafts/
│   ├── firewall/
│   │   └── <slug>.yaml          # FirewallRule drafts
│   └── nat/
│       └── <slug>.yaml          # NATRule drafts
└── snapshots/
    ├── firewall/
    │   └── <slug>-<ts>.yaml
    └── nat/
        └── <slug>-<ts>.yaml
```

**Slugging rules and collision logic** are unchanged from Phase 7 (lowercase ASCII alphanumerics + dashes, 6-char SHA-256 suffix on collision). Slugging is now per-tag scoped, so a FirewallRule named "X" and a NATRule named "X" land in distinct files (`drafts/firewall/x.yaml` vs `drafts/nat/x.yaml`).

**Path API change** (`internal/draft/paths.go`):

```go
func DraftPath(baseDir, profile, tag, ruleName string) (string, error)
func SnapshotPath(baseDir, profile, tag, ruleName string, t time.Time) (string, error)
func ListSnapshots(baseDir, profile, tag, ruleName string) ([]string, error)
func RotateSnapshots(baseDir, profile, tag, ruleName string, keep int) error
```

`tag` is the subdirectory name: `"firewall"` or `"nat"`. Validated against an allowlist (no path traversal possible). All existing callers in `firewallrule_pull.go` are updated to pass `"firewall"`.

**Migration** (`internal/draft/migrate.go`, new file):

```go
// MigrateLegacyLayout moves any pre-Phase-8 flat-directory draft and
// snapshot files into the new per-tag subdirectory layout. Idempotent:
// safe to call on every CLI invocation.
//
// Files at <profile>/drafts/<slug>.yaml are moved to
// <profile>/drafts/firewall/<slug>.yaml. Same for snapshots.
//
// Files in subdirectories (already-migrated state) are not touched.
// On collision (target path already exists), the legacy file is left
// in place rather than overwriting the migrated file.
func MigrateLegacyLayout(baseDir, profile string) error
```

Migration is invoked at the start of every `firewall rule` and `nat rule` command via a one-line call from the cli factory functions. Cost is one `os.ReadDir` per invocation when the layout is already current (cheap).

## 6. Draft file format

Unchanged from Phase 7. Header (profile, rule, pulledAt, diffHash) + `---` marker + canonical YAML body.

## 7. Components

### 7.1 `internal/svc/natrule_pull.go` (new)

```go
type NATRuleSvc struct {
    Inner   *ObjectSvc
    Audit   *AuditLog
    BaseDir string
    Now     func() time.Time
}

type NATRulePullResult struct {
    Profile      string
    Rule         string
    DraftPath    string
    SnapshotPath string
    DiffHash     string
    References   []ReferenceSummary
}

type NATRuleDiffResult struct {
    Profile        string
    Rule           string
    HasChanges     bool
    UnifiedDiff    string
    StructuredDiff []DiffEntry
}

type NATRulePushResult struct {
    Profile     string
    Rule        string
    Operation   string                 // "update" | "delete"
    DryRun      bool
    Preview     *Preview
    NewDiffHash string
    Item        map[string]any
}

func (s *NATRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*NATRulePullResult, error)
func (s *NATRuleSvc) Diff(ctx context.Context, profileName, ruleName string) (*NATRuleDiffResult, error)
func (s *NATRuleSvc) Push(ctx context.Context, profileName, ruleName string, ignoreHash, dryRun bool) (*NATRulePushResult, error)
func (s *NATRuleSvc) Delete(ctx context.Context, profileName, ruleName, expectedHash string, ignoreHash, dryRun bool) (*NATRulePushResult, error)
```

`ReferenceSummary` and `DiffEntry` are reused from `internal/svc/firewallrule_pull.go` (already exported; not redefined).

**Required-field validation** (cli-side, in `Push`):

```go
var requiredNATRuleFields = []string{"Name", "Status", "IPFamily"}
```

**Reference extraction:**

```go
func extractNATReferences(body map[string]any) []ReferenceSummary
```

Walks the rule body for the following reference-bearing fields, handling the single-or-list union shape (`{Network: "X"}` vs `{Network: ["X","Y"]}`):

| Field path | Reference type |
|---|---|
| `OriginalSourceNetworks.Network` | IPHost |
| `OriginalDestinationNetworks.Network` | IPHost |
| `TranslatedSource` (flat string) | IPHost (if not "Original") |
| `TranslatedDestination` (flat string) | IPHost (if not "Original") |
| `OriginalServices.Service` | Service |
| `TranslatedService` (flat string) | Service (if not "Original") |
| `LinkedFirewallrule` (flat string) | FirewallRule (if not "None") |
| `InboundInterfaces.Interface` (flat string or list) | Interface |

Sentinel values `"Original"` and `"None"` are filtered out (they're Sophos's way of saying "no translation" / "no link" — not actual references).

**XML marshaling** (`marshalNATRule`):

```go
func marshalNATRule(rule map[string]any) ([]byte, error) {
    var buf bytes.Buffer
    buf.WriteString("<NATRule>")
    if err := writeMapChildren(&buf, rule); err != nil {
        return nil, err
    }
    buf.WriteString("</NATRule>")
    return buf.Bytes(), nil
}
```

The lower-level `writeMapChildren`, `writeKeyValue`, `writeOpen`, `writeClose`, and `validateXMLName` helpers in `firewallrule_pull.go` are tag-agnostic and reused without modification.

**Push/Delete data flow** is structurally identical to Phase 7's `FirewallRuleSvc.Push`/`Delete`. Differences:
- XML wrapper tag: `<NATRule>` instead of `<FirewallRule>`.
- Required-field set: `requiredNATRuleFields`.
- Audit `objectType: "NATRule"`, `operation: "nat_rule_push"` / `"nat_rule_delete"` / `"nat_rule_pull"`.
- Path resolution passes `tag: "nat"`.

### 7.2 `internal/cli/natrule_mutation.go` (new)

Mirrors `firewallrule_mutation.go` structure. Functions:

```go
func natRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.NATRuleSvc
func newNATRulePullCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command
func newNATRuleDiffCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command
func newNATRulePushCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command
func newNATRuleDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command
```

The factory invokes `draft.MigrateLegacyLayout(d.BaseDir, profile)` once at the start (with the same call duplicated in `firewallRuleSvc` for symmetry).

`internal/cli/natrule.go` (existing — has `list` and `show` from Phase 3) is modified to register the four new subcommands.

### 7.3 `internal/render/envelope.go`

Three new functions:

```go
func NATRulePullEnvelope(r *svc.NATRulePullResult) ([]byte, error)
func NATRuleDiffEnvelope(r *svc.NATRuleDiffResult) ([]byte, error)
func NATRulePushEnvelope(r *svc.NATRulePushResult) ([]byte, error)
```

Schema names: `sophosfw.v1.natRulePull`, `sophosfw.v1.natRuleDiff`, `sophosfw.v1.natRulePush`. Payload shapes mirror the `firewallRule*` equivalents 1:1.

### 7.4 Catalog change

```yaml
- xmlTag: NATRule
  ...
  mutable: true
```

### 7.5 `internal/draft/migrate.go` (new)

```go
// MigrateLegacyLayout walks <baseDir>/profiles/<profile>/drafts/ and
// <baseDir>/profiles/<profile>/snapshots/ for *.yaml files at the top
// level (pre-Phase-8 flat layout) and moves them into the firewall/
// subdirectory. Idempotent: safe to call on every cli invocation. On
// collision (target path already exists), leaves the legacy file in
// place — no overwrite.
func MigrateLegacyLayout(baseDir, profile string) error
```

Implementation: ~30 LOC, stdlib-only (`os.ReadDir`, `os.Rename`, `os.Stat` for collision detection).

### 7.6 Path-API call sites updated

All existing callers in `internal/svc/firewallrule_pull.go` and tests are updated to pass `"firewall"` as the new `tag` parameter. No behavioral change after migration.

## 8. Data flow

Same as Phase 7 modulo the tag parameter and NAT-specific marshaling. Cross-references to Phase 7 spec sections 8.1–8.4. Differences summarized:

- **Pull**: passes `tag="nat"` to all `draft.*Path`/`*Snapshots` calls; calls `extractNATReferences` instead of `extractReferences`.
- **Diff**: passes `tag="nat"`; otherwise unchanged.
- **Push**: validates against `requiredNATRuleFields` (no `PolicyType`); calls `marshalNATRule`; audit operation `nat_rule_push`.
- **Delete**: builds `<Remove><NATRule><Name>X</Name></NATRule></Remove>` envelope (same XML escape pattern as Phase 7); audit operation `nat_rule_delete`.
- **Pre-flight rejection audit** (post-v0.6.1): inherits the deferred-write pattern from `firewallrule_pull.go`.

## 9. Error handling

No new sentinels, no new exit codes. Same error table as Phase 7 spec section 9 with `firewall_rule_*` operation tags replaced by `nat_rule_*` and `kind`/exit semantics unchanged. The `diff_hash_mismatch` user-facing message reads `"NAT rule <name> has changed on the firewall since you ran pull (have <new>, expected <old>); re-run \`sophosfw nat rule pull <name>\` to refresh, or pass --ignore-diff-hash to override"`.

## 10. Audit log

Three new operation tags: `nat_rule_pull`, `nat_rule_push`, `nat_rule_delete`. Same audit-entry shape as the firewall_rule_* equivalents. `defaults.auditLog: false` continues to suppress all audit writes.

## 11. Testing strategy

### 11.1 Unit tests

- `internal/draft/paths_test.go` — extend with `TestDraftPath_TagSubdir` and `TestSnapshotPath_TagSubdir`. Existing tests updated to pass `"firewall"`.
- `internal/draft/migrate_test.go` (new):
  - `TestMigrateLegacyLayout_NoOpWhenAlreadyMigrated`
  - `TestMigrateLegacyLayout_MovesFlatDraftsToFirewall`
  - `TestMigrateLegacyLayout_MovesSnapshotsToFirewall`
  - `TestMigrateLegacyLayout_SkipsCollisions`
  - `TestMigrateLegacyLayout_Idempotent`
- `internal/svc/natrule_pull_test.go` (new) — full mirror of `firewallrule_pull_test.go`. ~22 tests covering Pull/Diff/Push/Delete plus extras for `extractNATReferences` and `marshalNATRule`.
- `internal/svc/firewallrule_pull_test.go` — updated to pass `"firewall"` tag through; existing assertions unchanged.
- `internal/cli/natrule_mutation_test.go` (new) — mirror of `firewallrule_mutation_test.go`. 5 tests minimum.

### 11.2 Integration tests (build tag `integration`, against testvm)

- `TestIntegration_NATRulePull_RoundTrips` — pull a real NAT rule, assert files written under `nat/`, hash non-empty, reference summary populated.
- `TestIntegration_NATRulePush_DryRun` — pull → push without `--yes` → assert preview, no envelope sent.
- `TestIntegration_NATRuleMigration` — pre-create a legacy `drafts/<slug>.yaml` in a tempdir, run migration, assert it lands under `drafts/firewall/`.

No live-mutation integration test. Editing a real NAT rule on the cloned-prod VM is too disruptive even for testing — the unit-test suite covers the wire format end-to-end via fakes, the same conservative posture as Phase 7's delete tests.

### 11.3 Manual smoke (final task)

1. `sophosfw nat rule pull '<real-rule>' --profile testvm --json` — inspect both files, verify reference summary, confirm `nat/` subdir present.
2. `sophosfw nat rule diff '<real-rule>' --profile testvm` — confirm "no changes".
3. `sophosfw nat rule push '<real-rule>' --profile testvm --json` (dry-run) — confirm preview envelope with redacted XML.
4. `tail -10 ~/.config/sophosfw/audit.log` — confirm `nat_rule_pull` entries.
5. Confirm migration: existing FirewallRule drafts at `drafts/firewall/` (no longer flat). Re-run `firewall rule diff` on a previously-pulled rule to confirm it still works.

## 12. Acceptance criteria

- All unit tests pass.
- All integration tests pass against testvm.
- `make skill-doctor` returns `skill ok`.
- Manual smoke checklist passes end-to-end.
- `go fmt` / `go vet` / `go test -race` clean.
- One-time migration runs cleanly against a real Phase 7 user state.
- New tag `v0.7.0-phase8`.

## 13. Conventions inherited from earlier phases

- No `Co-Authored-By` trailer on implementation commits.
- Single passing commit per task.
- Module path `github.com/iainmoffat/sophosfw`. Working directory `/Users/ipm/code/sophosfw`. Branch `main`.
- Skill content in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` is updated separately (not committed in the sophosfw repo).
- Snapshot retention default 10 (config-overridable via `defaults.snapshotRetention`).
- Phase 6/7 pre-flight audit pattern (defer + named return) is automatically inherited by mirroring the FirewallRuleSvc structure.

## 14. Deferred to Phase 9 or later

- `firewall rule new` and `nat rule new` create workflows. Deferred because creating a rule from scratch is its own UX problem (templates? blank rule? what defaults? wizard mode?) that deserves a separate brainstorm.
- MCP-native firewall and NAT rule mutating tools (Phase 10).
- Generalizing `FirewallRuleSvc` and `NATRuleSvc` into a shared `RuleSvc` (rule-of-three; revisit when a third rule type appears).
