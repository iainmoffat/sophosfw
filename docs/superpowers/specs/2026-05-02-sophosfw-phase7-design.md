# sophosfw Phase 7 — firewall rule draft workflow

**Status:** approved (2026-05-02)
**Predecessors:** Phase 6 (`v0.5.0-phase6`) — IPHost mutations, audit log, diff hash, catalog `Mutable` field.
**Successor:** Phase 8 (provisional) — MCP-native firewall rule tools + create-rule workflow + extension to NATRule.

## 1. Goal

Ship a complete pull/edit/push lifecycle for `FirewallRule` objects. The Phase 6 single-record pattern (flag-based create/update/delete on a flat struct) does not extend to firewall rules: rules are multi-section nested objects with embedded references to networks, services, schedules, identity groups, etc. They are routinely edited, and every edit needs to be auditable, drift-aware, and dry-runnable.

Phase 7 introduces a CLI workflow built around YAML draft files and immutable snapshots, with the same safety gates Phase 6 established (read-only profile rejection, catalog `Mutable` check, diff hash, audit log, dry-run default).

## 2. In scope

- CLI verbs: `firewall rule pull`, `firewall rule diff`, `firewall rule push`, `firewall rule delete`.
- On-disk draft + snapshot store under `~/.config/sophosfw/profiles/<profile>/{drafts,snapshots}/`.
- Draft format: round-trip 1:1 with `catalog.FirewallRule` plus a header comment block carrying metadata (profile, rule, pulledAt, diffHash).
- Snapshot retention (default 10 per rule, configurable).
- Required-field validation on push (parsed body must have non-empty `Name`, `Status`, `IPFamily`, `PolicyType`). Field-level validation deferred to the firewall.
- Catalog change: flag `FirewallRule` as `Mutable: true`.
- Three new render envelopes: `sophosfw.v1.firewallRulePull`, `sophosfw.v1.firewallRuleDiff`, `sophosfw.v1.firewallRulePush`.
- Two new error sentinels: `ErrDraftMissing`, `ErrSnapshotMissing`.
- Audit log entries: `firewall_rule_pull`, `firewall_rule_push`, `firewall_rule_delete`.
- Integration tests against the cloned-prod testvm, including a real round-trip write that reverts at the end.

## 3. Out of scope (deferred to later phases)

- MCP tools for the firewall rule workflow (Phase 8).
- Creating new rules from scratch (a separate UX problem — what's a "blank rule," what defaults, what template). Phase 7 only edits and deletes existing rules.
- NATRule, VPN, IPSec, or other complex multi-section types.
- Bulk operations (multi-rule pull/push transactions).
- Deep / transitive hash detection (changes to referenced IPHosts/Services do not trigger drift).

## 4. CLI surface

Three verbs plus `delete`. Mutating verbs (`push`, `delete`) default to dry-run; `--yes` applies. `pull` and `diff` are non-mutating (`pull` reads from the firewall; `diff` is local-only). Matches the Phase 6 ergonomic pattern.

```
sophosfw firewall rule pull <name>
sophosfw firewall rule diff <name> [--json]
sophosfw firewall rule push <name> [--yes] [--ignore-diff-hash] [--json]
sophosfw firewall rule delete <name> --expected-diff-hash <hex> [--ignore-diff-hash] [--yes] [--json]
```

`pull` writes:
- `~/.config/sophosfw/profiles/<profile>/snapshots/<slug>-<ISO8601-utc>.yaml` (immutable, `0600`)
- `~/.config/sophosfw/profiles/<profile>/drafts/<slug>.yaml` (mutable, `0600`, overwrites prior draft)

Both directories are `0700`.

`pull`'s human-readable output prints the draft path plus a summary of referenced objects:

```
Draft written: ~/.config/sophosfw/profiles/home/drafts/wan-to-lan.yaml
Snapshot:      ~/.config/sophosfw/profiles/home/snapshots/wan-to-lan-2026-05-02T15-30-00Z.yaml
Diff hash:     8b3bc27f...
References:
  IPHost:     LAN-network, WAN-network
  Services:   HTTP, HTTPS
  Zones:      LAN, WAN
```

`pull --json` emits `sophosfw.v1.firewallRulePull` with the same data structured.

`diff` reads the draft and finds the snapshot whose `diffHash` matches the draft's header `diffHash`. With no flag, emits a unified text diff. `--json` emits `sophosfw.v1.firewallRuleDiff` with a structured `diffEntries` array.

`push` validates → checks drift → builds envelope → dry-runs or applies → audit-logs.

`delete` mirrors `host ip delete` from Phase 6: positional name, required `--expected-diff-hash`, `--ignore-diff-hash` override, dry-run default, `--yes` to apply.

## 5. On-disk layout and slugging

```
~/.config/sophosfw/profiles/<profile>/
├── drafts/
│   └── <slug>.yaml
└── snapshots/
    └── <slug>-<timestamp>.yaml
```

**Slug derivation:**

1. Lowercase the rule name.
2. Replace any character that is not ASCII `[a-z0-9-]` with `-`.
3. Collapse runs of `-` into a single `-`.
4. Trim leading and trailing `-`.
5. If the result is empty (e.g., a rule name made entirely of unicode), use `rule` as a placeholder before the collision suffix.

**Examples:**

| Rule name | Slug |
|---|---|
| `WAN-to-LAN` | `wan-to-lan` |
| `My Rule (test)` | `my-rule-test` |
| `Allow / SSH` | `allow-ssh` |
| `🔥 Hot Rule` | `rule-<hash>` (after collision logic if needed) |

**Collision resolution:**
At write-time, if the slug already exists for a *different* original rule name (read existing draft header's `rule:`), append `-<6-char-suffix>` where suffix = first 6 hex chars of `SHA-256(originalName)`. Persist the suffix into the slug so subsequent operations on that rule resolve to the same path.

`internal/draft.DraftPath(baseDir, profile, ruleName)` is the single resolution entry point; nothing else constructs paths.

**Permissions:** `drafts/` and `snapshots/` directories are created `0700`; files written `0600`. Same convention as the existing `creds` store.

## 6. Draft file format

Two regions separated by a YAML document marker. The header is `#`-comment metadata; the body is the editable rule.

```yaml
# sophosfw firewall rule draft v1
# profile: home
# rule: WAN-to-LAN
# pulledAt: 2026-05-02T15:30:00Z
# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50
# DO NOT EDIT ABOVE THIS LINE — push reads this header to verify drift
---
Name: WAN-to-LAN
Status: Enable
PolicyType: Network
IPFamily: IPv4
Action: Accept
SourceZones:
  - LAN
DestinationZones:
  - WAN
SourceNetworks:
  - LAN-network
DestinationNetworks:
  - Any
Services:
  - HTTP
  - HTTPS
LogTraffic: Enable
Description: ""
```

**Parsing rules:**

- Lines from start-of-file to the first line that is exactly `---` are the header. Each header line must match `^# (\w+): (.*)$` or be the literal `# DO NOT EDIT ABOVE THIS LINE — push reads this header to verify drift` line. Other comment shapes are ignored.
- Required header keys: `profile`, `rule`, `pulledAt`, `diffHash`. Missing → `kind: invalid_request`.
- `pulledAt` parses as RFC 3339; `diffHash` matches `^[a-f0-9]{64}$`.
- The body is everything after the first `---`. Parsed via `yaml.Unmarshal` into `map[string]any`. Sophos `FirewallRule` shape varies by `PolicyType` (Network, User, HTTPBased, etc.) and includes single-or-list union fields (`SourceNetworks` may carry one or many `Network` children); a typed Go struct is deferred to a future phase. Required-field validation: the parsed body must contain non-empty `Name`, `Status`, `IPFamily`, and `PolicyType` keys at the top level. Field-by-field validation is the firewall's job.
- Header `rule:` must equal the positional `<name>` argument supplied to `push`/`diff`/`delete`. Mismatch → `kind: invalid_request`.
- Header `profile:` must equal the resolved active profile. Mismatch → `kind: invalid_request`.

**Snapshot file format:** identical shape (header + body). The snapshot's body is the canonical pulled state with no edits, so a `diff snapshot draft` is meaningful.

**On push success:** the firewall's response is written into a new snapshot under `snapshots/<slug>-<new-utc-timestamp>.yaml` with the new diffHash in its header. The old draft remains in place but its `diffHash` header is rewritten to the new hash so the next push validates against the post-push state.

## 7. Components

### 7.1 New package: `internal/draft/`

Owns on-disk format and slug rules. Keeps `internal/svc/` agnostic of filesystem layout.

```go
package draft

type Draft struct {
    Profile  string
    Rule     string    // original rule name (not slug)
    PulledAt time.Time
    DiffHash string
    Body     []byte    // YAML below the --- marker
}

func Slug(ruleName string) string
func DraftPath(baseDir, profile, ruleName string) (string, error)         // resolves slug + collisions
func SnapshotPath(baseDir, profile, ruleName string, t time.Time) (string, error)
func ReadDraft(path string) (*Draft, error)
func WriteDraft(path string, d *Draft) error                              // 0600
func ListSnapshots(baseDir, profile, ruleName string) ([]string, error)   // sorted oldest→newest
func RotateSnapshots(baseDir, profile, ruleName string, keep int) error
```

### 7.2 `internal/svc/firewallrule.go`

```go
type FirewallRuleSvc struct {
    Inner   *ObjectSvc       // for Get
    Audit   *AuditLog
    BaseDir string           // where drafts/ + snapshots/ live
    Now     func() time.Time // injectable for tests
}

type ReferenceSummary struct {
    Type  string   // IPHost | Services | Zone | Schedule | IdentityGroup | ...
    Names []string
}

type FirewallRulePullResult struct {
    Profile      string
    Rule         string
    DraftPath    string
    SnapshotPath string
    DiffHash     string
    References   []ReferenceSummary
}

type DiffEntry struct {
    Path     string // dotted path into the YAML tree
    Op       string // added | removed | changed
    OldValue any
    NewValue any
}

type FirewallRuleDiffResult struct {
    Profile        string
    Rule           string
    HasChanges     bool
    UnifiedDiff    string       // for text mode
    StructuredDiff []DiffEntry  // for --json
}

type FirewallRulePushResult struct {
    Profile     string
    Rule        string
    Operation   string                 // "update" | "delete"
    DryRun      bool
    Preview     *Preview                // dry-run only
    NewDiffHash string                  // apply only
    Item        map[string]any          // apply only — the refetched rule body
}

func (s *FirewallRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*FirewallRulePullResult, error)
func (s *FirewallRuleSvc) Diff(ctx context.Context, profileName, ruleName string) (*FirewallRuleDiffResult, error)
func (s *FirewallRuleSvc) Push(ctx context.Context, profileName, ruleName string, ignoreHash, dryRun bool) (*FirewallRulePushResult, error)
func (s *FirewallRuleSvc) Delete(ctx context.Context, profileName, ruleName, expectedHash string, ignoreHash, dryRun bool) (*FirewallRulePushResult, error)
```

### 7.3 cli wiring

- Append four subcommands to `internal/cli/firewallrule.go` (which already hosts `list`/`show`).
- `internal/cli/root.go`'s `RootDeps` already carries `Audit` and `BaseDir`; no new deps needed.
- `cmd/sophosfw/main.go` requires no changes.

### 7.4 `internal/render/envelope.go`

Three new functions:

```go
func FirewallRulePullEnvelope(r *svc.FirewallRulePullResult) ([]byte, error)
func FirewallRuleDiffEnvelope(r *svc.FirewallRuleDiffResult) ([]byte, error)
func FirewallRulePushEnvelope(r *svc.FirewallRulePushResult) ([]byte, error)
```

Schema names: `sophosfw.v1.firewallRulePull`, `sophosfw.v1.firewallRuleDiff`, `sophosfw.v1.firewallRulePush`.

### 7.5 Catalog change

```yaml
- xmlTag: FirewallRule
  ...
  mutable: true
```

## 8. Data flow

### 8.1 Pull

1. Resolve active profile.
2. (No read-only check — pull is non-mutating.)
3. `Inner.Get(profile, "FirewallRule", ruleName)` → `map[string]any` (the existing `FirewallRuleSvc.Get` already returns this shape). Not found → `kind: not_found`.
4. Compute `DiffHash(rule)` (canonical-JSON SHA-256 over the map; same `DiffHash` helper as Phase 6).
5. Marshal rule to canonical YAML. Field ordering must be deterministic — sort top-level keys alphabetically before marshaling so two calls on the same data produce byte-identical YAML.
6. `draft.DraftPath` and `draft.SnapshotPath`. Create parent dirs `0700` if missing.
7. Write the snapshot first (immutable record of what was on the firewall at this moment).
8. Write the draft second (overwrites any prior draft).
9. `RotateSnapshots(..., keep: cfg.Defaults.SnapshotRetention)` — defaults to 10.
10. Walk the rule body to extract referenced object names per the catalog metadata for FirewallRule (we know which fields are reference-bearing: `SourceNetworks`, `DestinationNetworks`, `Services`, `SourceZones`, `DestinationZones`, `Schedule`, `IdentityList`, etc.).
11. Audit entry: `{operation: "firewall_rule_pull", objectType: "FirewallRule", objectName: ruleName, result: "ok"}`.
12. Return `FirewallRulePullResult`.

### 8.2 Diff

1. Read the draft via `draft.ReadDraft`.
2. List snapshots via `draft.ListSnapshots`. Find the one whose header `diffHash` equals the draft's header `diffHash`. None matches → `kind: not_found` with sentinel `ErrSnapshotMissing` and message recommending re-pull.
3. Compute the diff:
   - Default text mode: unified diff between snapshot body bytes and draft body bytes. Implementation: a small stdlib-only line-based unified-diff helper in `internal/draft/diff.go` (≤80 LOC). No new dependencies.
   - `--json`: parse both into `map[string]any`, walk recursively, emit `[]DiffEntry`.
4. (No audit entry — diff is local-only and non-firewall-touching.)
5. Return `FirewallRuleDiffResult`.

### 8.3 Push

1. Read the draft.
2. Sanity: header `rule:` ≠ positional name → `kind: invalid_request`. Header `profile:` ≠ active profile → `kind: invalid_request`.
3. Validate body: `yaml.Unmarshal` into `map[string]any` (parse failure → `kind: invalid_request`); then check that `Name`, `Status`, `IPFamily`, and `PolicyType` are present and non-empty (missing → `kind: invalid_request` with the missing field name in the message).
4. Active profile is read-only → `kind: read_only`.
5. Catalog entry's `Mutable: false` → `kind: immutable`.
6. `Inner.Get(profile, "FirewallRule", ruleName)` → live state. Not found → `kind: not_found`.
7. `DiffHash(liveRule)` vs draft header `diffHash`. Mismatch → `kind: diff_hash_mismatch` (override: `ignoreHash` flag).
8. Build envelope: `sophos.BuildSetEnvelope("update", marshalFirewallRule(parsedBody), username, password)`, where `marshalFirewallRule` is a new helper (mirrors Phase 6's `marshalIPHost`) that XML-marshals the typed struct via `encoding/xml` with `xml.EscapeText` on string fields.
9. Initialize audit entry: `{operation: "firewall_rule_push", objectType: "FirewallRule", objectName: ruleName, expectedDiffHash: header.DiffHash, redactedXml: safety.RedactXML(envelope)}`.
10. **Dry-run path:** entry result `"ok (dry-run)"`. Audit-write. Return `FirewallRulePushResult{DryRun: true, Preview: ...}`.
11. **Apply path:** `cl.DoRaw(envelope)`.
    - On error: entry result `"error:" + ErrorKind(sendErr)`. Audit-write. Return error.
    - On success: refetch the rule. Compute new hash. Write the new snapshot under `snapshots/<slug>-<new-utc>.yaml`. `RotateSnapshots`. Update the draft header's `diffHash` in place (rewrite the file with the new hash but unchanged body — the user keeps editing forward). Entry result `"ok"`. Audit-write. Return `FirewallRulePushResult{DryRun: false, Item: refetched, NewDiffHash: ...}`.

### 8.4 Delete

Mirrors Phase 6 `HostIPSvc.Delete`:

1. Active profile is read-only → `kind: read_only`.
2. Catalog `Mutable: false` → `kind: immutable`.
3. CLI-side check: `--yes` without `--expected-diff-hash` and without `--ignore-diff-hash` → reject early.
4. Refetch live rule. `DiffHash` mismatch → `kind: diff_hash_mismatch` (override: `ignoreHash`).
5. Build `sophos.BuildRemoveEnvelope` with the rule's name (XML-escaped via `xml.EscapeText`, same as Phase 6's delete fix).
6. Initialize audit entry: `{operation: "firewall_rule_delete", ...}`.
7. Dry-run / apply / audit, same pattern as Push.
8. On apply success: archive the deleted rule's last-known-state under `snapshots/<slug>-<now>-deleted.yaml` (note the `-deleted` suffix to flag this as a tombstone rather than a regular snapshot). Subsequent `RotateSnapshots` treats `-deleted` snapshots the same as regular snapshots for retention purposes.

## 9. Error handling

| Trigger | Sentinel | Kind | Exit |
|---|---|---|---|
| Draft file missing | `ErrDraftMissing` (new) | `not_found` | 4 |
| Draft header malformed | `ErrInvalidRequest` | `invalid_request` | 6 |
| Header `rule:`/`profile:` mismatch with cli args | `ErrInvalidRequest` | `invalid_request` | 6 |
| YAML body fails to parse, or required field (`Name`/`Status`/`IPFamily`/`PolicyType`) missing | `ErrInvalidRequest` | `invalid_request` | 6 |
| No matching snapshot for diff | `ErrSnapshotMissing` (new) | `not_found` | 4 |
| Read-only profile | `ErrReadOnlyViolation` | `read_only` | 5 |
| Catalog `Mutable: false` | `ErrImmutable` | `immutable` | 5 |
| Live rule not found on push/delete | `ErrNotFound` | `not_found` | 4 |
| Live hash ≠ draft header hash | `ErrDiffHashMismatch` | `diff_hash_mismatch` | 7 |
| Sophos firewall rejected envelope | passes through | varies | 1/2/3 |

The new sentinels (`ErrDraftMissing`, `ErrSnapshotMissing`) are added to `internal/svc/errors_kind.go` with `ErrorKind` returning `"not_found"` for both. No new exit codes — `ExitCodeFor("not_found")` already returns 4.

The `diff_hash_mismatch` user-facing message is tailored: `"firewall rule <name> has changed on the firewall since you ran pull (have <new>, expected <old>); re-run \`sophosfw firewall rule pull <name>\` to refresh, or pass --ignore-diff-hash to override"`.

Pre-flight rejections that occur *before* the audit entry is constructed (e.g., draft file missing) are not audit-logged. Phase 6 has the same gap; closing it is a foundation cleanup-pass concern, not Phase 7's.

## 10. Audit log

Three new operation tags:

- `firewall_rule_pull` — written on every successful pull. `objectType: "FirewallRule"`. No `redactedXml` (pull is read-only — the `<Get>` envelope is already implied by the catalog and need not be logged).
- `firewall_rule_push` — written on every push attempt that reaches the post-validation point. `result` reflects success, dry-run, or `error:<kind>`. `redactedXml` carries the envelope being sent. `expectedDiffHash` carries the header's value.
- `firewall_rule_delete` — same shape as `firewall_rule_push` with `redactedXml` of the `<Remove>` envelope.

Existing `defaults.auditLog: false` config knob continues to suppress all audit writes.

## 11. Testing strategy

### 11.1 Unit tests

- `internal/draft/`:
  - `Slug` rules including unicode (zero-character result), spaces, slashes, parens, and runs of dashes.
  - `DraftPath` / `SnapshotPath` collision resolution (two distinct names slugging to the same value get different suffixes; same name resolves to same path).
  - `ReadDraft` / `WriteDraft` round-trip with all required header fields; rejects missing headers, malformed timestamps, malformed hashes.
  - `RotateSnapshots` with `keep=10` and 15 existing snapshots: oldest 5 are deleted; sort order is by timestamp.
  - File-permission assertion (0600/0700) via `os.Stat`.

- `internal/svc/firewallrule_test.go`:
  - `Pull_WritesSnapshotAndDraft` (asserts both files, hash, reference summary).
  - `Pull_OverwritesExistingDraft` (second pull replaces the first; new snapshot added).
  - `Pull_RotatesOldSnapshots` (15 pulls leave 10 snapshots).
  - `Diff_NoChanges` (HasChanges=false, empty diff).
  - `Diff_DetectsFieldChange` (one-field edit shows in unified diff).
  - `Diff_StructuredJSON` (DiffEntry list correct).
  - `Diff_MissingSnapshot_Error` (kind=not_found).
  - `Push_DryRun_NoSend` (no envelope sent; preview emitted; audit entry result="ok (dry-run)").
  - `Push_Apply_RefetchAndArchive` (envelope sent; snapshot archived; draft header's hash updated).
  - `Push_DiffHashMismatch_Rejects` (kind=diff_hash_mismatch; no envelope sent).
  - `Push_DiffHashMismatch_IgnoreFlag_Applies` (envelope sent despite mismatch).
  - `Push_HeaderRuleMismatch_Rejects` (kind=invalid_request).
  - `Push_RequiredFieldMissing_Rejects` (body missing `PolicyType` → kind=invalid_request).
  - `Push_ReadOnlyProfile_Rejects` (envelope not built).
  - `Push_Failure_AuditLogged` (audit entry result starts with "error:").
  - `Delete_RequiresExpectedHash` (cli-side gate).
  - `Delete_Apply` (`<Remove>` envelope sent; snapshot archived as `-deleted`).

- `internal/cli/firewallrule_mutation_test.go`:
  - `pull --json`, `diff --json`, `push --json`, `delete --json` all emit the expected schema.
  - Default (no `--yes`) on push runs as dry-run.
  - `delete` without `--expected-diff-hash` errors at the cli before any service call.

### 11.2 Integration tests (build tag `integration`, against testvm)

- `TestIntegration_FirewallRulePull_RoundTrips` — pull a real rule, assert files exist, header parses, hash is non-empty, reference summary is non-empty.
- `TestIntegration_FirewallRulePush_DryRun` — pull → push without `--yes` → assert preview envelope; the IntegrationClient panic-on-mutating safety net catches accidental sends.
- `TestIntegration_FirewallRulePush_RoundTrip` — pull a real rule, toggle `LogTraffic` (Enable↔Disable), push with `--yes`, refetch, assert change persisted, then push again to revert. **Cleanup**: the test uses `t.Cleanup` to revert even if assertions fail mid-test.
- Delete is intentionally NOT exercised in integration tests — deleting a real rule is too disruptive even on a cloned VM. Unit tests cover the wire format end-to-end via fakes; the manual smoke (Section 11.3) doesn't include delete either.

### 11.3 Manual smoke (final task)

1. `sophosfw firewall rule pull <real-rule>` — inspect both files, verify header, verify reference summary.
2. Edit one field in the draft.
3. `sophosfw firewall rule diff <real-rule>` — confirm the change shows.
4. `sophosfw firewall rule push <real-rule> --json` (no `--yes`) — confirm preview envelope with redacted XML.
5. Manually mutate the live rule via the firewall webconsole, then `push --yes` — confirm `kind: diff_hash_mismatch` and exit 7.
6. Re-pull, push `--yes`, refetch, confirm change applied.
7. `cat ~/.config/sophosfw/audit.log | tail -10` — confirm pull/push entries with redacted credentials.
8. Revert the change.

## 12. Acceptance criteria

- All unit tests pass (`go test ./...`).
- All integration tests pass against testvm (`SOPHOSFW_PROFILE=testvm go test -tags=integration ./internal/testutil`).
- `make skill-doctor` returns `skill ok` (skill-content updates are tracked in a sibling Phase 7 task, not in this spec).
- Manual smoke checklist passes end-to-end.
- `go fmt` / `go vet` / `go test -race` clean.
- New tag `v0.6.0-phase7`.

## 13. Conventions inherited from earlier phases

- No `Co-Authored-By` trailer on implementation commits.
- Single passing commit per task.
- Module path `github.com/iainmoffat/sophosfw`. Working directory `/Users/ipm/code/sophosfw`. Branch `main` (the project does work on `main` after Phase 5 was merged).
- SDK alias `sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"` (not used in Phase 7 — MCP is deferred).
- Skill content in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` is updated separately and not committed in the sophosfw repo.

## 14. Deferred to Phase 8 or later

- MCP-native tools: `firewall_rule_pull`, `firewall_rule_diff`, `firewall_rule_push`, `firewall_rule_delete`. Stateless variants (no draft file on the MCP side; YAML passed inline through tool args).
- `firewall rule new` / `firewall rule create` workflow with templating.
- Same workflow extended to `NATRule`, `IPSecVPN`, `SSLVPN`.
- Closing the audit-log gap for pre-flight rejections (foundation concern, applies to Phase 6 too).
- Wiring `--insecure-skip-verify` cli flag through `cmd/sophosfw/main.go` (foundation TODO observed during Phase 6 smoke).
