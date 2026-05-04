# Phase 13 — Backup + drift detection (design)

**Date:** 2026-05-03
**Status:** Design (pre-implementation)
**Goal:** Add `sophosfw backup` (full firewall config dump as a YAML tree) and `sophosfw drift` (compare a snapshot against current state). Read-only feature; high value for change-tracking, audit, and pre-edit safety. Ship as `v0.11.0`.

---

## 1. Motivation

After Phase 12 sophosfw has full mutating surface for 9 of 12 catalog types. The natural next capability is **change tracking**: "what changed on the firewall since I last looked?"

Today the user's options are:
- Run `sophosfw object list <Type>` for each type by hand and eyeball the output
- Use the existing per-firewall-rule `pull` (creates a single-record snapshot)
- Compare two `--json` outputs with external diff tools

None of these scale to "did anything change anywhere on the firewall this week?" A unified backup+drift workflow gives:

- **Disaster recovery** (read-only baseline of the full config)
- **Audit trail** (timestamped snapshots stored under the profile config dir)
- **Drift detection** (CI-friendly exit codes; agent-friendly JSON output)
- **Pre-edit safety** (snapshot before a change session, drift afterward to confirm only intended changes landed)

This phase ships read-only. **Restore is explicitly out of scope** — the snapshot format is round-trippable in principle (per-record YAML bodies) but no `restore` command is added in Phase 13.

## 2. Architecture

Two new top-level CLI commands (`sophosfw backup`, `sophosfw drift`) plus matching MCP tools. Implementation reuses Phase 6/12 primitives:

- `ObjectSvc.List` for per-type fetch (already returns full bodies)
- `marshalCanonicalYAML` for stable per-record output (already used by drafts)
- `DiffHash` for fast unchanged-record detection (already used by firewall_rule_show / _diffHash injection)
- `internal/draft/paths.go` slug logic for filesystem-safe filenames (existing)

No new dependencies. New code lives in:
- `internal/svc/backup.go` — `BackupSvc.Create`, `BackupSvc.Drift`, `BackupSvc.List`, `BackupSvc.Rotate`
- `internal/cli/backup.go` — `sophosfw backup` (+ `list` / `rotate` sub-commands)
- `internal/cli/drift.go` — `sophosfw drift`
- `internal/mcp/backup.go` — `backup_create`, `backup_list`, `drift_check` MCP tools (3 new tools, count 48 → 51)
- `internal/render/backup.go` — JSON envelope + table renderers
- `internal/render/drift.go` — JSON envelope + summary-table + per-record unified-diff renderer

## 3. Components

### 3.1 Backup output structure (per-record files)

```
~/.config/sophosfw/profiles/<name>/backups/<utc-timestamp>/
├── _meta.yaml
├── FirewallRule/
│   ├── Block-Countries.yaml
│   ├── Allow-LAN-to-WAN.yaml
│   └── ...
├── NATRule/
│   └── ...
├── IPHost/
├── IPHostGroup/
├── FQDNHost/
├── FQDNHostGroup/
├── MACHost/
├── Services/
├── ServiceGroup/
├── Zone/
├── Interface/
└── GatewayConfiguration/
```

`<utc-timestamp>` format: `2026-05-03T20-30-00Z` (matches `draft.SnapshotPath` convention).

Filename slugging: reuse `internal/draft/paths.go::slug` (existing). Validates against filesystem-unsafe chars; collision handling already implemented for drafts.

**Per-record file content**: the record body, with `_diffHash` retained (so drift can short-circuit unchanged records by hash compare without re-canonicalizing). YAML serialized via `marshalCanonicalYAML`.

```yaml
# FirewallRule/Block-Countries.yaml
Name: Block Countries
Status: Enable
IPFamily: IPv4
PolicyType: Network
Position: Top
NetworkPolicy:
  Action: Drop
  ...
_diffHash: "a3b8f2c1..."
```

`_meta.yaml`:

```yaml
schema: sophosfw.v1.backupMeta
profile: testvm
url: https://192.168.1.2:4444
sophosfwVersion: "0.11.0-pre"
createdAt: "2026-05-03T20:30:00Z"
catalogVersion: "1"
typesIncluded:
  - FirewallRule
  - NATRule
  - IPHost
  # ... (12 entries by default)
recordCounts:
  FirewallRule: 124
  NATRule: 47
  # ...
totalRecords: 503
```

The `schema` field follows the existing `sophosfw.v1.*` envelope convention.

### 3.2 Backup command

**CLI:**

```bash
sophosfw backup                                # default location, all 12 types
sophosfw backup --out /path/to/snapshot-dir    # custom location (must not exist)
sophosfw backup --types FirewallRule,NATRule   # subset
sophosfw backup --exclude Zone,Interface       # complement: all except these
sophosfw backup list                           # list snapshots under default location
sophosfw backup rotate --keep 10               # delete all but the 10 most recent
```

Top-level `sophosfw backup` (no sub-command) is `create`. `backup list` and `backup rotate` are sub-commands. (Cobra treats the parent's RunE as the default action when no sub-command is given — clean.)

**Flag matrix:**

| Flag | Where | Notes |
|---|---|---|
| `--out <dir>` | create | Override default snapshot location. Must not exist. |
| `--types <csv>` | create | Subset of catalog types. Mutually exclusive with `--exclude`. |
| `--exclude <csv>` | create | Skip listed types from full set. |
| `--keep N` | rotate | Required. Keep N most recent snapshots; delete older. |

**MCP tools:**

```
backup_create:
  Inputs: { profile?, out?, types?, exclude? }
  Output: sophosfw.v1.backupCreate
  Behavior: writes snapshot to disk; returns metadata (path, profile, timestamp, recordCounts).

backup_list:
  Inputs: { profile? }
  Output: sophosfw.v1.backupList
  Behavior: lists snapshots under the default location for the profile;
            returns array of { path, createdAt, recordCounts }.
```

`backup_create` does NOT have a `confirm` gate — it's read-only as far as the firewall is concerned (just produces files locally).

**`backup_rotate` is intentionally CLI-only** (no MCP tool). Rotation deletes filesystem state; exposing it to agents widens the destructive surface for low value (agents can request a rotate via the user running the CLI command). If a real agent workflow needs it, add in a follow-up — the svc method exists; only the MCP registration is omitted.

### 3.3 Drift command

**CLI:**

```bash
sophosfw drift /path/to/backup-2026-05-01     # explicit dir
sophosfw drift --latest                        # most recent under default location
sophosfw drift --latest --json                 # machine-readable output
sophosfw drift --latest --types FirewallRule   # only check this type
```

**Flags:**

| Flag | Notes |
|---|---|
| `<positional dir>` | Snapshot dir. XOR with `--latest`. |
| `--latest` | Use most recent snapshot under default location. |
| `--types <csv>` | Restrict drift check to these types. |
| `--json` | Machine-readable output. Default is human (table + per-record diff). |

**Exit codes:** 0 = no drift, 1 = drift detected, 2 = error. Mirrors `git diff --exit-code`.

**Default human output** (table + diffs):

```
sophosfw drift /path/to/backup-2026-05-01

  Profile: testvm  Snapshot: 2026-05-01T08-00-00Z  Now: 2026-05-03T20:30:14Z

  Type             Added  Modified  Removed  Unchanged
  FirewallRule     1      2         0        121
  IPHost           0      1         0        311
  Zone             0      0         0        4
  ...

  Total: 1 added, 3 modified, 0 removed (unchanged: 487)

  --- Modified: FirewallRule/Block-Countries.yaml
  +++ Modified: FirewallRule/Block-Countries (live)
  @@ -3,7 +3,7 @@
     Status: Enable
     NetworkPolicy:
       Action: Drop
  -    LogTraffic: Enable
  +    LogTraffic: Disable
       Schedule: All The Time

  --- Added: IPHost/new-server.yaml
  +++ ...
  (full body)

  --- Removed: Services/old-tcp-3000
  (just the name; record body shown if --verbose)
```

**JSON output** (`--json`):

```json
{
  "schema": "sophosfw.v1.drift",
  "snapshot": "/path/to/backup-2026-05-01",
  "profile": "testvm",
  "snapshotCreatedAt": "2026-05-01T08:00:00Z",
  "checkedAt": "2026-05-03T20:30:14Z",
  "summary": {
    "added": 1,
    "modified": 3,
    "removed": 0,
    "unchanged": 487,
    "perType": {
      "FirewallRule": {"added": 1, "modified": 2, "removed": 0, "unchanged": 121},
      "IPHost": {"added": 0, "modified": 1, "removed": 0, "unchanged": 311}
    }
  },
  "changes": [
    {"type": "FirewallRule", "name": "Block-Countries", "change": "modified", "diff": "..."},
    {"type": "IPHost", "name": "new-server", "change": "added", "body": {...}},
    {"type": "Services", "name": "old-tcp-3000", "change": "removed"}
  ]
}
```

**MCP tool:**

```
drift_check:
  Inputs: { profile?, snapshot?, latest?, types? }
  Output: sophosfw.v1.drift  (always JSON shape, regardless of CLI's --json flag)
  Behavior: read-only; returns the change-set.
```

`drift_check` does NOT mutate anything; no confirm gate.

### 3.4 Snapshot path + lifecycle helpers

New svc helpers in `internal/svc/backup.go`:

```go
type BackupSvc struct {
    Inner   *ObjectSvc
    Catalog *catalog.Catalog
    BaseDir string
    Now     func() time.Time
}

type BackupCreateOptions struct {
    OutDir   string   // empty → default location
    Types    []string // empty → all 12
    Exclude  []string // mutually exclusive with Types
}

type BackupCreateResult struct {
    Profile        string
    Path           string
    CreatedAt      time.Time
    TypesIncluded  []string
    RecordCounts   map[string]int
    TotalRecords   int
}

type BackupListEntry struct {
    Path         string
    CreatedAt    time.Time
    RecordCounts map[string]int
}

type DriftOptions struct {
    SnapshotPath string   // explicit path, OR
    Latest       bool     // resolve from default location
    Types        []string // empty → all in snapshot
}

type DriftResult struct {
    SnapshotPath      string
    Profile           string
    SnapshotCreatedAt time.Time
    CheckedAt         time.Time
    Summary           DriftSummary
    Changes           []DriftChange
}

type DriftSummary struct {
    Added     int
    Modified  int
    Removed   int
    Unchanged int
    PerType   map[string]DriftSummaryPerType
}

type DriftSummaryPerType struct{ Added, Modified, Removed, Unchanged int }

type DriftChange struct {
    Type   string
    Name   string
    Change string             // "added" | "modified" | "removed"
    Diff   string             // unified diff text, only for "modified"
    Body   map[string]any     // only for "added" (full body)
}

func (s *BackupSvc) Create(ctx context.Context, profile string, opts BackupCreateOptions) (*BackupCreateResult, error)
func (s *BackupSvc) List(profile string) ([]BackupListEntry, error)
func (s *BackupSvc) Rotate(profile string, keep int) (deleted []string, err error)
func (s *BackupSvc) Drift(ctx context.Context, profile string, opts DriftOptions) (*DriftResult, error)
```

Default snapshot location (helper):

```go
// internal/draft/paths.go (extend)
func BackupRootDir(baseDir, profile string) (string, error)
// returns: <baseDir>/profiles/<profile>/backups/

func BackupSnapshotDir(baseDir, profile string, t time.Time) (string, error)
// returns: <baseDir>/profiles/<profile>/backups/2026-05-03T20-30-00Z/
```

Reuses the same `validProfileName` allowlist as draft paths.

### 3.5 Diff format

Per-record unified diff produced via `internal/draft/diff.go::UnifiedDiff` (existing — used today by `firewall rule diff`). Diff inputs:

- Snapshot side: read from `<snapshot-dir>/<Type>/<slug>.yaml`, strip `_diffHash`, marshal canonical
- Live side: fetch via `ObjectSvc.Get(profile, type, "Name", name)`, strip `_diffHash`, marshal canonical

Hash short-circuit: if BOTH sides have `_diffHash` and they match, classify as `unchanged` without computing the diff. Saves work on a 500-record firewall where most records are unchanged.

For "added" records (in live, not in snapshot): full body in JSON, full YAML in human output.
For "removed" records (in snapshot, not in live): just `<Type>/<name>` in human output, `change: removed` + `name` in JSON.

## 4. Data flow

**Backup**:

```
sophosfw backup
  ↓
BackupSvc.Create(profile, opts)
  ↓
For each type in (resolved type set):
  records := ObjectSvc.List(profile, type)
  For each record:
    write <out-dir>/<Type>/<slug>.yaml (body + _diffHash)
  ↓
Write _meta.yaml
  ↓
Return BackupCreateResult
```

**Drift**:

```
sophosfw drift <snapshot-dir>
  ↓
BackupSvc.Drift(profile, opts)
  ↓
Read _meta.yaml; verify profile match (or warn if --force)
  ↓
For each type in snapshot dir:
  snapshotRecords := load <snapshot-dir>/<Type>/*.yaml
  liveRecords     := ObjectSvc.List(profile, type)
  For each name in (snapshotNames ∪ liveNames):
    if only in live      → DriftChange{Change: "added"}
    if only in snapshot  → DriftChange{Change: "removed"}
    if in both:
      if hashes match    → "unchanged"
      else               → unified-diff → DriftChange{Change: "modified", Diff: ...}
  ↓
Aggregate summary
  ↓
Return DriftResult
```

Concurrency: per-type fetches can run in parallel (independent). Per-record diffs within a type are CPU-only (no I/O after the list call) — sequential is fine, parallelism not worth the complexity.

## 5. Errors

No new sentinels. Reuses:
- `sophos.ErrNotFound` — snapshot dir doesn't exist
- `sophos.ErrInvalidRequest` — `--out` already exists; `--types` and `--exclude` both set; `--types` references unknown type; snapshot's profile doesn't match current profile
- `sophos.ErrReadOnlyViolation` — N/A (backup/drift are read-only)
- Wrapped fs errors — bubbled up with context

## 6. Testing strategy

### Unit tests

- `internal/svc/backup_test.go`:
  - `TestBackup_Create_DefaultLocation_WritesAllTypes` — fake catalog/list, assert per-type subdirs + per-record files + `_meta.yaml`
  - `TestBackup_Create_WithTypesFilter_OnlyIncludesSubset`
  - `TestBackup_Create_WithExcludeFilter_OmitsListedTypes`
  - `TestBackup_Create_RejectsTypesAndExcludeTogether`
  - `TestBackup_Create_RejectsExistingOutDir`
  - `TestBackup_Create_WritesDiffHashInRecordFiles`
  - `TestBackup_List_ReturnsTimestampSorted`
  - `TestBackup_Rotate_DeletesOldestKeepsNewest`
  - `TestBackup_Drift_ReportsAddedModifiedRemovedUnchanged`
  - `TestBackup_Drift_HashShortCircuit_SkipsDiff`
  - `TestBackup_Drift_RejectsProfileMismatch`
  - `TestBackup_Drift_PerTypeFilter`

- `internal/render/backup_test.go`, `internal/render/drift_test.go`:
  - JSON envelope shape
  - Human table output (basic shape; full visual fidelity tested via golden files)

- `internal/cli/backup_test.go`, `internal/cli/drift_test.go`:
  - Flag parsing (--out, --types, --exclude, --latest, --json)
  - Mutual exclusion errors
  - Exit code propagation (drift returns 1 when changes present, 0 when clean)

- `internal/mcp/backup_test.go`:
  - `backup_create` writes the tree and returns metadata
  - `drift_check` returns the change-set JSON

### Integration tests (build-tagged)

Extend `internal/testutil/integration_test.go`:

- `TestIntegration_Backup_Create_FullSnapshot` — runs full backup against testvm, asserts at least 1 record per mutable type written
- `TestIntegration_Drift_NoChanges_ExitsZero` — backup → immediate drift → expect 0 changes, exit 0
- `TestIntegration_Drift_AfterAdd_ReportsAdded` — backup → host_ip_create a test host → drift → expect 1 added, exit 1 → cleanup (delete the test host)

### Manual smoke

```bash
sophosfw backup
ls -la ~/.config/sophosfw/profiles/testvm/backups/

sophosfw backup list
sophosfw drift --latest        # expect: no drift, exit 0

sophosfw host ip update <some-host> --body @body.yaml --expected-diff-hash <hash> --yes
sophosfw drift --latest        # expect: 1 modified, exit 1, diff visible

sophosfw drift --latest --json | jq .
sophosfw backup rotate --keep 3
```

## 7. Acceptance

- [ ] `sophosfw backup` writes a complete snapshot tree with `_meta.yaml` + per-type subdirs + per-record YAML files.
- [ ] `sophosfw backup list` enumerates snapshots under the default location.
- [ ] `sophosfw backup rotate --keep N` deletes all but N most recent snapshots.
- [ ] `sophosfw drift <dir>` and `sophosfw drift --latest` work; exit code 0 when clean, 1 when drift, 2 on error.
- [ ] `--json` flag on drift produces a `sophosfw.v1.drift` envelope.
- [ ] MCP tools `backup_create`, `backup_list`, `drift_check` registered (count 48 → 51).
- [ ] Unit tests for both happy path and the listed error modes pass.
- [ ] At least 2 integration tests pass against testvm.
- [ ] `docs/api-coverage.md` unchanged (no surface change). `docs/roadmap.md` updated.
- [ ] `v0.11.0` tagged + released; `brew upgrade sophosfw` works.

## 8. Out of scope

- **Restore command.** Snapshot format is round-trippable (per-record YAML bodies map cleanly back to the existing create/update svc methods), but no `restore` is added in Phase 13. Defer to Phase 14+.
- **Cross-profile drift comparison.** Drift compares one profile's snapshot against the same profile's current state. Comparing `profile A snapshot` against `profile B live state` is a different use case (config diff between firewalls) — defer.
- **Auto-rotation on backup.** Each `sophosfw backup` invocation is independent. Rotation requires the explicit `backup rotate --keep N` command. Cron users handle their own retention.
- **Compression.** Snapshot trees are plain YAML; user can `tar czf` if they want to ship one.
- **Diff filtering by field.** "Show me drift but ignore Position changes" — defer. Full diff only.
- **Per-record snapshots from existing draft pull workflow.** The existing `firewall rule pull` writes a single-record snapshot under `snapshots/firewall/`. Phase 13's `backup` is a separate, full-config path; the two coexist. Future consolidation is its own phase.

## 9. Risks

- **Filename slugging collisions.** Two records with names like `Foo Bar` and `Foo-Bar` slug to the same filename. The existing `internal/draft/paths.go::slug` handles this for drafts (suffix with hash) — verify the same logic applies cleanly here. If two records collide, the second-written file overwrites the first silently. Mitigation: extend slug logic to detect collision within the snapshot dir during write, append a hash disambiguator when needed.

- **Large firewalls produce many files.** A real firewall with 1000+ FirewallRules + 500+ IPHosts produces a snapshot dir with 1500+ files. macOS / Linux filesystems handle this fine; `ls` and `tree` may be slow but interactive use is OK. No mitigation needed unless real-world reports show pain.

- **Profile mismatch on drift.** User runs `sophosfw drift backup-from-other-firewall/`. Currently we'd compute drift against the wrong baseline silently. Mitigation: `_meta.yaml` records the profile name + URL; drift refuses if either differs from the current profile (with `--force` to override).

- **Snapshot during a long-running mutation.** If the user runs `sophosfw backup` mid-way through a Sophos web-UI edit session, the snapshot captures whatever state the API returns at that moment. Sophos doesn't expose transaction boundaries. Acceptable — backups are point-in-time observations, not transactionally consistent.

- **Disk space.** A backup of a 1000-rule firewall is probably ~5-20 MB. `backup rotate --keep 30` (one per day) is ~600 MB at the upper bound. Acceptable; document in the help text.

- **Sophos pagination / list response size.** Some types might return very large list responses. Existing `ObjectSvc.List` handles this transparently. If a list call fails mid-way during backup, the snapshot is incomplete — the implementation must atomically rename a `.partial` directory to the final name only on full success. Otherwise users get half-broken snapshots that drift would misreport.

## 10. Decision log

- **Q1 — Output structure: per-record files in per-type subdirs (option C).** Rationale: clean per-record diffs, git-tree-friendly, restore-ready. File count is acceptable.
- **Q2 — Scope: all 12 catalog tags by default with `--types` and `--exclude` flags (option A).** Rationale: drift on Zone/Interface is exactly the kind of unauthorized-change signal a network admin wants.
- **Q3 — Drift output: human-default summary table + per-record unified diff; `--json` flag for machine; CI exit codes (option A).** Rationale: matches existing CLI UX; CI integration via exit codes mirrors `git diff --exit-code`.
- **Q4 — MCP exposure: both `backup_create` and `drift_check` (Option 1). CLI placement: root-level `sophosfw backup` and `sophosfw drift` (option a).** Rationale: drift is high-value for agents; backup is useful for "snapshot before edit" agent workflow. Root-level reads cleanest for top-level operations.
- **Defaults**: snapshot path `~/.config/sophosfw/profiles/<name>/backups/<utc-timestamp>/`; never overwrite (timestamped); `--out` flag for custom location; `backup list` + `backup rotate --keep N` sub-commands; `drift --latest` resolves to most recent snapshot; profile mismatch refuses with `--force` override.
- **Release tag**: `v0.11.0` (minor bump — new user-visible feature, no breaking changes).

## 11. References

- Existing snapshot path / slug logic: `internal/draft/paths.go::SnapshotPath`, `slug`
- Unified diff helper: `internal/draft/diff.go::UnifiedDiff`
- DiffHash: `internal/svc/diffhash.go::DiffHash`
- Per-rule pull pattern (precedent for snapshot writing): `internal/svc/firewallrule_pull.go::Pull`
- Catalog enumeration: `internal/catalog/catalog.go::All` (or equivalent)
- Existing MCP read-only tool patterns: `internal/mcp/object.go`, `internal/mcp/auth.go`
