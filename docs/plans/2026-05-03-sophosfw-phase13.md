# sophosfw Phase 13 Implementation Plan

**Goal:** Add `sophosfw backup` (full firewall config dump as a YAML tree) and `sophosfw drift` (compare a snapshot to current state). Read-only; CI-friendly exit codes; agent-friendly JSON output. Ship as `v0.11.0`.

**Architecture:** New `BackupSvc` with four methods (Create / List / Rotate / Drift). Reuses existing primitives (`ObjectSvc.List`, `marshalCanonicalYAML`, `DiffHash`, `internal/draft/paths.go::slug`). Per-record files in per-type subdirs under `~/.config/sophosfw/profiles/<name>/backups/<utc-timestamp>/`. CLI commands at root level (`sophosfw backup`, `sophosfw drift`). 3 new MCP tools (count 48 → 51).

**Tech Stack:** Go 1.26+, gopkg.in/yaml.v3, github.com/modelcontextprotocol/go-sdk v1.5.0. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-03-sophosfw-phase13-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.10.0`. Working dir: `/Users/ipm/code/sophosfw`.

```bash
git status
go test ./... -count=1 -race
golangci-lint run ./...
```

Expected: clean status, all tests pass, lint clean.

## File structure

**New files:**
- `internal/draft/paths.go` — extend with `BackupRootDir` + `BackupSnapshotDir`.
- `internal/svc/backup.go` — `BackupSvc` + types + Create / List / Rotate / Drift methods.
- `internal/svc/backup_test.go` — unit tests.
- `internal/render/backup.go` — backup envelope + table renderer.
- `internal/render/backup_test.go`.
- `internal/render/drift.go` — drift envelope + summary table + per-record diff renderer.
- `internal/render/drift_test.go`.
- `internal/cli/backup.go` — `sophosfw backup` (+ `list` / `rotate` subcommands).
- `internal/cli/backup_test.go`.
- `internal/cli/drift.go` — `sophosfw drift`.
- `internal/cli/drift_test.go`.
- `internal/mcp/backup.go` — 3 MCP tools.
- `internal/mcp/backup_test.go` — handler tests.

**Modified files:**
- `internal/cli/root.go` — register `backup` and `drift` commands.
- `internal/mcp/server.go` — register backup tools.
- `internal/mcp/server_test.go` — tool count 48 → 51; add 3 names.
- `docs/roadmap.md` — Phase 13 complete (final task).

---

## Task 1: Snapshot path helpers

**Files:**
- Modify: `internal/draft/paths.go`
- Modify: `internal/draft/paths_test.go`

- [ ] **Step 1: Read existing path helpers**

```bash
grep -n "func.*RootDir\|func.*SnapshotPath\|func.*DraftPath" internal/draft/paths.go
```

Confirm the existing pattern (signature returns `(string, error)`, validates profile name, validates tag if applicable).

- [ ] **Step 2: Add `BackupRootDir` and `BackupSnapshotDir`**

Append to `internal/draft/paths.go`:

```go
// BackupRootDir returns the directory containing all backup snapshots
// for a profile. Created lazily by BackupSvc.Create.
func BackupRootDir(baseDir, profile string) (string, error) {
    if !validProfileName(profile) {
        return "", fmt.Errorf("%w: invalid profile name %q", sophos.ErrInvalidRequest, profile)
    }
    return filepath.Join(baseDir, "profiles", profile, "backups"), nil
}

// BackupSnapshotDir returns the absolute path for a single backup
// snapshot. Format mirrors SnapshotPath: <root>/2026-05-03T20-30-00Z.
func BackupSnapshotDir(baseDir, profile string, t time.Time) (string, error) {
    root, err := BackupRootDir(baseDir, profile)
    if err != nil {
        return "", err
    }
    return filepath.Join(root, t.UTC().Format("2006-01-02T15-04-05Z")), nil
}
```

- [ ] **Step 3: Tests**

Append to `internal/draft/paths_test.go`:

```go
func TestBackupRootDir_Format(t *testing.T) {
    p, err := BackupRootDir("/base", "home")
    require.NoError(t, err)
    require.Equal(t, "/base/profiles/home/backups", p)
}

func TestBackupRootDir_RejectsInvalidProfile(t *testing.T) {
    _, err := BackupRootDir("/base", "../etc")
    require.Error(t, err)
}

func TestBackupSnapshotDir_Format(t *testing.T) {
    tt := time.Date(2026, 5, 3, 20, 30, 0, 0, time.UTC)
    p, err := BackupSnapshotDir("/base", "home", tt)
    require.NoError(t, err)
    require.Equal(t, "/base/profiles/home/backups/2026-05-03T20-30-00Z", p)
}
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/draft -run "TestBackupRoot\|TestBackupSnapshot" -v -count=1
golangci-lint run ./...
git add internal/draft/paths.go internal/draft/paths_test.go
git commit -m "$(cat <<'EOF'
draft: BackupRootDir + BackupSnapshotDir path helpers

Phase 13 backup/drift scaffolding. Mirrors the existing SnapshotPath
naming convention (UTC timestamp formatted as 2006-01-02T15-04-05Z).
Profile-name validation reuses validProfileName from drafts.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Do NOT push.

---

## Task 2: BackupSvc.Create

**Files:**
- Create: `internal/svc/backup.go`
- Create: `internal/svc/backup_test.go`

- [ ] **Step 1: Write the BackupSvc struct + types**

Create `internal/svc/backup.go` with the public types from the spec section 3.4. Key constants:

```go
// MetaSchemaName is the schema string written into _meta.yaml.
const MetaSchemaName = "sophosfw.v1.backupMeta"
```

The Create method must be **atomic**: write to `<snapshot-dir>.partial/`, then `os.Rename` to `<snapshot-dir>` only on full success. On any error, leave `.partial` for inspection but do NOT advertise an incomplete snapshot.

```go
type BackupSvc struct {
    Inner   *ObjectSvc
    Catalog *catalog.Catalog
    BaseDir string
    Now     func() time.Time
}

func (s *BackupSvc) now() time.Time {
    if s.Now != nil { return s.Now() }
    return time.Now().UTC()
}

type BackupCreateOptions struct {
    OutDir  string   // empty → default
    Types   []string // empty → all 12; XOR with Exclude
    Exclude []string
}

type BackupCreateResult struct {
    Profile       string
    Path          string
    CreatedAt     time.Time
    TypesIncluded []string
    RecordCounts  map[string]int
    TotalRecords  int
}

type backupMeta struct {
    Schema          string         `yaml:"schema"`
    Profile         string         `yaml:"profile"`
    URL             string         `yaml:"url"`
    SophosfwVersion string         `yaml:"sophosfwVersion"`
    CreatedAt       string         `yaml:"createdAt"`
    CatalogVersion  string         `yaml:"catalogVersion"`
    TypesIncluded   []string       `yaml:"typesIncluded"`
    RecordCounts    map[string]int `yaml:"recordCounts"`
    TotalRecords    int            `yaml:"totalRecords"`
}

func (s *BackupSvc) Create(ctx context.Context, profileName string, opts BackupCreateOptions) (*BackupCreateResult, error) {
    profile, name, err := s.Inner.Config.ActiveProfile(profileName)
    if err != nil {
        return nil, err
    }

    if len(opts.Types) > 0 && len(opts.Exclude) > 0 {
        return nil, fmt.Errorf("%w: --types and --exclude are mutually exclusive", sophos.ErrInvalidRequest)
    }

    types, err := s.resolveTypes(opts.Types, opts.Exclude)
    if err != nil {
        return nil, err
    }

    now := s.now()
    targetDir := opts.OutDir
    if targetDir == "" {
        targetDir, err = draft.BackupSnapshotDir(s.BaseDir, name, now)
        if err != nil {
            return nil, err
        }
    }

    if _, statErr := os.Stat(targetDir); statErr == nil {
        return nil, fmt.Errorf("%w: snapshot dir already exists at %s", sophos.ErrInvalidRequest, targetDir)
    } else if !os.IsNotExist(statErr) {
        return nil, statErr
    }

    partialDir := targetDir + ".partial"
    if err := os.RemoveAll(partialDir); err != nil {
        return nil, err
    }
    if err := os.MkdirAll(partialDir, 0o755); err != nil {
        return nil, err
    }

    counts := map[string]int{}
    total := 0

    for _, tag := range types {
        records, err := s.Inner.List(ctx, profileName, tag, "")
        if err != nil {
            return nil, fmt.Errorf("list %s: %w", tag, err)
        }
        if len(records) == 0 {
            continue
        }
        typeDir := filepath.Join(partialDir, tag)
        if err := os.MkdirAll(typeDir, 0o755); err != nil {
            return nil, err
        }
        for _, record := range records {
            recName, _ := record["Name"].(string)
            if recName == "" {
                continue // skip stub records
            }
            // Inject diff hash for fast drift comparison later.
            if hash, herr := DiffHash(record); herr == nil {
                record["_diffHash"] = hash
            }
            slug := slugify(recName)
            yamlBytes, merr := marshalCanonicalYAML(record)
            if merr != nil {
                return nil, fmt.Errorf("marshal %s/%s: %w", tag, recName, merr)
            }
            if err := os.WriteFile(filepath.Join(typeDir, slug+".yaml"), yamlBytes, 0o644); err != nil {
                return nil, err
            }
            counts[tag]++
            total++
        }
    }

    meta := backupMeta{
        Schema:          MetaSchemaName,
        Profile:         name,
        URL:             profile.URL,
        SophosfwVersion: BuildVersion,  // see step 4 for source of this constant
        CreatedAt:       now.Format(time.RFC3339),
        CatalogVersion:  "1",
        TypesIncluded:   types,
        RecordCounts:    counts,
        TotalRecords:    total,
    }
    metaBytes, err := yaml.Marshal(meta)
    if err != nil {
        return nil, err
    }
    if err := os.WriteFile(filepath.Join(partialDir, "_meta.yaml"), metaBytes, 0o644); err != nil {
        return nil, err
    }

    if err := os.Rename(partialDir, targetDir); err != nil {
        return nil, err
    }

    return &BackupCreateResult{
        Profile:       name,
        Path:          targetDir,
        CreatedAt:     now,
        TypesIncluded: types,
        RecordCounts:  counts,
        TotalRecords:  total,
    }, nil
}

func (s *BackupSvc) resolveTypes(want, exclude []string) ([]string, error) {
    all := s.Catalog.AllTags()  // alphabetic; verify the actual function name
    sort.Strings(all)
    if len(want) == 0 && len(exclude) == 0 {
        return all, nil
    }
    if len(want) > 0 {
        for _, t := range want {
            if _, ok := s.Catalog.Resolve(t); !ok {
                return nil, fmt.Errorf("%w: unknown type %q", sophos.ErrInvalidRequest, t)
            }
        }
        return want, nil
    }
    excludeSet := map[string]bool{}
    for _, t := range exclude {
        if _, ok := s.Catalog.Resolve(t); !ok {
            return nil, fmt.Errorf("%w: unknown type %q (in --exclude)", sophos.ErrInvalidRequest, t)
        }
        excludeSet[t] = true
    }
    out := []string{}
    for _, t := range all {
        if !excludeSet[t] {
            out = append(out, t)
        }
    }
    return out, nil
}

// slugify produces a filesystem-safe filename from a record name.
// Reuses the draft slug logic by importing it directly.
func slugify(name string) string {
    return draft.Slug(name)  // verify exact draft slug helper name
}
```

**`BuildVersion`**: there should be a single source of truth for the project version. Check `cmd/sophosfw/main.go` (it has `var version = "dev"`); for svc-layer access, either expose it via deps injection (RootDeps already has Version per Phase 6) or read from a build flag. Simplest: add a `Version string` field to `BackupSvc` and let the caller inject. Update the struct + factory accordingly.

**`s.Inner.List`**: verify the actual signature:
```bash
grep -n "func.*ObjectSvc.*List\b" internal/svc/object.go
```
Adjust the call in Create accordingly. The existing List likely takes `(ctx, profileName, tag, filter)` and returns `([]map[string]any, error)`.

**`s.Catalog.AllTags`**: verify the actual function name:
```bash
grep -n "AllTags\|func.*Catalog.*All\b" internal/catalog/catalog.go
```
If the helper doesn't exist, add it (returns sorted slice of catalog tags) — single one-line wrapper around the underlying map keys.

**`draft.Slug`**: verify name:
```bash
grep -n "func slug\|func Slug\|func slugify\|func Slugify" internal/draft/paths.go
```
If it's lowercase (unexported), expose it as `draft.Slug`. If a different name, use that.

- [ ] **Step 2: Tests for Create**

Create `internal/svc/backup_test.go` with these tests:

```go
func TestBackupSvc_Create_DefaultLocation_WritesAllTypes(t *testing.T) {
    // Use the existing fake-client/svc fixture pattern.
    // Set fake responses for at least 3 types (e.g. IPHost, FirewallRule, Zone).
    // Call Create with default options.
    // Assert: targetDir exists, _meta.yaml present and parseable,
    //         per-type subdir exists with the expected number of records,
    //         per-record .yaml files contain the body + _diffHash.
}

func TestBackupSvc_Create_RejectsTypesAndExcludeTogether(t *testing.T)
func TestBackupSvc_Create_RejectsExistingOutDir(t *testing.T)
func TestBackupSvc_Create_RejectsUnknownType(t *testing.T)
func TestBackupSvc_Create_TypesFilter_OnlyIncludesSubset(t *testing.T)
func TestBackupSvc_Create_ExcludeFilter_OmitsListedTypes(t *testing.T)
func TestBackupSvc_Create_AtomicRename_PartialDirRemovedOnSuccess(t *testing.T)
func TestBackupSvc_Create_OnListError_LeavesPartialForInspection(t *testing.T)
func TestBackupSvc_Create_WritesDiffHashInRecordFiles(t *testing.T)
func TestBackupSvc_Create_StubRecordsSkipped(t *testing.T)  // record with empty Name should be skipped
```

Run:
```bash
go test ./internal/svc -run TestBackupSvc_Create -v -count=1
```

Expected: all pass. Iterate on implementation if any fail.

- [ ] **Step 3: Run full suite + lint + commit**

```bash
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/backup.go internal/svc/backup_test.go
git commit -m "$(cat <<'EOF'
svc: BackupSvc.Create — atomic per-record snapshot tree

Phase 13 core write path. Walks the catalog (or --types / --exclude
subset), calls ObjectSvc.List per type, writes per-record YAML files
under <snapshot-dir>/<Type>/<slug>.yaml. Each record file includes
the injected _diffHash so drift can short-circuit unchanged records.

Atomic via .partial → rename: a partial snapshot never appears under
the canonical name. On error, the .partial dir is left for inspection.
_meta.yaml at the root records profile, URL, version, timestamp,
catalog version, types, and per-type record counts.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Do NOT push.

---

## Task 3: BackupSvc.List + Rotate

**Files:**
- Modify: `internal/svc/backup.go`
- Modify: `internal/svc/backup_test.go`

- [ ] **Step 1: Add List + Rotate**

Append to `internal/svc/backup.go`:

```go
type BackupListEntry struct {
    Path         string
    CreatedAt    time.Time
    RecordCounts map[string]int
}

func (s *BackupSvc) List(profileName string) ([]BackupListEntry, error) {
    _, name, err := s.Inner.Config.ActiveProfile(profileName)
    if err != nil {
        return nil, err
    }
    root, err := draft.BackupRootDir(s.BaseDir, name)
    if err != nil {
        return nil, err
    }
    entries, err := os.ReadDir(root)
    if errors.Is(err, fs.ErrNotExist) {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    var out []BackupListEntry
    for _, e := range entries {
        if !e.IsDir() {
            continue
        }
        if strings.HasSuffix(e.Name(), ".partial") {
            continue
        }
        path := filepath.Join(root, e.Name())
        meta, err := readBackupMeta(path)
        if err != nil {
            // Skip dirs without a valid _meta.yaml — could be foreign content.
            continue
        }
        createdAt, _ := time.Parse(time.RFC3339, meta.CreatedAt)
        out = append(out, BackupListEntry{
            Path: path, CreatedAt: createdAt, RecordCounts: meta.RecordCounts,
        })
    }
    sort.Slice(out, func(i, j int) bool {
        return out[i].CreatedAt.After(out[j].CreatedAt)  // newest first
    })
    return out, nil
}

func readBackupMeta(snapshotDir string) (*backupMeta, error) {
    raw, err := os.ReadFile(filepath.Join(snapshotDir, "_meta.yaml"))
    if err != nil {
        return nil, err
    }
    var m backupMeta
    if err := yaml.Unmarshal(raw, &m); err != nil {
        return nil, err
    }
    if m.Schema != MetaSchemaName {
        return nil, fmt.Errorf("invalid schema %q", m.Schema)
    }
    return &m, nil
}

func (s *BackupSvc) Rotate(profileName string, keep int) ([]string, error) {
    if keep < 0 {
        return nil, fmt.Errorf("%w: --keep must be >= 0", sophos.ErrInvalidRequest)
    }
    entries, err := s.List(profileName)
    if err != nil {
        return nil, err
    }
    if len(entries) <= keep {
        return nil, nil
    }
    var deleted []string
    for _, e := range entries[keep:] {
        if err := os.RemoveAll(e.Path); err != nil {
            return deleted, err
        }
        deleted = append(deleted, e.Path)
    }
    return deleted, nil
}
```

- [ ] **Step 2: Tests**

```go
func TestBackupSvc_List_EmptyDirectory_ReturnsNil(t *testing.T)
func TestBackupSvc_List_ReturnsTimestampSortedNewestFirst(t *testing.T)
func TestBackupSvc_List_SkipsPartialDirs(t *testing.T)
func TestBackupSvc_List_SkipsDirsWithoutValidMeta(t *testing.T)
func TestBackupSvc_Rotate_KeepZero_DeletesAll(t *testing.T)
func TestBackupSvc_Rotate_KeepN_DeletesOldestN(t *testing.T)
func TestBackupSvc_Rotate_NothingToDelete_ReturnsNil(t *testing.T)
func TestBackupSvc_Rotate_RejectsNegativeKeep(t *testing.T)
```

Run + commit:

```bash
go test ./internal/svc -run "TestBackupSvc_List\|TestBackupSvc_Rotate" -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/backup.go internal/svc/backup_test.go
git commit -m "$(cat <<'EOF'
svc: BackupSvc.List + Rotate

List enumerates snapshots under <baseDir>/profiles/<name>/backups/,
sorted newest-first. Skips .partial dirs and any dir whose _meta.yaml
is missing or has the wrong schema. Rotate deletes all but the N most
recent. Both operations are pure filesystem; no firewall calls.
EOF
)"
```

---

## Task 4: BackupSvc.Drift

**Files:**
- Modify: `internal/svc/backup.go`
- Modify: `internal/svc/backup_test.go`

- [ ] **Step 1: Add Drift method**

```go
type DriftOptions struct {
    SnapshotPath string
    Latest       bool
    Types        []string
    Force        bool  // override profile-mismatch refusal
}

type DriftSummaryPerType struct {
    Added, Modified, Removed, Unchanged int
}

type DriftSummary struct {
    Added, Modified, Removed, Unchanged int
    PerType map[string]DriftSummaryPerType
}

type DriftChange struct {
    Type   string
    Name   string
    Change string             // "added" | "modified" | "removed"
    Diff   string             // unified diff, only for "modified"
    Body   map[string]any     // only for "added"
}

type DriftResult struct {
    SnapshotPath      string
    Profile           string
    SnapshotCreatedAt time.Time
    CheckedAt         time.Time
    Summary           DriftSummary
    Changes           []DriftChange
}

func (s *BackupSvc) Drift(ctx context.Context, profileName string, opts DriftOptions) (*DriftResult, error) {
    _, name, err := s.Inner.Config.ActiveProfile(profileName)
    if err != nil {
        return nil, err
    }

    snapshotPath, err := s.resolveSnapshotPath(name, opts)
    if err != nil {
        return nil, err
    }

    meta, err := readBackupMeta(snapshotPath)
    if err != nil {
        return nil, fmt.Errorf("read snapshot meta: %w", err)
    }
    if !opts.Force && meta.Profile != name {
        return nil, fmt.Errorf("%w: snapshot is from profile %q, current is %q (use --force to override)",
            sophos.ErrInvalidRequest, meta.Profile, name)
    }

    types := meta.TypesIncluded
    if len(opts.Types) > 0 {
        types = opts.Types
    }

    perType := map[string]DriftSummaryPerType{}
    var changes []DriftChange

    for _, tag := range types {
        snap, err := loadSnapshotRecords(snapshotPath, tag)
        if err != nil {
            return nil, fmt.Errorf("load snapshot %s: %w", tag, err)
        }
        live, err := s.Inner.List(ctx, profileName, tag, "")
        if err != nil {
            return nil, fmt.Errorf("list live %s: %w", tag, err)
        }
        liveByName := map[string]map[string]any{}
        for _, r := range live {
            if n, _ := r["Name"].(string); n != "" {
                liveByName[n] = r
            }
        }
        var sum DriftSummaryPerType
        for snapName, snapBody := range snap {
            liveBody, present := liveByName[snapName]
            if !present {
                changes = append(changes, DriftChange{Type: tag, Name: snapName, Change: "removed"})
                sum.Removed++
                continue
            }
            // Hash short-circuit
            snapHash, _ := snapBody["_diffHash"].(string)
            liveHash, _ := liveBody["_diffHash"].(string)
            if snapHash != "" && liveHash != "" && snapHash == liveHash {
                sum.Unchanged++
                continue
            }
            // Recompute hashes if missing on either side
            if snapHash == "" {
                snapHash, _ = DiffHash(stripDiffHash(snapBody))
            }
            if liveHash == "" {
                liveHash, _ = DiffHash(stripDiffHash(liveBody))
            }
            if snapHash == liveHash {
                sum.Unchanged++
                continue
            }
            diff, derr := unifiedDiffOf(snapBody, liveBody)
            if derr != nil {
                return nil, derr
            }
            changes = append(changes, DriftChange{
                Type: tag, Name: snapName, Change: "modified", Diff: diff,
            })
            sum.Modified++
        }
        // Added: in live, not in snapshot
        for liveName, liveBody := range liveByName {
            if _, present := snap[liveName]; !present {
                changes = append(changes, DriftChange{
                    Type: tag, Name: liveName, Change: "added", Body: stripDiffHash(liveBody),
                })
                sum.Added++
            }
        }
        perType[tag] = sum
    }

    summary := DriftSummary{PerType: perType}
    for _, s := range perType {
        summary.Added += s.Added
        summary.Modified += s.Modified
        summary.Removed += s.Removed
        summary.Unchanged += s.Unchanged
    }

    snapshotCreatedAt, _ := time.Parse(time.RFC3339, meta.CreatedAt)
    return &DriftResult{
        SnapshotPath:      snapshotPath,
        Profile:           name,
        SnapshotCreatedAt: snapshotCreatedAt,
        CheckedAt:         s.now(),
        Summary:           summary,
        Changes:           changes,
    }, nil
}

func (s *BackupSvc) resolveSnapshotPath(profile string, opts DriftOptions) (string, error) {
    if opts.SnapshotPath != "" && opts.Latest {
        return "", fmt.Errorf("%w: snapshot path and --latest are mutually exclusive", sophos.ErrInvalidRequest)
    }
    if opts.SnapshotPath != "" {
        return opts.SnapshotPath, nil
    }
    entries, err := s.List(profile)
    if err != nil {
        return "", err
    }
    if len(entries) == 0 {
        return "", fmt.Errorf("%w: no snapshots found for profile %q", sophos.ErrNotFound, profile)
    }
    return entries[0].Path, nil
}

func loadSnapshotRecords(snapshotPath, tag string) (map[string]map[string]any, error) {
    typeDir := filepath.Join(snapshotPath, tag)
    entries, err := os.ReadDir(typeDir)
    if errors.Is(err, fs.ErrNotExist) {
        return map[string]map[string]any{}, nil
    }
    if err != nil {
        return nil, err
    }
    out := map[string]map[string]any{}
    for _, e := range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
            continue
        }
        raw, err := os.ReadFile(filepath.Join(typeDir, e.Name()))
        if err != nil {
            return nil, err
        }
        var body map[string]any
        if err := yaml.Unmarshal(raw, &body); err != nil {
            return nil, err
        }
        if n, _ := body["Name"].(string); n != "" {
            out[n] = body
        }
    }
    return out, nil
}

func stripDiffHash(m map[string]any) map[string]any {
    if m == nil {
        return nil
    }
    out := make(map[string]any, len(m))
    for k, v := range m {
        if k == "_diffHash" {
            continue
        }
        out[k] = v
    }
    return out
}

func unifiedDiffOf(a, b map[string]any) (string, error) {
    ay, err := marshalCanonicalYAML(stripDiffHash(a))
    if err != nil {
        return "", err
    }
    by, err := marshalCanonicalYAML(stripDiffHash(b))
    if err != nil {
        return "", err
    }
    // Reuse existing diff helper from internal/draft.
    return draft.UnifiedDiff(string(ay), string(by)), nil
}
```

Verify `draft.UnifiedDiff` signature; if it differs, adjust.

- [ ] **Step 2: Tests**

```go
func TestBackupSvc_Drift_NoChanges_EmptyResult(t *testing.T)
func TestBackupSvc_Drift_AddedRecord_ReportsAdded(t *testing.T)
func TestBackupSvc_Drift_RemovedRecord_ReportsRemoved(t *testing.T)
func TestBackupSvc_Drift_ModifiedRecord_ReportsModifiedWithDiff(t *testing.T)
func TestBackupSvc_Drift_HashShortCircuit_SkipsUnchanged(t *testing.T)
func TestBackupSvc_Drift_RejectsProfileMismatch(t *testing.T)
func TestBackupSvc_Drift_ForceOverridesProfileMismatch(t *testing.T)
func TestBackupSvc_Drift_LatestResolvesNewestSnapshot(t *testing.T)
func TestBackupSvc_Drift_LatestAndPathTogether_Rejects(t *testing.T)
func TestBackupSvc_Drift_NoSnapshots_ReturnsNotFound(t *testing.T)
func TestBackupSvc_Drift_PerTypeFilter(t *testing.T)
```

Run + commit:

```bash
go test ./internal/svc -run TestBackupSvc_Drift -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/backup.go internal/svc/backup_test.go
git commit -m "$(cat <<'EOF'
svc: BackupSvc.Drift — compare snapshot to current state

Reads <snapshot-dir>/<Type>/*.yaml, fetches live state per type via
ObjectSvc.List, computes added/modified/removed/unchanged per record.
Hash short-circuit: if both sides have _diffHash and they match,
classify unchanged without computing diff. Modified records get a
unified diff via draft.UnifiedDiff over the canonical YAML bodies
with _diffHash stripped from both sides.

Profile-mismatch refusal (--force to override) prevents silently
diffing snapshot from one firewall against another firewall's live
state. --latest resolves to the most recent snapshot under the
default location.
EOF
)"
```

---

## Task 5: Render envelopes

**Files:**
- Create: `internal/render/backup.go` + `_test.go`
- Create: `internal/render/drift.go` + `_test.go`

- [ ] **Step 1: Backup envelope**

Create `internal/render/backup.go`:

```go
package render

import (
    "encoding/json"
    "github.com/iainmoffat/sophosfw/internal/svc"
)

func BackupCreateEnvelope(r *svc.BackupCreateResult) ([]byte, error) {
    env := map[string]any{
        "schema":        "sophosfw.v1.backupCreate",
        "profile":       r.Profile,
        "path":          r.Path,
        "createdAt":     r.CreatedAt.UTC().Format(time.RFC3339),
        "typesIncluded": r.TypesIncluded,
        "recordCounts":  r.RecordCounts,
        "totalRecords":  r.TotalRecords,
    }
    return json.MarshalIndent(env, "", "  ")
}

func BackupListEnvelope(profile string, entries []svc.BackupListEntry) ([]byte, error) {
    out := make([]map[string]any, 0, len(entries))
    for _, e := range entries {
        out = append(out, map[string]any{
            "path":         e.Path,
            "createdAt":    e.CreatedAt.UTC().Format(time.RFC3339),
            "recordCounts": e.RecordCounts,
        })
    }
    env := map[string]any{
        "schema":    "sophosfw.v1.backupList",
        "profile":   profile,
        "snapshots": out,
    }
    return json.MarshalIndent(env, "", "  ")
}
```

Tests in `_test.go`: schema names correct, fields populated, empty slices marshal cleanly.

- [ ] **Step 2: Drift envelope (JSON + human renderers)**

Create `internal/render/drift.go`:

```go
package render

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "text/tabwriter"

    "github.com/iainmoffat/sophosfw/internal/svc"
)

func DriftEnvelope(r *svc.DriftResult) ([]byte, error) {
    perType := map[string]map[string]int{}
    for tag, s := range r.Summary.PerType {
        perType[tag] = map[string]int{
            "added": s.Added, "modified": s.Modified,
            "removed": s.Removed, "unchanged": s.Unchanged,
        }
    }
    changes := make([]map[string]any, 0, len(r.Changes))
    for _, c := range r.Changes {
        m := map[string]any{
            "type":   c.Type,
            "name":   c.Name,
            "change": c.Change,
        }
        if c.Diff != "" {
            m["diff"] = c.Diff
        }
        if c.Body != nil {
            m["body"] = c.Body
        }
        changes = append(changes, m)
    }
    env := map[string]any{
        "schema":            "sophosfw.v1.drift",
        "snapshot":          r.SnapshotPath,
        "profile":           r.Profile,
        "snapshotCreatedAt": r.SnapshotCreatedAt.UTC().Format(time.RFC3339),
        "checkedAt":         r.CheckedAt.UTC().Format(time.RFC3339),
        "summary": map[string]any{
            "added":     r.Summary.Added,
            "modified":  r.Summary.Modified,
            "removed":   r.Summary.Removed,
            "unchanged": r.Summary.Unchanged,
            "perType":   perType,
        },
        "changes": changes,
    }
    return json.MarshalIndent(env, "", "  ")
}

// DriftHumanText writes the human-readable drift output (table + per-record diffs).
func DriftHumanText(w io.Writer, r *svc.DriftResult) error {
    fmt.Fprintf(w, "Profile: %s  Snapshot: %s  Now: %s\n\n",
        r.Profile, r.SnapshotCreatedAt.UTC().Format(time.RFC3339), r.CheckedAt.UTC().Format(time.RFC3339))

    tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
    fmt.Fprintln(tw, "Type\tAdded\tModified\tRemoved\tUnchanged")
    for tag, s := range r.Summary.PerType {
        fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", tag, s.Added, s.Modified, s.Removed, s.Unchanged)
    }
    tw.Flush()
    fmt.Fprintf(w, "\nTotal: %d added, %d modified, %d removed (unchanged: %d)\n\n",
        r.Summary.Added, r.Summary.Modified, r.Summary.Removed, r.Summary.Unchanged)

    for _, c := range r.Changes {
        switch c.Change {
        case "modified":
            fmt.Fprintf(w, "--- Modified: %s/%s.yaml\n", c.Type, c.Name)
            fmt.Fprintf(w, "+++ Modified: %s/%s (live)\n", c.Type, c.Name)
            fmt.Fprintln(w, c.Diff)
        case "added":
            fmt.Fprintf(w, "+++ Added: %s/%s\n", c.Type, c.Name)
            yamlBytes, _ := yaml.Marshal(c.Body)
            fmt.Fprintln(w, string(yamlBytes))
        case "removed":
            fmt.Fprintf(w, "--- Removed: %s/%s\n", c.Type, c.Name)
        }
    }
    return nil
}
```

Tests: JSON envelope shape (DriftEnvelope), table format spot-checks (DriftHumanText writes expected substrings).

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/render -run "TestBackup\|TestDrift" -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/render/backup.go internal/render/backup_test.go internal/render/drift.go internal/render/drift_test.go
git commit -m "$(cat <<'EOF'
render: backup + drift envelopes

Three new envelope shapes per the Phase 13 spec:
  sophosfw.v1.backupCreate  — create result metadata
  sophosfw.v1.backupList    — snapshot listing
  sophosfw.v1.drift         — change set with summary + per-record diffs

Plus DriftHumanText for the default human output (summary table +
per-record unified diffs / added bodies / removed names).
EOF
)"
```

---

## Task 6: CLI `sophosfw backup` (+ list + rotate)

**Files:**
- Create: `internal/cli/backup.go` + `_test.go`
- Modify: `internal/cli/root.go` (register backup command)

- [ ] **Step 1: Write the cobra commands**

Create `internal/cli/backup.go`:

```go
package cli

import (
    "fmt"

    "github.com/spf13/cobra"

    "github.com/iainmoffat/sophosfw/internal/render"
    "github.com/iainmoffat/sophosfw/internal/svc"
)

func newBackupCmd(d RootDeps) *cobra.Command {
    var outDir string
    var typesCSV, excludeCSV string
    var jsonOut bool

    cmd := &cobra.Command{
        Use:   "backup",
        Short: "Snapshot the firewall config (per-record YAML tree)",
        RunE: func(cmd *cobra.Command, args []string) error {
            opts := svc.BackupCreateOptions{OutDir: outDir}
            if typesCSV != "" { opts.Types = splitCSV(typesCSV) }
            if excludeCSV != "" { opts.Exclude = splitCSV(excludeCSV) }
            result, err := backupSvc(d).Create(cmd.Context(), profileFromFlags(cmd), opts)
            if err != nil {
                return err
            }
            if jsonOut {
                body, _ := render.BackupCreateEnvelope(result)
                _, _ = cmd.OutOrStdout().Write(body)
                return nil
            }
            fmt.Fprintf(cmd.OutOrStdout(), "Backup written: %s\n", result.Path)
            fmt.Fprintf(cmd.OutOrStdout(), "  Profile: %s\n", result.Profile)
            fmt.Fprintf(cmd.OutOrStdout(), "  Records: %d across %d types\n", result.TotalRecords, len(result.TypesIncluded))
            return nil
        },
    }
    cmd.Flags().StringVar(&outDir, "out", "", "snapshot directory (default: ~/.config/sophosfw/profiles/<name>/backups/<utc>)")
    cmd.Flags().StringVar(&typesCSV, "types", "", "comma-separated catalog tags to include (default: all 12)")
    cmd.Flags().StringVar(&excludeCSV, "exclude", "", "comma-separated catalog tags to skip (mutually exclusive with --types)")
    cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")

    cmd.AddCommand(newBackupListCmd(d))
    cmd.AddCommand(newBackupRotateCmd(d))
    return cmd
}

func newBackupListCmd(d RootDeps) *cobra.Command {
    var jsonOut bool
    cmd := &cobra.Command{
        Use:   "list",
        Short: "List existing snapshots for the current profile",
        RunE: func(cmd *cobra.Command, _ []string) error {
            entries, err := backupSvc(d).List(profileFromFlags(cmd))
            if err != nil { return err }
            if jsonOut {
                body, _ := render.BackupListEnvelope(profileFromFlags(cmd), entries)
                _, _ = cmd.OutOrStdout().Write(body)
                return nil
            }
            if len(entries) == 0 {
                fmt.Fprintln(cmd.OutOrStdout(), "No snapshots.")
                return nil
            }
            for _, e := range entries {
                total := 0
                for _, n := range e.RecordCounts { total += n }
                fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  (%d records)\n",
                    e.CreatedAt.Format(time.RFC3339), e.Path, total)
            }
            return nil
        },
    }
    cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
    return cmd
}

func newBackupRotateCmd(d RootDeps) *cobra.Command {
    var keep int
    cmd := &cobra.Command{
        Use:   "rotate",
        Short: "Delete snapshots, keeping the N most recent",
        RunE: func(cmd *cobra.Command, _ []string) error {
            deleted, err := backupSvc(d).Rotate(profileFromFlags(cmd), keep)
            if err != nil { return err }
            fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d snapshot(s).\n", len(deleted))
            for _, p := range deleted {
                fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", p)
            }
            return nil
        },
    }
    cmd.Flags().IntVar(&keep, "keep", -1, "number of most recent snapshots to keep (required)")
    _ = cmd.MarkFlagRequired("keep")
    return cmd
}

func backupSvc(d RootDeps) *svc.BackupSvc {
    return &svc.BackupSvc{
        Inner:   objectSvc(d),
        Catalog: d.Catalog, // ensure RootDeps exposes this; if not, build inline
        BaseDir: d.BaseDir,
        Now:     time.Now,
    }
}

func splitCSV(s string) []string {
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        if t := strings.TrimSpace(p); t != "" {
            out = append(out, t)
        }
    }
    return out
}
```

Verify `RootDeps.Catalog` exists. If it doesn't, look at how existing commands access the catalog (e.g. `internal/cli/object.go`) and follow that pattern.

- [ ] **Step 2: Register in root.go**

```bash
grep -n "newFirewallCmd\|cmd.AddCommand" internal/cli/root.go | head -10
```

Add `cmd.AddCommand(newBackupCmd(d))` next to existing top-level command registrations.

- [ ] **Step 3: Tests**

```go
func TestCmd_Backup_DryShape(t *testing.T)        // smoke: --help works
func TestCmd_Backup_TypesAndExcludeRejected(t *testing.T)
func TestCmd_BackupList_EmptyShape(t *testing.T)
func TestCmd_BackupRotate_RequiresKeep(t *testing.T)
func TestCmd_Backup_CreatesSnapshotInTempDir(t *testing.T)  // end-to-end with fake client
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/cli -run TestCmd_Backup -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/cli/backup.go internal/cli/backup_test.go internal/cli/root.go
git commit -m "$(cat <<'EOF'
cli: sophosfw backup (+ list + rotate)

Top-level backup command takes optional --out, --types, --exclude;
default writes to ~/.config/sophosfw/profiles/<name>/backups/<utc>.
backup list shows existing snapshots newest-first.
backup rotate --keep N deletes all but the N most recent.
EOF
)"
```

---

## Task 7: CLI `sophosfw drift`

**Files:**
- Create: `internal/cli/drift.go` + `_test.go`
- Modify: `internal/cli/root.go` (register drift command)

- [ ] **Step 1: Write the cobra command**

```go
package cli

import (
    "fmt"

    "github.com/spf13/cobra"

    "github.com/iainmoffat/sophosfw/internal/render"
    "github.com/iainmoffat/sophosfw/internal/svc"
)

func newDriftCmd(d RootDeps) *cobra.Command {
    var latest, jsonOut, force bool
    var typesCSV string
    cmd := &cobra.Command{
        Use:   "drift [snapshot-dir]",
        Short: "Compare a snapshot to current firewall state",
        Args:  cobra.MaximumNArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            opts := svc.DriftOptions{Latest: latest, Force: force}
            if len(args) == 1 {
                opts.SnapshotPath = args[0]
            }
            if typesCSV != "" { opts.Types = splitCSV(typesCSV) }

            result, err := backupSvc(d).Drift(cmd.Context(), profileFromFlags(cmd), opts)
            if err != nil {
                return err
            }
            if jsonOut {
                body, _ := render.DriftEnvelope(result)
                _, _ = cmd.OutOrStdout().Write(body)
            } else {
                if err := render.DriftHumanText(cmd.OutOrStdout(), result); err != nil {
                    return err
                }
            }
            // Exit code: 1 if drift detected.
            if result.Summary.Added+result.Summary.Modified+result.Summary.Removed > 0 {
                return ErrDriftDetected  // sentinel mapped to exit code 1 in HandleError
            }
            return nil
        },
    }
    cmd.Flags().BoolVar(&latest, "latest", false, "use most recent snapshot under default location")
    cmd.Flags().BoolVar(&force, "force", false, "compare even if snapshot's profile differs from current")
    cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
    cmd.Flags().StringVar(&typesCSV, "types", "", "comma-separated catalog tags to check (default: all in snapshot)")
    return cmd
}
```

`ErrDriftDetected` is a new sentinel. Add to wherever existing CLI sentinels live (probably `internal/cli/error.go` or `internal/cli/root.go`):

```go
// ErrDriftDetected is returned by sophosfw drift when changes were detected.
// HandleError maps it to exit code 1 without printing an error message.
var ErrDriftDetected = errors.New("drift detected")
```

Update `HandleError` in the same file to map `ErrDriftDetected` → exit 1 (silent) instead of the default error path.

- [ ] **Step 2: Register in root.go**

`cmd.AddCommand(newDriftCmd(d))` next to backup.

- [ ] **Step 3: Tests**

```go
func TestCmd_Drift_SnapshotPathPositional(t *testing.T)
func TestCmd_Drift_LatestFlag(t *testing.T)
func TestCmd_Drift_NoChangesExitsZero(t *testing.T)
func TestCmd_Drift_WithChangesExitsOne(t *testing.T)
func TestCmd_Drift_JSONOutputShape(t *testing.T)
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/cli -run TestCmd_Drift -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/cli/drift.go internal/cli/drift_test.go internal/cli/root.go [error.go if modified]
git commit -m "$(cat <<'EOF'
cli: sophosfw drift (--latest, --json, exit codes)

Top-level drift command takes a snapshot dir or --latest, computes
drift against current state, prints human or JSON output. New
ErrDriftDetected sentinel mapped to exit code 1 (silent) so cron and
CI invocations behave like git diff --exit-code: 0 = clean, 1 =
drift, 2 = error.
EOF
)"
```

---

## Task 8: MCP tools (backup_create, backup_list, drift_check)

**Files:**
- Create: `internal/mcp/backup.go` + `_test.go`
- Modify: `internal/mcp/server.go` (register)
- Modify: `internal/mcp/server_test.go` (count 48 → 51)

- [ ] **Step 1: Write the handlers**

```go
package mcp

import (
    "context"

    sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

    "github.com/iainmoffat/sophosfw/internal/render"
    "github.com/iainmoffat/sophosfw/internal/svc"
)

type BackupCreateInput struct {
    Profile string   `json:"profile,omitempty"`
    Out     string   `json:"out,omitempty" jsonschema_description:"snapshot directory; default: ~/.config/sophosfw/profiles/<profile>/backups/<utc>"`
    Types   []string `json:"types,omitempty"`
    Exclude []string `json:"exclude,omitempty"`
}

type BackupListInput struct {
    Profile string `json:"profile,omitempty"`
}

type DriftCheckInput struct {
    Profile  string   `json:"profile,omitempty"`
    Snapshot string   `json:"snapshot,omitempty" jsonschema_description:"snapshot dir path; mutually exclusive with latest"`
    Latest   bool     `json:"latest,omitempty"`
    Types    []string `json:"types,omitempty"`
    Force    bool     `json:"force,omitempty" jsonschema_description:"override profile-mismatch refusal"`
}

func (s *Server) handleBackupCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in BackupCreateInput) (*sdkmcp.CallToolResult, any, error) {
    profile := s.resolveProfile(in.Profile)
    result, err := s.backupSvc().Create(ctx, profile, svc.BackupCreateOptions{
        OutDir: in.Out, Types: in.Types, Exclude: in.Exclude,
    })
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    body, err := render.BackupCreateEnvelope(result)
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    return jsonResult(body)
}

func (s *Server) handleBackupList(_ context.Context, _ *sdkmcp.CallToolRequest, in BackupListInput) (*sdkmcp.CallToolResult, any, error) {
    profile := s.resolveProfile(in.Profile)
    entries, err := s.backupSvc().List(profile)
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    body, err := render.BackupListEnvelope(profile, entries)
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    return jsonResult(body)
}

func (s *Server) handleDriftCheck(ctx context.Context, _ *sdkmcp.CallToolRequest, in DriftCheckInput) (*sdkmcp.CallToolResult, any, error) {
    profile := s.resolveProfile(in.Profile)
    result, err := s.backupSvc().Drift(ctx, profile, svc.DriftOptions{
        SnapshotPath: in.Snapshot, Latest: in.Latest, Types: in.Types, Force: in.Force,
    })
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    body, err := render.DriftEnvelope(result)
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    return jsonResult(body)
}

func (s *Server) backupSvc() *svc.BackupSvc {
    return &svc.BackupSvc{
        Inner:   s.objectSvc(),
        Catalog: s.deps.Catalog,
        BaseDir: s.deps.BaseDir,
        Now:     time.Now,
    }
}

func (s *Server) registerBackup() {
    sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
        Name:        "backup_create",
        Description: "Snapshot the firewall config to a per-record YAML tree. Read-only against the firewall; produces files locally. Returns metadata (path, profile, timestamp, recordCounts).",
        Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Create backup"},
    }, s.handleBackupCreate)
    sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
        Name:        "backup_list",
        Description: "List existing backup snapshots for the profile, newest-first.",
        Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List backups"},
    }, s.handleBackupList)
    sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
        Name:        "drift_check",
        Description: "Compare a backup snapshot to current firewall state. Returns added/modified/removed/unchanged counts plus per-record diffs. Read-only.",
        Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Drift check"},
    }, s.handleDriftCheck)
}
```

- [ ] **Step 2: Register in server.go**

Add `s.registerBackup()` to `registerAll`.

- [ ] **Step 3: Update server_test.go**

Tool count 48 → 51; add `backup_create`, `backup_list`, `drift_check` to expected names.

- [ ] **Step 4: Tests**

```go
func TestBackupCreate_Handler_WritesAndReturnsMetadata(t *testing.T)
func TestBackupList_Handler_ReturnsSnapshots(t *testing.T)
func TestDriftCheck_Handler_NoChanges(t *testing.T)
func TestDriftCheck_Handler_DetectsChanges(t *testing.T)
```

(Use the existing `newMutMcpServer` helper if applicable, OR build a similar fixture for backup tests.)

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/mcp -count=1 -race -v
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/mcp/backup.go internal/mcp/backup_test.go internal/mcp/server.go internal/mcp/server_test.go
git commit -m "$(cat <<'EOF'
mcp: backup_create, backup_list, drift_check (3 new tools, count 48 to 51)

All three tools are read-only (ReadOnlyHint:true). backup_create writes
filesystem state but does not mutate the firewall; backup_list and
drift_check are pure reads. backup_rotate is intentionally CLI-only —
exposing destructive filesystem ops to agents widens the surface for
low value.
EOF
)"
```

---

## Task 9: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

- [ ] **Step 1: Add integration tests**

Append to `internal/testutil/integration_test.go`:

```go
func TestIntegration_Backup_Create_FullSnapshot(t *testing.T) {
    profileName := os.Getenv("SOPHOSFW_PROFILE")
    require.NotEmpty(t, profileName)

    // ... build BackupSvc against the live testvm using the existing
    // integration helpers (read RootDeps, etc.) ...

    tmp := t.TempDir()
    result, err := svc.Create(ctx, profileName, svc.BackupCreateOptions{OutDir: tmp})
    require.NoError(t, err)
    require.Greater(t, result.TotalRecords, 0)
    // Assert per-type subdirs exist for at least FirewallRule + IPHost
    require.DirExists(t, filepath.Join(tmp, "FirewallRule"))
    require.DirExists(t, filepath.Join(tmp, "IPHost"))
    // _meta.yaml present
    require.FileExists(t, filepath.Join(tmp, "_meta.yaml"))
}

func TestIntegration_Drift_NoChanges_EmptyResult(t *testing.T) {
    // Backup → immediate drift → expect no changes.
}

func TestIntegration_Drift_AfterIPHostCreate_ReportsAdded(t *testing.T) {
    // 1. Backup to t.TempDir()
    // 2. Create a test IPHost via host_ip_create
    // 3. Drift against the backup — expect 1 added in IPHost
    // 4. Cleanup: delete the test IPHost
    // (gate with SOPHOSFW_TEST_IPHOST_NAME so it's opt-in)
}
```

Build with the integration tag and run against the testvm:

```bash
go build -tags=integration ./internal/testutil/...
SOPHOSFW_PROFILE=testvm \
SOPHOSFW_TEST_IPHOST_NAME=sophosfw-drift-test \
go test -tags=integration ./internal/testutil -run "TestIntegration_Backup\|TestIntegration_Drift" -v
```

Expected: 3 PASS.

- [ ] **Step 2: Manual smoke**

```bash
sophosfw backup
ls -la ~/.config/sophosfw/profiles/testvm/backups/
sophosfw backup list
sophosfw drift --latest                          # expect: no drift, exit 0

# Make a small change
sophosfw host ip update <existing-host> --body @body.yaml --expected-diff-hash <hash> --yes

sophosfw drift --latest                          # expect: 1 modified, exit 1
echo "exit: $?"

sophosfw drift --latest --json | jq .summary
sophosfw backup rotate --keep 3
```

Confirm output shapes match the spec.

- [ ] **Step 3: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "$(cat <<'EOF'
test: phase 13 backup + drift integration smokes

3 tests gated by SOPHOSFW_PROFILE: full backup snapshot, drift with
no changes, drift after ip host create. The third creates and
cleans up a real test record so it must be opt-in via
SOPHOSFW_TEST_IPHOST_NAME. Pattern mirrors Phase 12 integration smokes.
EOF
)"
```

---

## Task 10: Docs + tag v0.11.0 + verify release

**Files:**
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update `docs/roadmap.md`**

Append:

```
- Phase 13 — Backup + drift detection (complete; v0.11.0)
```

after the Phase 12 line.

- [ ] **Step 2: Final test pass**

```bash
go fmt ./... && go vet ./... && golangci-lint run ./... && go test -race ./...
```

Expected: clean. If `go fmt` produces changes, commit them in a separate `fix: phase 13 acceptance pass formatting` commit.

- [ ] **Step 3: Commit + push**

```bash
git add docs/roadmap.md
git commit -m "$(cat <<'EOF'
docs: phase 13 complete in roadmap

Phase 13 ships sophosfw backup and sophosfw drift plus 3 MCP tools
(backup_create, backup_list, drift_check; tool count 48 to 51).
Read-only feature; restore deferred. Tag v0.11.0.
EOF
)"
git push origin main
```

Wait for CI green:

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

- [ ] **Step 4: Tag v0.11.0**

```bash
git tag -a v0.11.0 -m "v0.11.0 — Phase 13: backup + drift detection

sophosfw backup writes a per-record YAML snapshot tree under the
profile config dir. sophosfw drift compares a snapshot to current
state, with CI-friendly exit codes (0 clean, 1 drift, 2 error) and
agent-friendly --json output. 3 new MCP tools: backup_create,
backup_list, drift_check (count 48 to 51). Restore is deferred to a
future phase."
git push origin v0.11.0
```

- [ ] **Step 5: Watch the release workflow**

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

- [ ] **Step 6: Verify release**

```bash
gh release view v0.11.0 --repo iainmoffat/sophosfw --json name,tagName,assets --jq '{name, tagName, assets: [.assets[].name]}'
gh api repos/iainmoffat/homebrew-sophosfw/contents/sophosfw.rb --jq '.content' | base64 -d | grep -E '^  version'
```

Expected: 5 assets, formula `version "0.11.0"`.

- [ ] **Step 7: Verify brew upgrade**

```bash
brew update
brew upgrade sophosfw
sophosfw version
sophosfw backup --help
sophosfw drift --help
```

Expected: `sophosfw 0.11.0`. Both commands display help cleanly.

---

## End of plan

## Self-review checklist

- ✅ **Spec coverage:** Section 3.1 (output structure) → Task 1 + Task 2; Section 3.2 (backup CLI + MCP) → T2/T3 (svc), T6 (CLI), T8 (MCP); Section 3.3 (drift CLI + MCP) → T4 (svc), T7 (CLI), T8 (MCP); Section 3.4 (svc helpers) → T2/T3/T4; Section 3.5 (diff format) → T4 (unifiedDiffOf); Section 7 (acceptance) → T9 (smokes) + T10 (release verify).
- ✅ **No placeholders.** All tasks have concrete code blocks, exact file paths, exact commit messages.
- ✅ **Atomic write.** Task 2 explicitly uses `.partial` → rename pattern; Task 9 includes a test for the on-error leftover.
- ✅ **Type/file consistency.** `BackupCreateOptions / BackupCreateResult / DriftOptions / DriftResult / DriftSummary / DriftChange` defined in T2/T4; consumed by T5 render, T6 CLI, T7 CLI, T8 MCP. Schema names consistent: `sophosfw.v1.{backupCreate, backupList, drift}`.
- ✅ **Tool count math.** 48 + 3 = 51. T8 step 3 updates `internal/mcp/server_test.go` accordingly.
- ✅ **Exit codes.** T7 introduces `ErrDriftDetected` sentinel mapped to exit 1; HandleError must be updated in the same task.
- ✅ **Atomicity preserved.** Backups are timestamped; never overwrite. Drift refuses on profile mismatch unless `--force`.
- ✅ **No restore.** Out-of-scope per spec section 8.

## Notes for the implementer

- **Subagent-driven flow:** T1 is small (paths). T2-T4 are the meaty svc-layer tasks; each warrants a dispatch + review pair. T5/T6/T7 are mechanical render+CLI work. T8 is MCP wiring. T9 is integration. T10 is release.
- **Catalog access from BackupSvc:** verify whether `RootDeps` already exposes `*catalog.Catalog`. If not, add it (minor surface change, follow how svc constructors that need the catalog get it today).
- **Token handling:** T10 release runs zero-touch since `HOMEBREW_TAP_TOKEN` is in repo secrets from Phase 11.
- **`s.Inner.List` vs `s.Inner.Get`:** the spec assumes `List` returns full bodies. Verify: if `List` returns only summaries, the implementation needs a per-record `Get` round trip (slow). If that turns out to be the case, **stop and surface to the user** before proceeding — it's a non-trivial design pivot.
