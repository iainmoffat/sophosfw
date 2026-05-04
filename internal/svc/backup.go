package svc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// MetaSchemaName is the schema string written into _meta.yaml at the root
// of every snapshot. Drift readers MUST refuse to interpret a directory as
// a snapshot unless this exact string is present.
const MetaSchemaName = "sophosfw.v1.backupMeta"

// BackupSvc orchestrates `sophosfw backup` and `sophosfw drift`.
//
// Inner provides the per-type list/get plumbing (config, creds, catalog,
// client factory). Catalog is duplicated on the struct so resolveTypes
// can iterate the full tag list without dipping into ObjectSvc internals.
// BaseDir is the root of the on-disk store (typically ~/.config/sophosfw).
// Now is overrideable for deterministic tests. Version is the sophosfw
// build version baked into _meta.yaml; injected by the caller (CLI/MCP
// factories pass RootDeps.Version).
type BackupSvc struct {
	Inner   *ObjectSvc
	Catalog *catalog.Catalog
	BaseDir string
	Now     func() time.Time
	Version string
}

func (s *BackupSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// BackupCreateOptions controls Create. OutDir overrides the default
// timestamped location under <BaseDir>/profiles/<name>/backups/. Types and
// Exclude are mutually exclusive: Types restricts to a subset, Exclude
// trims from the full catalog.
type BackupCreateOptions struct {
	OutDir  string
	Types   []string
	Exclude []string
}

// BackupCreateResult is the render-friendly summary returned by Create.
type BackupCreateResult struct {
	Profile       string
	Path          string
	CreatedAt     time.Time
	TypesIncluded []string
	RecordCounts  map[string]int
	TotalRecords  int
}

// backupMeta is serialized as _meta.yaml at the root of every snapshot.
// The leading `schema` field is the discriminator; CatalogVersion is a
// placeholder for future schema evolution.
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

// Create writes a per-record YAML snapshot tree under <OutDir or default>.
//
// Atomicity: the snapshot is built under "<targetDir>.partial" and
// os.Renamed to "<targetDir>" only after every type has been written.
// On any error, the .partial directory is deliberately left in place for
// inspection; the caller (or an operator) can decide whether to retry or
// to investigate the partial result.
//
// Stub records (where Name is empty) are dropped. _diffHash is injected
// per record before writing so a later drift pass can short-circuit on
// hash equality without re-marshalling.
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
	// Clear any leftover .partial from a prior failed run before starting.
	// On-error retention applies to *this* run's failure, not stale state.
	if err := os.RemoveAll(partialDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(partialDir, 0o755); err != nil {
		return nil, err
	}

	counts := map[string]int{}
	total := 0

	for _, tag := range types {
		list, err := s.Inner.List(ctx, profileName, tag, nil)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", tag, err)
		}
		if list == nil || len(list.Items) == 0 {
			continue
		}
		typeDir := filepath.Join(partialDir, tag)
		if err := os.MkdirAll(typeDir, 0o755); err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			record, mErr := toMap(item)
			if mErr != nil {
				return nil, fmt.Errorf("coerce %s record: %w", tag, mErr)
			}
			if record == nil {
				continue
			}
			recName, _ := record["Name"].(string)
			if recName == "" {
				// Defense in depth: ObjectSvc.List already drops stubs,
				// but if anything slips through we skip it here too.
				continue
			}
			// Inject diff hash for fast drift comparison later. DiffHash
			// strips _diffHash internally, so re-hashing is idempotent.
			if hash, herr := DiffHash(record); herr == nil {
				record["_diffHash"] = hash
			}
			slug := draft.Slug(recName)
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
		SophosfwVersion: s.Version,
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

	// Ensure the parent of targetDir exists before rename. (BackupSnapshotDir
	// returns a nested path; default location's parent is typically already
	// created by MkdirAll above on partialDir, but custom OutDir may not be.)
	if err := os.MkdirAll(filepath.Dir(targetDir), 0o755); err != nil {
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

// resolveTypes returns the alphabetically-sorted list of catalog tags to
// include. want and exclude are mutually exclusive (the caller checks).
// All inputs are validated against the catalog; an unknown tag is an
// invalid-request error.
func (s *BackupSvc) resolveTypes(want, exclude []string) ([]string, error) {
	all := append([]string(nil), s.Catalog.Tags()...)
	sort.Strings(all)

	if len(want) == 0 && len(exclude) == 0 {
		return all, nil
	}

	if len(want) > 0 {
		out := make([]string, 0, len(want))
		for _, t := range want {
			entry, ok := s.Catalog.Resolve(t)
			if !ok {
				return nil, fmt.Errorf("%w: unknown type %q", sophos.ErrInvalidRequest, t)
			}
			out = append(out, entry.Tag)
		}
		sort.Strings(out)
		return out, nil
	}

	excludeSet := map[string]bool{}
	for _, t := range exclude {
		entry, ok := s.Catalog.Resolve(t)
		if !ok {
			return nil, fmt.Errorf("%w: unknown type %q (in --exclude)", sophos.ErrInvalidRequest, t)
		}
		excludeSet[entry.Tag] = true
	}
	out := make([]string, 0, len(all))
	for _, t := range all {
		if !excludeSet[t] {
			out = append(out, t)
		}
	}
	return out, nil
}

// BackupListEntry is one row in the result of BackupSvc.List.
//
// Path is the absolute snapshot directory; CreatedAt is parsed from the
// snapshot's _meta.yaml; RecordCounts mirrors the per-type counts written
// by Create.
type BackupListEntry struct {
	Path         string
	CreatedAt    time.Time
	RecordCounts map[string]int
}

// List enumerates valid snapshots under the active profile's backups
// directory, newest-first by CreatedAt from _meta.yaml. It silently
// skips directories whose name ends in ".partial" (left behind by a
// failed Create) and any directory whose _meta.yaml is missing or
// has the wrong schema (foreign content). A missing root directory
// returns (nil, nil).
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
			Path:         path,
			CreatedAt:    createdAt,
			RecordCounts: meta.RecordCounts,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt) // newest first
	})
	return out, nil
}

// readBackupMeta loads and validates the _meta.yaml at the root of a
// snapshot directory. Returns an error if the file is missing, fails
// to unmarshal, or has a schema string other than MetaSchemaName.
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

// Rotate deletes all snapshots beyond the keep most-recent for the
// active profile, returning the absolute paths of the deleted dirs.
// keep == 0 deletes every valid snapshot; negative values are an
// invalid request. A failure mid-loop returns the set deleted so far.
// .partial dirs are not touched (List filters them out).
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

// DriftOptions controls Drift. SnapshotPath and Latest are mutually
// exclusive. Types restricts the comparison to a subset of the
// catalog tags recorded in the snapshot's _meta.yaml; empty means
// "all types in the snapshot". Force overrides the profile-mismatch
// refusal so a snapshot from one firewall can be diffed against a
// different firewall's live state (rare; usually a mistake).
type DriftOptions struct {
	SnapshotPath string
	Latest       bool
	Types        []string
	Force        bool
}

// DriftSummaryPerType is the per-type tally rolled up into DriftSummary.
type DriftSummaryPerType struct {
	Added, Modified, Removed, Unchanged int
}

// DriftSummary is the global tally plus a per-type breakdown.
type DriftSummary struct {
	Added, Modified, Removed, Unchanged int
	PerType                             map[string]DriftSummaryPerType
}

// DriftChange is one record-level difference. Diff is populated only
// for "modified"; Body is populated only for "added"; "removed" carries
// only Type+Name+Change. _diffHash is stripped from any Body before
// it lands here.
type DriftChange struct {
	Type   string
	Name   string
	Change string         // "added" | "modified" | "removed"
	Diff   string         // unified diff, only for "modified"
	Body   map[string]any // only for "added"
}

// DriftResult is the render-friendly result returned by Drift.
type DriftResult struct {
	SnapshotPath      string
	Profile           string
	SnapshotCreatedAt time.Time
	CheckedAt         time.Time
	Summary           DriftSummary
	Changes           []DriftChange
}

// Drift compares the snapshot at opts.SnapshotPath (or the most recent
// snapshot under the default location when opts.Latest is true) against
// the firewall's current state, per type.
//
// Per-record classification, in order:
//
//   - removed: in snapshot, not in live
//   - unchanged: hash short-circuit when both sides have a non-empty
//     _diffHash and the hashes match (no diff computed)
//   - unchanged: recomputed-hash equality (defensive — a snapshot
//     written by an older sophosfw might lack _diffHash)
//   - modified: hashes differ; a unified diff is computed over the
//     canonical YAML bodies with _diffHash stripped from both sides
//   - added: in live, not in snapshot
//
// Live records are walked through toMap (the same path Create uses
// when writing snapshot records) so the hashing inputs match exactly.
//
// Profile-mismatch refusal: if the snapshot's _meta.yaml records a
// different profile than the active one, Drift errors with
// ErrInvalidRequest unless opts.Force is set. This prevents silently
// diffing one firewall's snapshot against another firewall's live
// state.
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
		// Validate each requested type against the catalog so a typo
		// surfaces as ErrInvalidRequest rather than as silent "no
		// records found".
		out := make([]string, 0, len(opts.Types))
		for _, t := range opts.Types {
			entry, ok := s.Catalog.Resolve(t)
			if !ok {
				return nil, fmt.Errorf("%w: unknown type %q", sophos.ErrInvalidRequest, t)
			}
			out = append(out, entry.Tag)
		}
		types = out
	}

	perType := map[string]DriftSummaryPerType{}
	var changes []DriftChange

	for _, tag := range types {
		snap, err := loadSnapshotRecords(snapshotPath, tag)
		if err != nil {
			return nil, fmt.Errorf("load snapshot %s: %w", tag, err)
		}
		list, err := s.Inner.List(ctx, profileName, tag, nil)
		if err != nil {
			return nil, fmt.Errorf("list live %s: %w", tag, err)
		}
		// Coerce live records through toMap so hashes computed here
		// match hashes computed at snapshot-write time (Create runs the
		// same coercion before injecting _diffHash).
		liveByName := map[string]map[string]any{}
		if list != nil {
			for _, item := range list.Items {
				rec, mErr := toMap(item)
				if mErr != nil {
					return nil, fmt.Errorf("coerce live %s record: %w", tag, mErr)
				}
				if rec == nil {
					continue
				}
				if n, _ := rec["Name"].(string); n != "" {
					liveByName[n] = rec
				}
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
			// Hash short-circuit: when both sides carry a non-empty
			// _diffHash and they match, classify unchanged without
			// re-marshalling. This is the hot path for unchanged
			// records under typical operational use.
			snapHash, _ := snapBody["_diffHash"].(string)
			liveHash, _ := liveBody["_diffHash"].(string)
			if snapHash != "" && liveHash != "" && snapHash == liveHash {
				sum.Unchanged++
				continue
			}
			// Recompute either side that was missing a hash. DiffHash
			// strips _diffHash internally so a stripped copy isn't
			// strictly required, but we pass one for symmetry.
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
			diff, derr := unifiedDiffOf(snapBody, liveBody, tag, snapName)
			if derr != nil {
				return nil, derr
			}
			changes = append(changes, DriftChange{
				Type: tag, Name: snapName, Change: "modified", Diff: diff,
			})
			sum.Modified++
		}
		// Added: in live, not in snapshot. Strip _diffHash from the
		// reported body so consumers see the firewall fields only.
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
	for _, ps := range perType {
		summary.Added += ps.Added
		summary.Modified += ps.Modified
		summary.Removed += ps.Removed
		summary.Unchanged += ps.Unchanged
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

// resolveSnapshotPath picks the snapshot to compare against. Explicit
// path wins; --latest resolves to the newest entry returned by List;
// supplying both is an invalid request. No snapshots → ErrNotFound.
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

// loadSnapshotRecords reads every <snapshotPath>/<tag>/*.yaml file into
// a map keyed by the record's Name. A missing type subdir is treated as
// an empty set — a snapshot may legitimately omit a type that had no
// records at create time.
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

// stripDiffHash returns a shallow copy of m with the _diffHash key
// removed. nil-safe.
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

// unifiedDiffOf renders the per-record diff text reported in
// DriftChange.Diff. Both sides are stripped of _diffHash and marshalled
// to canonical (sorted-key) YAML so diff output is deterministic and
// only reflects body changes.
func unifiedDiffOf(a, b map[string]any, tag, name string) (string, error) {
	ay, err := marshalCanonicalYAML(stripDiffHash(a))
	if err != nil {
		return "", err
	}
	by, err := marshalCanonicalYAML(stripDiffHash(b))
	if err != nil {
		return "", err
	}
	aLabel := fmt.Sprintf("snapshot:%s/%s", tag, name)
	bLabel := fmt.Sprintf("live:%s/%s", tag, name)
	return draft.UnifiedDiff(ay, by, aLabel, bLabel), nil
}
