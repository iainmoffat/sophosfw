package svc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// scriptedBodyClient returns body bodies keyed by XML tag. Each List op
// looks up the GetOp's XMLTag and returns the canned response. errFor
// short-circuits with an error if the requested tag is in the map.
type scriptedBodyClient struct {
	bodies map[string][]json.RawMessage
	errFor map[string]error
	calls  []string
}

func (c *scriptedBodyClient) Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error) {
	if len(env.Operations) == 0 {
		return &sophos.Response{LoginOK: true}, nil
	}
	getOp, ok := env.Operations[0].(sophos.GetOp)
	if !ok {
		return &sophos.Response{LoginOK: true}, nil
	}
	c.calls = append(c.calls, getOp.XMLTag)
	if err, has := c.errFor[getOp.XMLTag]; has {
		return nil, err
	}
	body := map[string][]json.RawMessage{}
	if rec, has := c.bodies[getOp.XMLTag]; has {
		body[getOp.XMLTag] = rec
	} else {
		body[getOp.XMLTag] = []json.RawMessage{}
	}
	return &sophos.Response{LoginOK: true, Body: body}, nil
}

func (c *scriptedBodyClient) DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

// newBackupSvc wires a BackupSvc against a scripted client. Profile
// "home" is pre-created with credentials so ActiveProfile + Creds.Load
// succeed.
func newBackupSvc(t *testing.T, cl Client) (*BackupSvc, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	cfg.CurrentProfile = "home"
	baseDir := t.TempDir()
	store := creds.NewFileStore(baseDir)
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))

	inner := &ObjectSvc{
		Config:    cfg,
		Creds:     store,
		Catalog:   cat,
		NewClient: func(p config.Profile, c creds.Credentials) Client { return cl },
	}
	fixedTime := time.Date(2026, 5, 3, 20, 30, 0, 0, time.UTC)
	bs := &BackupSvc{
		Inner:   inner,
		Catalog: cat,
		BaseDir: baseDir,
		Now:     func() time.Time { return fixedTime },
		Version: "test",
	}
	return bs, baseDir
}

// rawIPHost / rawZone / rawFirewallRule build minimal valid record
// fragments matching the typed parsers. Keeping these inline avoids
// dragging in helpers that fail in surprising ways across catalog edits.
func rawIPHost(name, ip string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"Name":%q,"IPFamily":"IPv4","HostType":"IP","IPAddress":%q}`, name, ip))
}

func rawZone(name string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"Name":%q,"Type":"LAN"}`, name))
}

func rawFirewallRule(name string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"Name":%q,"Status":"Enable","IPFamily":"IPv4","PolicyType":"Network"}`, name))
}

func TestBackupSvc_Create_DefaultLocation_WritesAllTypes(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost":       {rawIPHost("LAN", "10.0.0.1"), rawIPHost("DMZ", "10.0.1.1")},
			"Zone":         {rawZone("LAN"), rawZone("WAN")},
			"FirewallRule": {rawFirewallRule("rule-a")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)

	result, err := bs.Create(context.Background(), "", BackupCreateOptions{})
	require.NoError(t, err)
	require.Equal(t, "home", result.Profile)
	require.Equal(t, 5, result.TotalRecords)
	require.Equal(t, 2, result.RecordCounts["IPHost"])
	require.Equal(t, 2, result.RecordCounts["Zone"])
	require.Equal(t, 1, result.RecordCounts["FirewallRule"])

	// Default path: <baseDir>/profiles/home/backups/<utc>
	expectedPath := filepath.Join(baseDir, "profiles", "home", "backups", "2026-05-03T20-30-00Z")
	require.Equal(t, expectedPath, result.Path)
	require.DirExists(t, result.Path)

	// _meta.yaml present and parseable
	metaBytes, err := os.ReadFile(filepath.Join(result.Path, "_meta.yaml"))
	require.NoError(t, err)
	var meta backupMeta
	require.NoError(t, yaml.Unmarshal(metaBytes, &meta))
	require.Equal(t, MetaSchemaName, meta.Schema)
	require.Equal(t, "home", meta.Profile)
	require.Equal(t, "https://x:4444", meta.URL)
	require.Equal(t, "test", meta.SophosfwVersion)
	require.Equal(t, 5, meta.TotalRecords)

	// Per-type subdirs
	require.DirExists(t, filepath.Join(result.Path, "IPHost"))
	require.DirExists(t, filepath.Join(result.Path, "Zone"))
	require.DirExists(t, filepath.Join(result.Path, "FirewallRule"))

	// Per-record file content
	lanBytes, err := os.ReadFile(filepath.Join(result.Path, "IPHost", "lan.yaml"))
	require.NoError(t, err)
	var lan map[string]any
	require.NoError(t, yaml.Unmarshal(lanBytes, &lan))
	require.Equal(t, "LAN", lan["Name"])
	require.NotEmpty(t, lan["_diffHash"])

	// .partial dir must not remain on success
	require.NoDirExists(t, result.Path+".partial")
}

func TestBackupSvc_Create_RejectsTypesAndExcludeTogether(t *testing.T) {
	cl := &scriptedBodyClient{}
	bs, _ := newBackupSvc(t, cl)
	_, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Types:   []string{"IPHost"},
		Exclude: []string{"Zone"},
	})
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestBackupSvc_Create_RejectsExistingOutDir(t *testing.T) {
	cl := &scriptedBodyClient{}
	bs, _ := newBackupSvc(t, cl)
	out := t.TempDir() // already exists by virtue of TempDir
	_, err := bs.Create(context.Background(), "", BackupCreateOptions{OutDir: out})
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "already exists")
}

func TestBackupSvc_Create_RejectsUnknownType(t *testing.T) {
	cl := &scriptedBodyClient{}
	bs, _ := newBackupSvc(t, cl)
	_, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Types: []string{"NotARealTag"},
	})
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "unknown type")

	_, err = bs.Create(context.Background(), "", BackupCreateOptions{
		Exclude: []string{"NotARealTag"},
	})
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "--exclude")
}

func TestBackupSvc_Create_TypesFilter_OnlyIncludesSubset(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost":       {rawIPHost("LAN", "10.0.0.1")},
			"Zone":         {rawZone("LAN")},
			"FirewallRule": {rawFirewallRule("rule-a")},
		},
	}
	bs, _ := newBackupSvc(t, cl)

	result, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Types: []string{"IPHost", "Zone"},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"IPHost", "Zone"}, result.TypesIncluded)
	require.DirExists(t, filepath.Join(result.Path, "IPHost"))
	require.DirExists(t, filepath.Join(result.Path, "Zone"))
	require.NoDirExists(t, filepath.Join(result.Path, "FirewallRule"))

	// Verify the client only saw the two requested tags.
	calls := append([]string(nil), cl.calls...)
	sort.Strings(calls)
	require.Equal(t, []string{"IPHost", "Zone"}, calls)
}

func TestBackupSvc_Create_ExcludeFilter_OmitsListedTypes(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
	}
	bs, _ := newBackupSvc(t, cl)

	allTags := append([]string(nil), bs.Catalog.Tags()...)
	sort.Strings(allTags)

	result, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Exclude: []string{"FirewallRule", "NATRule", "Zone"},
	})
	require.NoError(t, err)

	for _, omitted := range []string{"FirewallRule", "NATRule", "Zone"} {
		require.NotContains(t, result.TypesIncluded, omitted,
			"%s should be excluded", omitted)
		for _, called := range cl.calls {
			require.NotEqual(t, omitted, called,
				"client should not have been called for excluded type %s", omitted)
		}
	}
	require.Contains(t, result.TypesIncluded, "IPHost")
}

func TestBackupSvc_Create_AtomicRename_PartialDirRemovedOnSuccess(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)

	result, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Types: []string{"IPHost"},
	})
	require.NoError(t, err)

	// .partial sibling MUST NOT exist
	partial := result.Path + ".partial"
	_, statErr := os.Stat(partial)
	require.True(t, os.IsNotExist(statErr),
		"%s should not exist after success (got err=%v)", partial, statErr)

	// And the canonical dir DOES exist with content
	require.DirExists(t, result.Path)
	require.FileExists(t, filepath.Join(result.Path, "_meta.yaml"))
	_ = baseDir
}

func TestBackupSvc_Create_OnListError_LeavesPartialForInspection(t *testing.T) {
	// resolveTypes sorts alphabetically: IPHost (success) → Zone (error).
	// So IPHost gets written under .partial before Zone errors out.
	listErr := errors.New("simulated network failure")
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
		errFor: map[string]error{"Zone": listErr},
	}
	bs, _ := newBackupSvc(t, cl)

	_, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Types: []string{"IPHost", "Zone"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Zone")

	// Snapshot dir does NOT exist (rename never happened).
	expectedTarget := filepath.Join(bs.BaseDir, "profiles", "home", "backups", "2026-05-03T20-30-00Z")
	require.NoDirExists(t, expectedTarget)

	// .partial sibling DOES exist with the IPHost subtree, for operator
	// inspection. (Zone errored before any Zone subdir was created.)
	partial := expectedTarget + ".partial"
	require.DirExists(t, partial)
	require.DirExists(t, filepath.Join(partial, "IPHost"))
	require.FileExists(t, filepath.Join(partial, "IPHost", "lan.yaml"))
}

func TestBackupSvc_Create_WritesDiffHashInRecordFiles(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
	}
	bs, _ := newBackupSvc(t, cl)

	result, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Types: []string{"IPHost"},
	})
	require.NoError(t, err)

	body, err := os.ReadFile(filepath.Join(result.Path, "IPHost", "lan.yaml"))
	require.NoError(t, err)
	var rec map[string]any
	require.NoError(t, yaml.Unmarshal(body, &rec))
	hash, ok := rec["_diffHash"].(string)
	require.True(t, ok, "_diffHash should be a string")
	require.Len(t, hash, 64, "SHA-256 hex is 64 chars")

	// And the hash must be the canonical DiffHash of the body sans hash.
	clean := map[string]any{}
	for k, v := range rec {
		if k == "_diffHash" {
			continue
		}
		clean[k] = v
	}
	expected, err := DiffHash(clean)
	require.NoError(t, err)
	require.Equal(t, expected, hash)
}

// writeSnapshotDir creates a fake snapshot directory under
// <baseDir>/profiles/home/backups/<dirName> with a _meta.yaml whose
// CreatedAt is the supplied timestamp. Used by List / Rotate tests
// that don't need the full Create flow.
func writeSnapshotDir(t *testing.T, baseDir, dirName string, createdAt time.Time) string {
	t.Helper()
	dir := filepath.Join(baseDir, "profiles", "home", "backups", dirName)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	meta := backupMeta{
		Schema:          MetaSchemaName,
		Profile:         "home",
		URL:             "https://x:4444",
		SophosfwVersion: "test",
		CreatedAt:       createdAt.UTC().Format(time.RFC3339),
		CatalogVersion:  "1",
		TypesIncluded:   []string{"IPHost"},
		RecordCounts:    map[string]int{"IPHost": 1},
		TotalRecords:    1,
	}
	metaBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "_meta.yaml"), metaBytes, 0o644))
	return dir
}

func TestBackupSvc_List_EmptyDirectory_ReturnsNil(t *testing.T) {
	bs, _ := newBackupSvc(t, &scriptedBodyClient{})

	// No snapshots yet — the backups dir doesn't even exist.
	entries, err := bs.List("")
	require.NoError(t, err)
	require.Nil(t, entries)
}

func TestBackupSvc_List_ReturnsTimestampSortedNewestFirst(t *testing.T) {
	bs, baseDir := newBackupSvc(t, &scriptedBodyClient{})

	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	writeSnapshotDir(t, baseDir, "2026-05-01T10-00-00Z", t1)
	writeSnapshotDir(t, baseDir, "2026-05-03T10-00-00Z", t3)
	writeSnapshotDir(t, baseDir, "2026-05-02T10-00-00Z", t2)

	entries, err := bs.List("")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	require.True(t, entries[0].CreatedAt.Equal(t3), "newest first: %v", entries[0].CreatedAt)
	require.True(t, entries[1].CreatedAt.Equal(t2))
	require.True(t, entries[2].CreatedAt.Equal(t1))
}

func TestBackupSvc_List_SkipsPartialDirs(t *testing.T) {
	bs, baseDir := newBackupSvc(t, &scriptedBodyClient{})

	good := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	goodDir := writeSnapshotDir(t, baseDir, "2026-05-02T10-00-00Z", good)

	// Create a .partial dir alongside (with a valid-looking meta to prove
	// the suffix check, not the meta check, is what filters it).
	partial := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	writeSnapshotDir(t, baseDir, "2026-05-01T10-00-00Z.partial", partial)

	entries, err := bs.List("")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, goodDir, entries[0].Path)
}

func TestBackupSvc_List_SkipsDirsWithoutValidMeta(t *testing.T) {
	bs, baseDir := newBackupSvc(t, &scriptedBodyClient{})

	// Good snapshot.
	good := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	goodDir := writeSnapshotDir(t, baseDir, "2026-05-02T10-00-00Z", good)

	// Dir with no _meta.yaml at all.
	noMeta := filepath.Join(baseDir, "profiles", "home", "backups", "no-meta")
	require.NoError(t, os.MkdirAll(noMeta, 0o755))

	// Dir with a _meta.yaml of the wrong schema.
	wrong := filepath.Join(baseDir, "profiles", "home", "backups", "wrong-schema")
	require.NoError(t, os.MkdirAll(wrong, 0o755))
	bogus, err := yaml.Marshal(map[string]string{"schema": "some.other.schema"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(wrong, "_meta.yaml"), bogus, 0o644))

	entries, err := bs.List("")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, goodDir, entries[0].Path)
}

func TestBackupSvc_Rotate_KeepZero_DeletesAll(t *testing.T) {
	bs, baseDir := newBackupSvc(t, &scriptedBodyClient{})

	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	d1 := writeSnapshotDir(t, baseDir, "2026-05-01T10-00-00Z", t1)
	d2 := writeSnapshotDir(t, baseDir, "2026-05-02T10-00-00Z", t2)

	deleted, err := bs.Rotate("", 0)
	require.NoError(t, err)
	require.Len(t, deleted, 2)
	require.ElementsMatch(t, []string{d1, d2}, deleted)
	require.NoDirExists(t, d1)
	require.NoDirExists(t, d2)
}

func TestBackupSvc_Rotate_KeepN_DeletesOldestN(t *testing.T) {
	bs, baseDir := newBackupSvc(t, &scriptedBodyClient{})

	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	t4 := time.Date(2026, 5, 4, 10, 0, 0, 0, time.UTC)
	d1 := writeSnapshotDir(t, baseDir, "2026-05-01T10-00-00Z", t1)
	d2 := writeSnapshotDir(t, baseDir, "2026-05-02T10-00-00Z", t2)
	d3 := writeSnapshotDir(t, baseDir, "2026-05-03T10-00-00Z", t3)
	d4 := writeSnapshotDir(t, baseDir, "2026-05-04T10-00-00Z", t4)

	deleted, err := bs.Rotate("", 2)
	require.NoError(t, err)
	// keep 2 newest (d4, d3); delete d2, d1.
	require.ElementsMatch(t, []string{d1, d2}, deleted)
	require.DirExists(t, d3)
	require.DirExists(t, d4)
	require.NoDirExists(t, d1)
	require.NoDirExists(t, d2)
}

func TestBackupSvc_Rotate_NothingToDelete_ReturnsNil(t *testing.T) {
	bs, baseDir := newBackupSvc(t, &scriptedBodyClient{})

	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	writeSnapshotDir(t, baseDir, "2026-05-01T10-00-00Z", t1)
	writeSnapshotDir(t, baseDir, "2026-05-02T10-00-00Z", t2)

	// keep >= existing count: nothing to delete.
	deleted, err := bs.Rotate("", 5)
	require.NoError(t, err)
	require.Nil(t, deleted)
}

func TestBackupSvc_Rotate_RejectsNegativeKeep(t *testing.T) {
	bs, _ := newBackupSvc(t, &scriptedBodyClient{})

	_, err := bs.Rotate("", -1)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "--keep")
}

// writeFullSnapshot builds a complete snapshot directory under
// <baseDir>/profiles/home/backups/<dirName>: _meta.yaml at the root
// plus per-type subdirs containing the supplied records as
// <slug>.yaml, each with an injected _diffHash matching what Create
// would have written. recordsByTag values must already be in
// map[string]any form (post-toMap); _diffHash is computed and added
// here.
func writeFullSnapshot(t *testing.T, baseDir, dirName, profile string, createdAt time.Time, recordsByTag map[string][]map[string]any) string {
	t.Helper()
	dir := filepath.Join(baseDir, "profiles", profile, "backups", dirName)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	counts := map[string]int{}
	total := 0
	types := make([]string, 0, len(recordsByTag))
	for tag := range recordsByTag {
		types = append(types, tag)
	}
	sort.Strings(types)
	for _, tag := range types {
		records := recordsByTag[tag]
		if len(records) == 0 {
			continue
		}
		typeDir := filepath.Join(dir, tag)
		require.NoError(t, os.MkdirAll(typeDir, 0o755))
		for _, rec := range records {
			recName, _ := rec["Name"].(string)
			require.NotEmpty(t, recName, "writeFullSnapshot record missing Name")
			// Skip auto-hash if caller pre-set _diffHash (lets tests
			// exercise the short-circuit path with explicit values).
			if _, has := rec["_diffHash"]; !has {
				h, err := DiffHash(rec)
				require.NoError(t, err)
				rec["_diffHash"] = h
			}
			body, err := marshalCanonicalYAML(rec)
			require.NoError(t, err)
			slug := strings.ToLower(recName)
			require.NoError(t, os.WriteFile(filepath.Join(typeDir, slug+".yaml"), body, 0o644))
			counts[tag]++
			total++
		}
	}
	meta := backupMeta{
		Schema:          MetaSchemaName,
		Profile:         profile,
		URL:             "https://x:4444",
		SophosfwVersion: "test",
		CreatedAt:       createdAt.UTC().Format(time.RFC3339),
		CatalogVersion:  "1",
		TypesIncluded:   types,
		RecordCounts:    counts,
		TotalRecords:    total,
	}
	metaBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "_meta.yaml"), metaBytes, 0o644))
	return dir
}

// rawIPHostMap mirrors rawIPHost but returns the post-coercion
// map[string]any shape that toMap would produce from the typed parser.
// Used to seed snapshot bodies in drift tests.
func rawIPHostMap(name, ip string) map[string]any {
	return map[string]any{
		"Name":      name,
		"IPFamily":  "IPv4",
		"HostType":  "IP",
		"IPAddress": ip,
	}
}

func TestBackupSvc_Drift_NoChanges_EmptyResult(t *testing.T) {
	// Snapshot has one IPHost; live returns the same one with the same
	// fields. Expect zero changes, one unchanged record.
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)
	snapTime := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "home", snapTime, map[string][]map[string]any{
		"IPHost": {rawIPHostMap("LAN", "10.0.0.1")},
	})

	result, err := bs.Drift(context.Background(), "", DriftOptions{SnapshotPath: snap})
	require.NoError(t, err)
	require.Empty(t, result.Changes)
	require.Equal(t, 0, result.Summary.Added)
	require.Equal(t, 0, result.Summary.Modified)
	require.Equal(t, 0, result.Summary.Removed)
	require.Equal(t, 1, result.Summary.Unchanged)
	require.Equal(t, "home", result.Profile)
	require.Equal(t, snap, result.SnapshotPath)
	require.True(t, result.SnapshotCreatedAt.Equal(snapTime),
		"snapshotCreatedAt parsed: got %v want %v", result.SnapshotCreatedAt, snapTime)
}

func TestBackupSvc_Drift_AddedRecord_ReportsAdded(t *testing.T) {
	// Live has two records; snapshot has one. The extra live record is
	// "added".
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1"), rawIPHost("DMZ", "10.0.1.1")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)
	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "home",
		time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		map[string][]map[string]any{
			"IPHost": {rawIPHostMap("LAN", "10.0.0.1")},
		})

	result, err := bs.Drift(context.Background(), "", DriftOptions{SnapshotPath: snap})
	require.NoError(t, err)
	require.Len(t, result.Changes, 1)
	require.Equal(t, "added", result.Changes[0].Change)
	require.Equal(t, "IPHost", result.Changes[0].Type)
	require.Equal(t, "DMZ", result.Changes[0].Name)
	require.NotNil(t, result.Changes[0].Body)
	// _diffHash must be stripped from the reported body.
	_, hasHash := result.Changes[0].Body["_diffHash"]
	require.False(t, hasHash, "added body should not include _diffHash")
	require.Equal(t, "10.0.1.1", result.Changes[0].Body["IPAddress"])
	require.Equal(t, 1, result.Summary.Added)
	require.Equal(t, 1, result.Summary.Unchanged) // LAN matches
}

func TestBackupSvc_Drift_RemovedRecord_ReportsRemoved(t *testing.T) {
	// Snapshot has two; live has one. Missing record is "removed".
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)
	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "home",
		time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		map[string][]map[string]any{
			"IPHost": {rawIPHostMap("LAN", "10.0.0.1"), rawIPHostMap("DMZ", "10.0.1.1")},
		})

	result, err := bs.Drift(context.Background(), "", DriftOptions{SnapshotPath: snap})
	require.NoError(t, err)
	require.Len(t, result.Changes, 1)
	require.Equal(t, "removed", result.Changes[0].Change)
	require.Equal(t, "IPHost", result.Changes[0].Type)
	require.Equal(t, "DMZ", result.Changes[0].Name)
	// Removed records carry no body and no diff.
	require.Empty(t, result.Changes[0].Diff)
	require.Nil(t, result.Changes[0].Body)
	require.Equal(t, 1, result.Summary.Removed)
	require.Equal(t, 1, result.Summary.Unchanged)
}

func TestBackupSvc_Drift_ModifiedRecord_ReportsModifiedWithDiff(t *testing.T) {
	// Snapshot LAN: 10.0.0.1; live LAN: 10.0.0.99. Same Name,
	// different IPAddress → "modified" with a unified diff.
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.99")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)
	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "home",
		time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		map[string][]map[string]any{
			"IPHost": {rawIPHostMap("LAN", "10.0.0.1")},
		})

	result, err := bs.Drift(context.Background(), "", DriftOptions{SnapshotPath: snap})
	require.NoError(t, err)
	require.Len(t, result.Changes, 1)
	require.Equal(t, "modified", result.Changes[0].Change)
	require.Equal(t, "IPHost", result.Changes[0].Type)
	require.Equal(t, "LAN", result.Changes[0].Name)
	require.NotEmpty(t, result.Changes[0].Diff, "modified records carry a unified diff")
	// Diff should mention the old and new IPs and reference the labels.
	require.Contains(t, result.Changes[0].Diff, "10.0.0.1")
	require.Contains(t, result.Changes[0].Diff, "10.0.0.99")
	require.Contains(t, result.Changes[0].Diff, "snapshot:IPHost/LAN")
	require.Contains(t, result.Changes[0].Diff, "live:IPHost/LAN")
	// The injected _diffHash must NOT appear in the diff (stripped).
	require.NotContains(t, result.Changes[0].Diff, "_diffHash")
	require.Equal(t, 1, result.Summary.Modified)
}

func TestBackupSvc_Drift_HashShortCircuit_SkipsUnchanged(t *testing.T) {
	// Snapshot record carries _diffHash="forced-hash"; we manually
	// post-process the live record map so its _diffHash matches. Even
	// though the underlying bodies differ, the hash short-circuit must
	// classify the record as unchanged and produce no diff.
	//
	// Implementation detail: we can't get a forced hash onto the live
	// side via the scripted client (toMap is called by Drift, not by
	// the client), so we wedge an IPHost whose toMap result happens to
	// be deterministic and pin its hash on both sides by writing the
	// snapshot with the same forced "_diffHash" string the live record
	// would compute via the standard rules — the simplest way is:
	//   1. compute the canonical hash of the live body (post-toMap)
	//   2. write the snapshot with a body that *differs* but reuses
	//      that same explicit _diffHash
	// Then the short-circuit kicks in and unchanged++ even though
	// bodies disagree. This is exactly the behaviour we want to verify.
	liveRaw := rawIPHost("LAN", "10.0.0.99")
	liveMap := rawIPHostMap("LAN", "10.0.0.99")
	liveHash, err := DiffHash(liveMap)
	require.NoError(t, err)

	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {liveRaw},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)

	// Snapshot body is intentionally different (10.0.0.1) but pinned
	// to the same hash → short-circuit must classify as unchanged.
	snapRec := rawIPHostMap("LAN", "10.0.0.1")
	snapRec["_diffHash"] = liveHash

	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "home",
		time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		map[string][]map[string]any{
			"IPHost": {snapRec},
		})

	result, err := bs.Drift(context.Background(), "", DriftOptions{SnapshotPath: snap})
	require.NoError(t, err)
	require.Empty(t, result.Changes,
		"hash short-circuit should classify as unchanged even when bodies differ; got %+v", result.Changes)
	require.Equal(t, 1, result.Summary.Unchanged)
	require.Equal(t, 0, result.Summary.Modified)
}

func TestBackupSvc_Drift_RejectsProfileMismatch(t *testing.T) {
	// Snapshot's _meta.yaml says profile "other"; current is "home".
	// Without --force, Drift refuses.
	cl := &scriptedBodyClient{}
	bs, baseDir := newBackupSvc(t, cl)
	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "other",
		time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		map[string][]map[string]any{
			"IPHost": {rawIPHostMap("LAN", "10.0.0.1")},
		})

	_, err := bs.Drift(context.Background(), "", DriftOptions{SnapshotPath: snap})
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "profile")
	require.Contains(t, err.Error(), "--force")
}

func TestBackupSvc_Drift_ForceOverridesProfileMismatch(t *testing.T) {
	// Same setup as the previous test, with Force=true. Drift proceeds.
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)
	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "other",
		time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		map[string][]map[string]any{
			"IPHost": {rawIPHostMap("LAN", "10.0.0.1")},
		})

	result, err := bs.Drift(context.Background(), "", DriftOptions{
		SnapshotPath: snap,
		Force:        true,
	})
	require.NoError(t, err)
	require.Equal(t, "home", result.Profile,
		"result reflects the *current* profile, not the snapshot's")
	require.Equal(t, 1, result.Summary.Unchanged)
}

func TestBackupSvc_Drift_LatestResolvesNewestSnapshot(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.1")},
		},
	}
	bs, baseDir := newBackupSvc(t, cl)
	// Three snapshots; the newest must be picked.
	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC)
	writeFullSnapshot(t, baseDir, "2026-05-01T10-00-00Z", "home", t1, map[string][]map[string]any{
		"IPHost": {rawIPHostMap("OLDEST", "10.0.0.1")},
	})
	writeFullSnapshot(t, baseDir, "2026-05-02T10-00-00Z", "home", t2, map[string][]map[string]any{
		"IPHost": {rawIPHostMap("MIDDLE", "10.0.0.1")},
	})
	newest := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "home", t3, map[string][]map[string]any{
		"IPHost": {rawIPHostMap("LAN", "10.0.0.1")},
	})

	result, err := bs.Drift(context.Background(), "", DriftOptions{Latest: true})
	require.NoError(t, err)
	require.Equal(t, newest, result.SnapshotPath)
	// Snapshot's only record (LAN) matches live, so no changes.
	require.Empty(t, result.Changes)
}

func TestBackupSvc_Drift_LatestAndPathTogether_Rejects(t *testing.T) {
	bs, _ := newBackupSvc(t, &scriptedBodyClient{})
	_, err := bs.Drift(context.Background(), "", DriftOptions{
		SnapshotPath: "/tmp/whatever",
		Latest:       true,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestBackupSvc_Drift_NoSnapshots_ReturnsNotFound(t *testing.T) {
	bs, _ := newBackupSvc(t, &scriptedBodyClient{})
	_, err := bs.Drift(context.Background(), "", DriftOptions{Latest: true})
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrNotFound)
}

func TestBackupSvc_Drift_PerTypeFilter(t *testing.T) {
	// Snapshot has IPHost + Zone records. Live has changes in BOTH
	// types, but we ask Drift to only check IPHost. Zone changes must
	// be invisible.
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {rawIPHost("LAN", "10.0.0.99")},  // changed
			"Zone":   {rawZone("LAN"), rawZone("WAN")}, // added WAN
		},
	}
	bs, baseDir := newBackupSvc(t, cl)
	snap := writeFullSnapshot(t, baseDir, "2026-05-03T10-00-00Z", "home",
		time.Date(2026, 5, 3, 10, 0, 0, 0, time.UTC),
		map[string][]map[string]any{
			"IPHost": {rawIPHostMap("LAN", "10.0.0.1")},
			"Zone":   {{"Name": "LAN", "Type": "LAN"}},
		})

	result, err := bs.Drift(context.Background(), "", DriftOptions{
		SnapshotPath: snap,
		Types:        []string{"IPHost"},
	})
	require.NoError(t, err)

	// Only IPHost changes should be reported.
	for _, c := range result.Changes {
		require.Equal(t, "IPHost", c.Type,
			"with Types=[IPHost], unexpected Zone change %+v", c)
	}
	require.Equal(t, 1, result.Summary.Modified)
	require.Equal(t, 0, result.Summary.Added)
	require.Equal(t, 0, result.Summary.Removed)

	// And the client should never have been asked for Zone.
	for _, called := range cl.calls {
		require.NotEqual(t, "Zone", called,
			"per-type filter must skip the Zone live fetch")
	}
}

func TestBackupSvc_Create_StubRecordsSkipped(t *testing.T) {
	// A real record + a stub (Name="") for the same tag. Stub must not
	// produce a file, must not contribute to counts, and must not error.
	// ObjectSvc.List already drops stubs, so we exercise that path here
	// for end-to-end coverage.
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"IPHost": {
				rawIPHost("LAN", "10.0.0.1"),
				json.RawMessage(`{"Name":"","IPFamily":"","HostType":""}`),
			},
		},
	}
	bs, _ := newBackupSvc(t, cl)

	result, err := bs.Create(context.Background(), "", BackupCreateOptions{
		Types: []string{"IPHost"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.TotalRecords)
	require.Equal(t, 1, result.RecordCounts["IPHost"])

	entries, err := os.ReadDir(filepath.Join(result.Path, "IPHost"))
	require.NoError(t, err)
	yamlFiles := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			yamlFiles++
		}
	}
	require.Equal(t, 1, yamlFiles)
}

// rawFQDNHost builds a minimal FQDNHost fragment. FQDN objects are where
// slug collisions bite hardest, because wildcard and bare names coexist
// routinely (*.google.com alongside google.com).
func rawFQDNHost(name string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"Name":%q,"FQDN":%q,"IPFamily":"IPv4"}`, name, strings.TrimPrefix(name, "*.")))
}

// snapshotFiles lists the .yaml basenames written for one type.
func snapshotFiles(t *testing.T, snapshotDir, tag string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(snapshotDir, tag))
	require.NoError(t, err)
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// A wildcard object and its bare sibling both exist on real devices and
// must not share a snapshot file. draft.Slug folds "*." to nothing, so
// "*.foo.example.com" and "foo.example.com" both reduce to
// "foo-example-com" — whichever was written second silently destroyed the
// other, and drift then reported the loser as Added on every run for ever.
func TestBackupSvc_Create_WildcardAndBareNameDoNotCollide(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"FQDNHost": {
				rawFQDNHost("foo.example.com"),
				rawFQDNHost("*.foo.example.com"),
			},
		},
	}
	bs, _ := newBackupSvc(t, cl)
	res, err := bs.Create(context.Background(), "", BackupCreateOptions{Types: []string{"FQDNHost"}})
	require.NoError(t, err)

	files := snapshotFiles(t, res.Path, "FQDNHost")
	require.Len(t, files, 2, "each object needs its own file, got %v", files)

	// Both must round-trip back out of the snapshot, keyed by real name.
	recs, err := loadSnapshotRecords(res.Path, "FQDNHost")
	require.NoError(t, err)
	require.Contains(t, recs, "foo.example.com")
	require.Contains(t, recs, "*.foo.example.com")
	require.Equal(t, "foo.example.com", recs["foo.example.com"]["Name"])
	require.Equal(t, "*.foo.example.com", recs["*.foo.example.com"]["Name"])
}

// The `*` case is only the instance we happened to hit. The sanitiser
// folds every run of non-alphanumerics to a single "-", so any names
// differing only in punctuation or spacing collide the same way.
func TestBackupSvc_Create_PunctuationVariantsDoNotCollide(t *testing.T) {
	names := []string{"a b", "a-b", "a.b", "a/b", "a:b"}
	raws := make([]json.RawMessage, len(names))
	for i, n := range names {
		raws[i] = rawFQDNHost(n)
	}
	cl := &scriptedBodyClient{bodies: map[string][]json.RawMessage{"FQDNHost": raws}}
	bs, _ := newBackupSvc(t, cl)
	res, err := bs.Create(context.Background(), "", BackupCreateOptions{Types: []string{"FQDNHost"}})
	require.NoError(t, err)

	require.Len(t, snapshotFiles(t, res.Path, "FQDNHost"), len(names))
	recs, err := loadSnapshotRecords(res.Path, "FQDNHost")
	require.NoError(t, err)
	for _, n := range names {
		require.Contains(t, recs, n, "object %q must survive the snapshot", n)
	}
}

// The count in _meta.yaml must describe what is actually on disk. The
// original bug reported 581 records against 579 files and nothing
// compared the two — that mismatch was the tool telling on itself.
func TestBackupSvc_Create_ReportedCountMatchesFilesWritten(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"FQDNHost": {
				rawFQDNHost("google.com"),
				rawFQDNHost("*.google.com"),
				rawFQDNHost("search.yahoo.com"),
				rawFQDNHost("*.search.yahoo.com"),
			},
		},
	}
	bs, _ := newBackupSvc(t, cl)
	res, err := bs.Create(context.Background(), "", BackupCreateOptions{Types: []string{"FQDNHost"}})
	require.NoError(t, err)

	require.Equal(t, 4, res.TotalRecords)
	require.Len(t, snapshotFiles(t, res.Path, "FQDNHost"), res.TotalRecords,
		"reported record count must equal files actually written")
}

// The strong invariant: a snapshot taken from an unchanged device must
// diff clean against that same device. Anything the snapshot loses shows
// up here as a phantom delta, and phantom deltas train operators to skim
// the one surface that tells them what changed on the firewall.
func TestBackupSvc_Drift_AgainstFreshSnapshot_ReportsZeroDeltas(t *testing.T) {
	cl := &scriptedBodyClient{
		bodies: map[string][]json.RawMessage{
			"FQDNHost": {
				rawFQDNHost("google.com"),
				rawFQDNHost("*.google.com"),
				rawFQDNHost("search.yahoo.com"),
				rawFQDNHost("*.search.yahoo.com"),
				rawFQDNHost("*.clients.l.google.com"),
				rawFQDNHost("clients.l.google.com"),
			},
		},
	}
	bs, _ := newBackupSvc(t, cl)
	res, err := bs.Create(context.Background(), "", BackupCreateOptions{Types: []string{"FQDNHost"}})
	require.NoError(t, err)

	drift, err := bs.Drift(context.Background(), "", DriftOptions{SnapshotPath: res.Path})
	require.NoError(t, err)
	require.Empty(t, drift.Changes,
		"a freshly taken snapshot must diff clean against the same device, got %+v", drift.Changes)
	require.Equal(t, 0, drift.Summary.Added)
	require.Equal(t, 0, drift.Summary.Removed)
	require.Equal(t, 0, drift.Summary.Modified)
	require.Equal(t, 6, drift.Summary.Unchanged)
}
