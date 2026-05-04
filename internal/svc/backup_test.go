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
