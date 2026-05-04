package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// fakeBackupCli is a scripted Client for backup/drift handler tests.
// It returns canned record bodies keyed by XML tag in response to GetOps.
// Unlike the mutation-test fakeMcpMutClient, this one returns the
// configured body for *every* tag (including those not in the map, which
// get an empty list) — Create iterates the whole catalog so any unscripted
// tag must come back as zero records to keep the snapshot small.
type fakeBackupCli struct {
	bodies map[string][]json.RawMessage
}

func (f *fakeBackupCli) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	op, ok := env.Operations[0].(sophos.GetOp)
	if !ok {
		return resp, nil
	}
	if recs, has := f.bodies[op.XMLTag]; has {
		resp.Body[op.XMLTag] = recs
	} else {
		resp.Body[op.XMLTag] = []json.RawMessage{}
	}
	return resp, nil
}

func (f *fakeBackupCli) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

// newBackupMcpServer builds a Server wired to a fakeBackupCli. BaseDir is
// a t.TempDir() so snapshot writes do not pollute the working tree.
// The returned cli reference lets tests mutate its bodies between calls
// (e.g. drift_check live state differing from snapshot).
func newBackupMcpServer(t *testing.T, bodies map[string][]json.RawMessage) (*Server, *fakeBackupCli, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	cfg.CurrentProfile = "home"
	baseDir := t.TempDir()
	store := creds.NewFileStore(baseDir)
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	cli := &fakeBackupCli{bodies: bodies}
	audit := svc.NewAuditLog(t.TempDir(), true)
	s := NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return cli },
		DefaultProfile: "home",
		Audit:          audit,
		BaseDir:        baseDir,
	})
	return s, cli, baseDir
}

func rawIPHostMcp(name, ip string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"Name":%q,"IPFamily":"IPv4","HostType":"IP","IPAddress":%q}`, name, ip))
}

func TestBackupCreate_Handler_WritesAndReturnsMetadata(t *testing.T) {
	s, _, baseDir := newBackupMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {rawIPHostMcp("LAN", "10.0.0.1"), rawIPHostMcp("DMZ", "10.0.1.1")},
	})

	out, _, err := s.handleBackupCreate(context.Background(), nil, BackupCreateInput{})
	require.NoError(t, err)

	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.backupCreate"`)
	require.Contains(t, body, `"profile": "home"`)
	require.Contains(t, body, `"totalRecords": 2`)

	// Decode to extract the snapshot path and verify on-disk artefacts.
	var env struct {
		Path         string         `json:"path"`
		RecordCounts map[string]int `json:"recordCounts"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &env))
	require.True(t, strings.HasPrefix(env.Path, baseDir),
		"snapshot path %q should be under BaseDir %q", env.Path, baseDir)
	require.Equal(t, 2, env.RecordCounts["IPHost"])

	meta, err := os.ReadFile(filepath.Join(env.Path, "_meta.yaml"))
	require.NoError(t, err)
	require.Contains(t, string(meta), "schema: sophosfw.v1.backupMeta")
	require.Contains(t, string(meta), "sophosfwVersion: test")

	// Per-record YAML files exist under <path>/IPHost/.
	entries, err := os.ReadDir(filepath.Join(env.Path, "IPHost"))
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestBackupList_Handler_ReturnsSnapshots(t *testing.T) {
	s, _, _ := newBackupMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {rawIPHostMcp("LAN", "10.0.0.1")},
	})

	// Empty initially.
	out, _, err := s.handleBackupList(context.Background(), nil, BackupListInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.backupList"`)
	require.Contains(t, body, `"snapshots": []`)

	// Create a snapshot, then re-list — should report one entry.
	_, _, err = s.handleBackupCreate(context.Background(), nil, BackupCreateInput{})
	require.NoError(t, err)

	out, _, err = s.handleBackupList(context.Background(), nil, BackupListInput{})
	require.NoError(t, err)
	body = textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.backupList"`)

	var env struct {
		Snapshots []map[string]any `json:"snapshots"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &env))
	require.Len(t, env.Snapshots, 1)
	require.NotEmpty(t, env.Snapshots[0]["path"])
	require.NotEmpty(t, env.Snapshots[0]["createdAt"])
}

func TestDriftCheck_Handler_NoChanges(t *testing.T) {
	s, _, _ := newBackupMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {rawIPHostMcp("LAN", "10.0.0.1")},
	})

	// Snapshot, then drift against the same live state — no changes.
	_, _, err := s.handleBackupCreate(context.Background(), nil, BackupCreateInput{})
	require.NoError(t, err)

	out, _, err := s.handleDriftCheck(context.Background(), nil, DriftCheckInput{Latest: true})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.drift"`)
	require.Contains(t, body, `"added": 0`)
	require.Contains(t, body, `"modified": 0`)
	require.Contains(t, body, `"removed": 0`)
	require.Contains(t, body, `"changes": []`)
}

func TestDriftCheck_Handler_DetectsChanges(t *testing.T) {
	s, cli, _ := newBackupMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {rawIPHostMcp("LAN", "10.0.0.1")},
	})

	// Snapshot at one state.
	_, _, err := s.handleBackupCreate(context.Background(), nil, BackupCreateInput{})
	require.NoError(t, err)

	// Mutate live state: change LAN's IP and add a new record.
	cli.bodies["IPHost"] = []json.RawMessage{
		rawIPHostMcp("LAN", "10.0.0.99"),
		rawIPHostMcp("DMZ", "10.0.1.1"),
	}

	out, _, err := s.handleDriftCheck(context.Background(), nil, DriftCheckInput{Latest: true})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.drift"`)
	// One modified (LAN), one added (DMZ).
	require.Contains(t, body, `"modified": 1`)
	require.Contains(t, body, `"added": 1`)
	require.Contains(t, body, `"name": "LAN"`)
	require.Contains(t, body, `"change": "modified"`)
	require.Contains(t, body, `"name": "DMZ"`)
	require.Contains(t, body, `"change": "added"`)
}
