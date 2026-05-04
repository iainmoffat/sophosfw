package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// fakeBackupClient returns canned responses for List ops keyed by XML
// tag. Anything not in `bodies` returns an empty body for that tag, so
// catalog walks complete cleanly even with sparse fixtures.
type fakeBackupClient struct {
	bodies map[string][]json.RawMessage
}

func (f fakeBackupClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	op, ok := env.Operations[0].(sophos.GetOp)
	if !ok {
		return resp, nil
	}
	if recs, ok := f.bodies[op.XMLTag]; ok {
		resp.Body[op.XMLTag] = recs
	} else {
		resp.Body[op.XMLTag] = []json.RawMessage{}
	}
	return resp, nil
}
func (fakeBackupClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

// newRootForBackupTest wires a RootDeps + ProfileSvc-registered "home"
// profile so backupSvc → ObjectSvc → ActiveProfile + Creds.Load all
// resolve. Mirrors newRootForObjectTest but with the backup-flavoured
// fake client.
func newRootForBackupTest(t *testing.T, bodies map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeBackupClient{bodies: bodies}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).
		Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestCmd_Backup_DryShape(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"backup", "--help"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "Snapshot the firewall config")
	require.Contains(t, out.String(), "--out")
	require.Contains(t, out.String(), "--types")
	require.Contains(t, out.String(), "--exclude")
}

func TestCmd_Backup_TypesAndExcludeRejected(t *testing.T) {
	d := newRootForBackupTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"backup", "--types", "IPHost", "--exclude", "Zone"})
	err := root.Execute()
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
}

func TestCmd_Backup_CreatesSnapshotInTempDir(t *testing.T) {
	bodies := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"IP","IPAddress":"10.0.0.1"}`)},
	}
	d := newRootForBackupTest(t, bodies)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	snap := filepath.Join(t.TempDir(), "snap")
	root.SetArgs([]string{"backup", "--out", snap, "--types", "IPHost"})
	require.NoError(t, root.Execute())

	// _meta.yaml present → atomic rename succeeded.
	metaPath := filepath.Join(snap, "_meta.yaml")
	_, err := os.Stat(metaPath)
	require.NoError(t, err, "expected _meta.yaml in %s", snap)

	// IPHost record file written.
	recPath := filepath.Join(snap, "IPHost", "lan.yaml")
	_, err = os.Stat(recPath)
	require.NoError(t, err, "expected per-record file at %s", recPath)

	require.Contains(t, out.String(), "Backup written:")
}

func TestCmd_BackupList_EmptyShape(t *testing.T) {
	d := newRootForBackupTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"backup", "list"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "No snapshots.")
}

func TestCmd_BackupRotate_RequiresKeep(t *testing.T) {
	d := newRootForBackupTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"backup", "rotate"})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "keep"),
		"expected required-flag error mentioning 'keep', got: %v", err)
}
