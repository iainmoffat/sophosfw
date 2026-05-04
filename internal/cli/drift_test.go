package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// driftRoot is a thin convenience that wraps newRootForBackupTest +
// returns a fresh root + buffers without seeding a snapshot. Used by
// the "neither set" / "both set" guard tests where no snapshot is
// needed because we expect the CLI to bail before touching the FS.
func driftRoot(t *testing.T) (*bytes.Buffer, *bytes.Buffer, func(args ...string) error) {
	t.Helper()
	d := newRootForBackupTest(t, nil)
	root := NewRoot(*d)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	return stdout, stderr, func(args ...string) error {
		root.SetArgs(args)
		return root.Execute()
	}
}

func TestCmd_Drift_RequiresSnapshotOrLatest(t *testing.T) {
	_, _, run := driftRoot(t)
	err := run("--profile", "home", "drift")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "snapshot")
}

func TestCmd_Drift_SnapshotAndLatestRejected(t *testing.T) {
	_, _, run := driftRoot(t)
	err := run("--profile", "home", "drift", "/tmp/some/snap", "--latest")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestCmd_Drift_NoChangesReturnsNil(t *testing.T) {
	// Seed a snapshot, then drift against the same fake client. With
	// identical live + snapshot state the summary is all-unchanged and
	// the command must return nil (exit 0).
	bodies := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"IP","IPAddress":"10.0.0.1"}`)},
	}
	d := newRootForBackupTest(t, bodies)

	snap := filepath.Join(t.TempDir(), "snap")
	rootSeed := NewRoot(*d)
	bufSeed := &bytes.Buffer{}
	rootSeed.SetOut(bufSeed)
	rootSeed.SetErr(bufSeed)
	rootSeed.SetArgs([]string{"--profile", "home", "backup", "--out", snap})
	require.NoError(t, rootSeed.Execute(), bufSeed.String())

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"--profile", "home", "drift", snap})
	require.NoError(t, root.Execute(), out.String())
	require.Contains(t, out.String(), "Total: 0 added, 0 modified, 0 removed")
}

func TestCmd_Drift_WithChangesReturnsErrDriftDetected(t *testing.T) {
	// Seed snapshot with one IPHost; live has two → drift reports one
	// "added", and the command must return ErrDriftDetected so main()
	// exits 1.
	seedBodies := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"IP","IPAddress":"10.0.0.1"}`)},
	}
	d := newRootForBackupTest(t, seedBodies)

	// Step 1: seed snapshot with the small body set.
	snap := filepath.Join(t.TempDir(), "snap")
	rootSeed := NewRoot(*d)
	bufSeed := &bytes.Buffer{}
	rootSeed.SetOut(bufSeed)
	rootSeed.SetErr(bufSeed)
	rootSeed.SetArgs([]string{"--profile", "home", "backup", "--out", snap})
	require.NoError(t, rootSeed.Execute(), bufSeed.String())

	// Step 2: swap the fake client to return a SUPERSET of the snapshot
	// state, so drift sees an "added" record.
	driftBodies := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"IP","IPAddress":"10.0.0.1"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"IP","IPAddress":"10.0.1.1"}`),
		},
	}
	d2 := *d
	d2.NewClient = newRootForBackupTest(t, driftBodies).NewClient
	// Reuse the same on-disk profile/baseDir so the snapshot is found.
	d2.BaseDir = d.BaseDir
	d2.Config = d.Config
	d2.Creds = d.Creds

	root := NewRoot(d2)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"--profile", "home", "drift", snap})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDriftDetected),
		"expected ErrDriftDetected, got %T: %v", err, err)
	// Output was emitted before the sentinel return.
	require.Contains(t, out.String(), "added")
}

func TestCmd_Drift_JSONOutputContainsSchema(t *testing.T) {
	bodies := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"IP","IPAddress":"10.0.0.1"}`)},
	}
	d := newRootForBackupTest(t, bodies)

	snap := filepath.Join(t.TempDir(), "snap")
	rootSeed := NewRoot(*d)
	bufSeed := &bytes.Buffer{}
	rootSeed.SetOut(bufSeed)
	rootSeed.SetErr(bufSeed)
	rootSeed.SetArgs([]string{"--profile", "home", "backup", "--out", snap})
	require.NoError(t, rootSeed.Execute(), bufSeed.String())

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"--profile", "home", "--json", "drift", snap})
	require.NoError(t, root.Execute(), out.String())
	require.True(t, strings.Contains(out.String(), `"sophosfw.v1.drift"`),
		"expected drift envelope schema, got: %s", out.String())
}

// TestCmd_Drift_HandleError_DriftDetectedIsExit1 verifies the wiring
// from ErrDriftDetected → HandleError → exit 1 with a silent stderr.
// This is the contract that makes the CLI cron-friendly: drift must
// look like `git diff --exit-code` (1, no message) rather than a real
// error (2+, with envelope or stderr line).
func TestCmd_Drift_HandleError_DriftDetectedIsExit1(t *testing.T) {
	d := newRootForBackupTest(t, nil)
	root := NewRoot(*d)
	code := HandleError(root, ErrDriftDetected)
	require.Equal(t, 1, code)
}
