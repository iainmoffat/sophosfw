package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// fakeIpHostGroupCliClient is the test double for the CLI mutation
// commands. It mirrors fakeFwRuleMutCliClient but answers IPHostGroup
// Get queries.
type fakeIpHostGroupCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeIpHostGroupCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "IPHostGroup" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["IPHostGroup"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}
func (f *fakeIpHostGroupCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForHostGroupTest(t *testing.T, body map[string]any) (*RootDeps, *fakeIpHostGroupCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeIpHostGroupCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

// writeBodyFile drops a JSON body fixture under dir for use with
// `--body @<path>`.
func writeBodyFile(t *testing.T, dir string, body map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	path := filepath.Join(dir, "body.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func TestCmd_HostGroupCreate_DryRun_Smoke(t *testing.T) {
	d, fc := newRootForHostGroupTest(t, nil)
	bodyPath := writeBodyFile(t, d.BaseDir, map[string]any{"Name": "G1", "IPFamily": "IPv4"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "group", "create", "G1", "--body", "@" + bodyPath, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.ipHostGroupMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_HostGroupCreate_RejectsBodyNameMismatch(t *testing.T) {
	d, fc := newRootForHostGroupTest(t, nil)
	bodyPath := writeBodyFile(t, d.BaseDir, map[string]any{"Name": "Mismatch", "IPFamily": "IPv4"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "group", "create", "G1", "--body", "@" + bodyPath})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
	require.Empty(t, fc.sent)
}

func TestCmd_HostGroupUpdate_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForHostGroupTest(t, live)
	bodyPath := writeBodyFile(t, d.BaseDir, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "group", "update", "G1",
		"--body", "@" + bodyPath,
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.ipHostGroupMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_HostGroupDelete_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForHostGroupTest(t, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "group", "delete", "G1",
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.ipHostGroupMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}
