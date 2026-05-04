package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// fakeFqdnHostGroupCliClient is the test double for the CLI mutation
// commands. It mirrors fakeIpHostGroupCliClient but answers FQDNHostGroup
// Get queries.
type fakeFqdnHostGroupCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeFqdnHostGroupCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "FQDNHostGroup" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["FQDNHostGroup"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}
func (f *fakeFqdnHostGroupCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForFqdnHostGroupTest(t *testing.T, body map[string]any) (*RootDeps, *fakeFqdnHostGroupCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeFqdnHostGroupCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestCmd_HostFqdnGroupCreate_DryRun_Smoke(t *testing.T) {
	d, fc := newRootForFqdnHostGroupTest(t, nil)
	bodyPath := writeBodyFile(t, d.BaseDir, map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "fqdn-group", "create", "F1", "--body", "@" + bodyPath, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.fqdnHostGroupMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_HostFqdnGroupCreate_RejectsBodyNameMismatch(t *testing.T) {
	d, fc := newRootForFqdnHostGroupTest(t, nil)
	bodyPath := writeBodyFile(t, d.BaseDir, map[string]any{"Name": "Mismatch", "FQDN": "example.com", "IPFamily": "IPv4"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "fqdn-group", "create", "F1", "--body", "@" + bodyPath})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
	require.Empty(t, fc.sent)
}

func TestCmd_HostFqdnGroupUpdate_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForFqdnHostGroupTest(t, live)
	bodyPath := writeBodyFile(t, d.BaseDir, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "fqdn-group", "update", "F1",
		"--body", "@" + bodyPath,
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.fqdnHostGroupMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_HostFqdnGroupDelete_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForFqdnHostGroupTest(t, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "fqdn-group", "delete", "F1",
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.fqdnHostGroupMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}
