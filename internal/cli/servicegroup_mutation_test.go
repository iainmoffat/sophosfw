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

// fakeServiceGroupCliClient is the test double for the CLI mutation
// commands. It mirrors fakeFqdnHostGroupCliClient but answers ServiceGroup
// Get queries.
type fakeServiceGroupCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeServiceGroupCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "ServiceGroup" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["ServiceGroup"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}
func (f *fakeServiceGroupCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForServiceGroupTest(t *testing.T, body map[string]any) (*RootDeps, *fakeServiceGroupCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeServiceGroupCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestCmd_ServiceGroupCreate_DryRun_Smoke(t *testing.T) {
	d, fc := newRootForServiceGroupTest(t, nil)
	bodyPath := writeBodyFile(t, d.BaseDir, map[string]any{"Name": "g"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "group", "create", "g", "--body", "@" + bodyPath, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceGroupMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_ServiceGroupCreate_RejectsBodyNameMismatch(t *testing.T) {
	d, fc := newRootForServiceGroupTest(t, nil)
	bodyPath := writeBodyFile(t, d.BaseDir, map[string]any{"Name": "Mismatch"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "group", "create", "g", "--body", "@" + bodyPath})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
	require.Empty(t, fc.sent)
}

func TestCmd_ServiceGroupUpdate_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "g"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForServiceGroupTest(t, live)
	bodyPath := writeBodyFile(t, d.BaseDir, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "group", "update", "g",
		"--body", "@" + bodyPath,
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceGroupMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_ServiceGroupDelete_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "g"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForServiceGroupTest(t, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "group", "delete", "g",
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceGroupMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}
