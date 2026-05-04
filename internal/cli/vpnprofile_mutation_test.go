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

// fakeVPNProfileCliClient mirrors fakeIpsecPolicyCliClient but answers
// VPNProfile Get queries.
type fakeVPNProfileCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeVPNProfileCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "VPNProfile" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["VPNProfile"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}
func (f *fakeVPNProfileCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForVPNProfileTest(t *testing.T, body map[string]any) (*RootDeps, *fakeVPNProfileCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeVPNProfileCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func writeVPNProfileBodyFile(t *testing.T, dir string, body map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	path := filepath.Join(dir, "body.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func TestCmd_VPNIKEProfileCreate_DryRun_Smoke(t *testing.T) {
	d, fc := newRootForVPNProfileTest(t, nil)
	bodyPath := writeVPNProfileBodyFile(t, d.BaseDir, map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ike-profile", "create", "P1", "--body", "@" + bodyPath, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.vpnProfileMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_VPNIKEProfileCreate_RejectsBodyNameMismatch(t *testing.T) {
	d, fc := newRootForVPNProfileTest(t, nil)
	bodyPath := writeVPNProfileBodyFile(t, d.BaseDir, map[string]any{"Name": "Mismatch", "AuthenticationMode": "PresharedKey"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ike-profile", "create", "P1", "--body", "@" + bodyPath})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
	require.Empty(t, fc.sent)
}

func TestCmd_VPNIKEProfileUpdate_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForVPNProfileTest(t, live)
	bodyPath := writeVPNProfileBodyFile(t, d.BaseDir, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ike-profile", "update", "P1",
		"--body", "@" + bodyPath,
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.vpnProfileMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_VPNIKEProfileDelete_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForVPNProfileTest(t, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ike-profile", "delete", "P1",
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.vpnProfileMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}
