// IPsecPolicy is dormant in v0.13.1 — Sophos 22.x XML API does not
// recognize the "IPsecPolicy" tag. Tests excluded from default builds
// behind the `ipsecpolicy_dormant` build tag. See Phase 15.x roadmap.

//go:build ipsecpolicy_dormant

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

// fakeIpsecPolicyCliClient mirrors fakeIpHostGroupCliClient but answers
// IPsecPolicy Get queries.
type fakeIpsecPolicyCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeIpsecPolicyCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "IPsecPolicy" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["IPsecPolicy"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}
func (f *fakeIpsecPolicyCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForIPsecPolicyTest(t *testing.T, body map[string]any) (*RootDeps, *fakeIpsecPolicyCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeIpsecPolicyCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func writeIPsecPolicyBodyFile(t *testing.T, dir string, body map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	path := filepath.Join(dir, "body.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func TestCmd_VPNPolicyCreate_DryRun_Smoke(t *testing.T) {
	d, fc := newRootForIPsecPolicyTest(t, nil)
	bodyPath := writeIPsecPolicyBodyFile(t, d.BaseDir, map[string]any{"Name": "P1"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "policy", "create", "P1", "--body", "@" + bodyPath, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.ipsecPolicyMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_VPNPolicyCreate_RejectsBodyNameMismatch(t *testing.T) {
	d, fc := newRootForIPsecPolicyTest(t, nil)
	bodyPath := writeIPsecPolicyBodyFile(t, d.BaseDir, map[string]any{"Name": "Mismatch"})

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "policy", "create", "P1", "--body", "@" + bodyPath})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
	require.Empty(t, fc.sent)
}

func TestCmd_VPNPolicyUpdate_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForIPsecPolicyTest(t, live)
	bodyPath := writeIPsecPolicyBodyFile(t, d.BaseDir, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "policy", "update", "P1",
		"--body", "@" + bodyPath,
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.ipsecPolicyMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_VPNPolicyDelete_DryRun_Smoke(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForIPsecPolicyTest(t, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "policy", "delete", "P1",
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.ipsecPolicyMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}
