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

// fakeVPNIPsecCliClient mirrors fakeFwRuleMutCliClient. It records every
// raw envelope sent (push/delete) and replays a canned VPNIPsecConnection
// body for any matching Get.
type fakeVPNIPsecCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeVPNIPsecCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "VPNIPsecConnection" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["VPNIPsecConnection"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeVPNIPsecCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForVPNIPsecTest(t *testing.T, body map[string]any) (*RootDeps, *fakeVPNIPsecCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeVPNIPsecCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestCmd_VPNIPsec_List_DryShape(t *testing.T) {
	// Smoke: `vpn ipsec list --help` exits cleanly with the parent
	// description, proving the sub-tree is wired.
	d, _ := newRootForVPNIPsecTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ipsec", "list", "--help"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "List IPsec VPN tunnels")
}

func TestCmd_VPNIPsec_List_JSONEnvelope(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	d, _ := newRootForVPNIPsecTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ipsec", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.vpnIPsecList"`)
	require.Contains(t, out.String(), `"xmlTag": "VPNIPsecConnection"`)
	require.Contains(t, out.String(), `"Name": "site-a"`)
}

func TestCmd_VPNIPsec_New_FromTemplate(t *testing.T) {
	// `vpn ipsec new <name>` with no --from writes a draft from the
	// embedded template. SnapshotPath/DiffHash stay empty so the
	// success message takes the "snapshot none" branch.
	d, _ := newRootForVPNIPsecTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ipsec", "new", "test-tunnel"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "Draft written:")
	require.Contains(t, out.String(), "first push will create one")
	require.Contains(t, out.String(), "sophosfw vpn ipsec push test-tunnel --yes")
}

func TestCmd_VPNIPsec_New_JSON(t *testing.T) {
	d, _ := newRootForVPNIPsecTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ipsec", "new", "test-tunnel", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.vpnIPsecPull"`)
	require.Contains(t, out.String(), `"tunnel": "test-tunnel"`)
	require.Contains(t, out.String(), `"diffHash": ""`)
}

func TestCmd_VPNIPsec_Push_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	d, fc := newRootForVPNIPsecTest(t, body)

	// First pull to seed draft + snapshot.
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ipsec", "pull", "site-a"})
	require.NoError(t, root.Execute())

	// Push --dry-run (default) emits a preview envelope and sends nothing.
	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"vpn", "ipsec", "push", "site-a", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"dryRun": true`)
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.vpnIPsecPush"`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_VPNIPsec_Delete_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	d, fc := newRootForVPNIPsecTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	// Delete is dry-run by default. The svc-level Delete still
	// requires expectedDiffHash unless --ignore-diff-hash is passed
	// (the CLI's --yes gate is in addition to that).
	root.SetArgs([]string{"vpn", "ipsec", "delete", "site-a", "--ignore-diff-hash", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"dryRun": true`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Empty(t, fc.sent, "dry-run delete must not send")
}

func TestCmd_VPNIPsec_PushHelp_HasProfileSet(t *testing.T) {
	// Phase 14 fan-out: --profile-set must be wired on push.
	d, _ := newRootForVPNIPsecTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"vpn", "ipsec", "push", "--help"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "--profile-set")
}
