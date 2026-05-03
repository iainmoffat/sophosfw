package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeFwRuleMutCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeFwRuleMutCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "FirewallRule" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["FirewallRule"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}
func (f *fakeFwRuleMutCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForFwRuleMutTest(t *testing.T, body map[string]any) (*RootDeps, *fakeFwRuleMutCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeFwRuleMutCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestFwRule_Pull_WritesFiles_Json(t *testing.T) {
	body := map[string]any{
		"Name": "WAN-to-LAN", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "pull", "WAN-to-LAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRulePull"`)
	require.Contains(t, out.String(), `"rule": "WAN-to-LAN"`)
	require.Contains(t, out.String(), `"diffHash":`)
}

func TestFwRule_Push_DryRunDefault(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, fc := newRootForFwRuleMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "push", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"dryRun": true`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestFwRule_Push_YesApplies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, fc := newRootForFwRuleMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "push", "X", "--yes", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestFwRule_Diff_Json(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "diff", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRuleDiff"`)
	require.Contains(t, out.String(), `"hasChanges": false`)
}

func TestFwRule_Delete_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "delete", "X", "--yes"})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expected-diff-hash") || strings.Contains(err.Error(), "expectedDiffHash"))
}

func TestFwRule_New_WritesDraft_Json(t *testing.T) {
	d, _ := newRootForFwRuleMutTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "new", "MyRule", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRulePull"`)
	require.Contains(t, out.String(), `"rule": "MyRule"`)
	require.Contains(t, out.String(), `"diffHash": ""`)
}

func TestFwRule_New_FromExisting_CopiesBody(t *testing.T) {
	body := map[string]any{
		"Name": "OldRule", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "new", "NewRule", "--from", "OldRule", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"rule": "NewRule"`)
}

func TestFwRule_New_RejectsExistingDraft(t *testing.T) {
	d, _ := newRootForFwRuleMutTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "new", "MyRule"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "new", "MyRule"})
	err := root2.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}
