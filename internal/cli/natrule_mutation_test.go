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

type fakeNATMutCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeNATMutCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "NATRule" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["NATRule"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeNATMutCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForNATMutTest(t *testing.T, body map[string]any) (*RootDeps, *fakeNATMutCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeNATMutCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestNATRule_Pull_WritesFiles_Json(t *testing.T) {
	body := map[string]any{
		"Name": "DNAT-X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, _ := newRootForNATMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "DNAT-X", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRulePull"`)
	require.Contains(t, out.String(), `"rule": "DNAT-X"`)
}

func TestNATRule_Push_DryRunDefault(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, fc := newRootForNATMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"nat", "rule", "push", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"dryRun": true`)
	require.Empty(t, fc.sent)
}

func TestNATRule_Push_YesApplies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, fc := newRootForNATMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"nat", "rule", "push", "X", "--yes", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRule_Diff_Json(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, _ := newRootForNATMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"nat", "rule", "diff", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRuleDiff"`)
	require.Contains(t, out.String(), `"hasChanges": false`)
}

func TestNATRule_Delete_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, _ := newRootForNATMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "delete", "X", "--yes"})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expected-diff-hash") || strings.Contains(err.Error(), "expectedDiffHash"))
}
