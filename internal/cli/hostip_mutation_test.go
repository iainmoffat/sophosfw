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

type fakeMutCliClient struct {
	sent [][]byte
	body map[string][]json.RawMessage
}

func (f *fakeMutCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (f *fakeMutCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForHostIpMutTest(t *testing.T, body map[string][]json.RawMessage) (*RootDeps, *fakeMutCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeMutCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestHostIp_Create_DryRunDefault(t *testing.T) {
	d, fc := newRootForHostIpMutTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "create",
		"--name", "LAN-network", "--host-type", "Network",
		"--ip-address", "10.0.0.0", "--subnet", "255.255.255.0",
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.preview"`)
	require.Contains(t, out.String(), `"mutating": true`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestHostIp_Create_YesApplies(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d, fc := newRootForHostIpMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "create",
		"--name", "LAN-network", "--host-type", "Network",
		"--ip-address", "10.0.0.0", "--subnet", "255.255.255.0",
		"--yes", "--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, out.String(), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
}

func TestHostIp_Update_RequiresExpectedDiffHash(t *testing.T) {
	d, _ := newRootForHostIpMutTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "update",
		"--name", "X", "--host-type", "IP", "--ip-address", "1.1.1.1",
		"--yes",
	})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expectedDiffHash") || strings.Contains(err.Error(), "expected-diff-hash"))
}

func TestHostIp_Delete_PositionalArg(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	d, fc := newRootForHostIpMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	hash, _ := svc.DiffHash(struct {
		Name      string `json:"Name"`
		IPFamily  string `json:"IPFamily"`
		HostType  string `json:"HostType"`
		IPAddress string `json:"IPAddress"`
	}{"X", "IPv4", "IP", "1.1.1.1"})
	root.SetArgs([]string{"host", "ip", "delete", "X",
		"--expected-diff-hash", hash, "--yes", "--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
}

func TestHostIp_Show_IncludesDiffHashByDefault(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	d, _ := newRootForHostIpMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "show", "X", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"_diffHash":`)
}
