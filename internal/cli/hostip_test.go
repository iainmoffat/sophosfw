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

type fakeHostIpCliClient struct{ body map[string][]json.RawMessage }

func (f fakeHostIpCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	switch op := env.Operations[0].(type) {
	case sophos.GetOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	case sophos.StatisticsOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeHostIpCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForHostIpTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeHostIpCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestHostIp_List_JSONHasDerivedBlock(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpList"`)
	require.Contains(t, out.String(), `"xmlTag": "IPHost"`)
	require.Contains(t, out.String(), `"cidr": "10.0.0.0/24"`)
	require.Contains(t, out.String(), `"kind": "network"`)
}

func TestHostIp_List_TablePrintsCidrColumn(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "list", "--columns", "Name,derived.cidr,derived.kind"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN")
	require.Contains(t, out.String(), "10.0.0.0/24")
	require.Contains(t, out.String(), "network")
}

func TestHostIp_Show_Positional(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "show", "LAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIp"`)
	require.Contains(t, out.String(), `"Name": "LAN"`)
}

func TestHostIp_Search_FiltersClientSide(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "search", "LAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpSearch"`)
	require.Contains(t, out.String(), `"Name": "LAN"`)
	// DMZ must not appear in the search output.
	require.False(t, strings.Contains(out.String(), `"Name": "DMZ"`))
}

func TestHostIp_Usage_WithReferences_JSONShape(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostStatistics": {json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)},
		"IPHostGroup":      {json.RawMessage(`{"Name":"LAN-grp","HostList":["LAN","DMZ"]}`)},
		"FirewallRule":     {json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN"]}`)},
		"NATRule":          {},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "usage", "LAN", "--with-references", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpUsage"`)
	require.Contains(t, out.String(), `"references"`)
	require.Contains(t, out.String(), `"IPHostGroup"`)
	require.Contains(t, out.String(), `"LAN-grp"`)
}
