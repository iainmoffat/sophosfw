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

type fakeFwRuleCliClient struct{ body map[string][]json.RawMessage }

func (f fakeFwRuleCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeFwRuleCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForFwRuleTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeFwRuleCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestFirewallRule_List_DefaultColumnsAndArrayCells(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable","Position":"1","IPFamily":"IPv4","SourceZones":["LAN","DMZ"],"DestinationZones":["WAN"]}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "list"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN-To-WAN")
	// Array cell collapsed to comma-joined: "LAN, DMZ"
	require.Contains(t, out.String(), "LAN, DMZ")
}

func TestFirewallRule_List_JSONEnvelopeWithXmlTag(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable"}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRuleList"`)
	require.Contains(t, out.String(), `"xmlTag": "FirewallRule"`)
	require.Contains(t, out.String(), `"Name": "LAN-To-WAN"`)
}

func TestFirewallRule_List_ColumnsOverride(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable","Position":"1"}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "list", "--columns", "Name,Action"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN-To-WAN")
	require.Contains(t, out.String(), "Accept")
	// Status is in the catalog default but NOT requested.
	require.False(t, strings.Contains(out.String(), "Enable"))
}

func TestFirewallRule_Show_ByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable"}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "show", "LAN-To-WAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRule"`)
	require.Contains(t, out.String(), `"Name": "LAN-To-WAN"`)
}
