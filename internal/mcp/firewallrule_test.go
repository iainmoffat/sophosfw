package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeFwMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeFwMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeFwMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newFwTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeFwMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestFirewallRuleList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable","SourceZones":["LAN"]}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleFirewallRuleList(context.Background(), nil, FirewallRuleListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.firewallRuleList"`)
	require.Contains(t, body2, `"xmlTag": "FirewallRule"`)
	require.Contains(t, body2, `"Name": "LAN-To-WAN"`)
}

func TestFirewallRuleShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleFirewallRuleShow(context.Background(), nil, FirewallRuleShowInput{Name: "LAN-To-WAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRule"`)
}
