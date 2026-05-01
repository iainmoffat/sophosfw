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

type fakeHostIpMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeHostIpMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeHostIpMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newHostIpTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeHostIpMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestHostIpList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpList(context.Background(), nil, HostIpListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.hostIpList"`)
	require.Contains(t, body2, `"cidr": "10.0.0.0/24"`)
}

func TestHostIpShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpShow(context.Background(), nil, HostIpShowInput{Name: "LAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIp"`)
}

func TestHostIpSearch_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpSearch(context.Background(), nil, HostIpSearchInput{Query: "LAN"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.hostIpSearch"`)
	require.Contains(t, body2, `"Name": "LAN"`)
}

func TestHostIpUsage_WithReferences(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostStatistics": {json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)},
		"IPHostGroup":      {json.RawMessage(`{"Name":"LAN-grp","HostList":["LAN"]}`)},
		"FirewallRule":     {json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN"]}`)},
		"NATRule":          {},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpUsage(context.Background(), nil, HostIpUsageInput{Name: "LAN", WithReferences: true})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.hostIpUsage"`)
	require.Contains(t, body2, `"references"`)
	require.Contains(t, body2, `"LAN-grp"`)
}
