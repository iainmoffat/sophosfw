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

type fakeNatMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeNatMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeNatMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newNatTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeNatMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestNATRuleList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {json.RawMessage(`{"Name":"WAN-Out","Status":"Enable","OriginalSourceNetworks":["LAN-network"]}`)},
	}
	s := newNatTestServer(t, body)
	out, _, err := s.handleNATRuleList(context.Background(), nil, NATRuleListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.natRuleList"`)
	require.Contains(t, body2, `"xmlTag": "NATRule"`)
	require.Contains(t, body2, `"Name": "WAN-Out"`)
}

func TestNATRuleShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {json.RawMessage(`{"Name":"WAN-Out","Status":"Enable"}`)},
	}
	s := newNatTestServer(t, body)
	out, _, err := s.handleNATRuleShow(context.Background(), nil, NATRuleShowInput{Name: "WAN-Out"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRule"`)
}

func TestNATRuleShow_Handler_IncludesDiffHash(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {json.RawMessage(`{"Name":"X","Status":"Enable","IPFamily":"IPv4"}`)},
	}
	s := newNatTestServer(t, body)
	out, _, err := s.handleNATRuleShow(context.Background(), nil, NATRuleShowInput{Name: "X"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"_diffHash":`)
}
