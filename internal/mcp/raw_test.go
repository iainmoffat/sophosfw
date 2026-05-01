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

type fakeRawMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeRawMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeRawMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRawTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeRawMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestRawGet_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4"}`)},
	}
	s := newRawTestServer(t, body)
	out, _, err := s.handleRawGet(context.Background(), nil, RawGetInput{XmlTag: "IPHost"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.rawResponse"`)
	require.Contains(t, body2, `"xmlTag": "IPHost"`)
}
