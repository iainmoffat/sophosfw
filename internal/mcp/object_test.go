package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeObjectMcpClient struct {
	body map[string][]json.RawMessage
}

func (f fakeObjectMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeObjectMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newObjectTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeObjectMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestObjectList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectList(context.Background(), nil, ObjectListInput{Tag: "IPHost"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, body2, `"xmlTag": "IPHost"`)
	require.Contains(t, body2, `"Name": "LAN"`)
}

func TestObjectGet_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectGet(context.Background(), nil, ObjectGetInput{Tag: "IPHost", Name: "LAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.object"`)
	require.Contains(t, textOf(out), `"name": "LAN"`)
}

// TestObjectGet_PassesDiffHashThrough confirms the MCP object_get handler
// surfaces the _diffHash that ObjectSvc.Get injects for catalog-mutable
// types (Phase 12). Update/delete callers use this hash as
// expectedDiffHash without a separate query.
func TestObjectGet_PassesDiffHashThrough(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectGet(context.Background(), nil, ObjectGetInput{Tag: "IPHost", Name: "LAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"_diffHash"`)
}

func TestObjectGet_NotFound_ReturnsErrorEnvelope(t *testing.T) {
	s := newObjectTestServer(t, map[string][]json.RawMessage{"IPHost": {}})
	out, _, err := s.handleObjectGet(context.Background(), nil, ObjectGetInput{Tag: "IPHost", Name: "missing"})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.error"`)
	require.Contains(t, body, `"kind": "not_found"`)
}

func TestObjectSearch_FiltersByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectSearch(context.Background(), nil, ObjectSearchInput{Tag: "IPHost", Query: "LAN"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, body2, `"Name": "LAN"`)
	require.False(t, strings.Contains(body2, `"Name": "DMZ"`))
}

func TestObjectUsage_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostStatistics": {json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectUsage(context.Background(), nil, ObjectUsageInput{Tag: "IPHost", Name: "LAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.objectUsage"`)
	require.Contains(t, textOf(out), `"HitCount": "42"`)
}
