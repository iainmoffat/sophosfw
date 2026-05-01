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

type fakeServiceMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeServiceMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeServiceMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newServiceTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeServiceMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestServiceList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceList(context.Background(), nil, ServiceListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.serviceList"`)
	require.Contains(t, body2, `"xmlTag": "Services"`)
	require.Contains(t, body2, `"protocol": "tcp"`)
	require.Contains(t, body2, `"portRange": "80"`)
}

func TestServiceShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceShow(context.Background(), nil, ServiceShowInput{Name: "HTTP"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.service"`)
	require.Contains(t, textOf(out), `"Name": "HTTP"`)
}

func TestServiceSearch_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`),
			json.RawMessage(`{"Name":"SSH","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"22"}]}}`),
		},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceSearch(context.Background(), nil, ServiceSearchInput{Query: "SSH"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.serviceSearch"`)
	require.Contains(t, body2, `"Name": "SSH"`)
	require.False(t, strings.Contains(body2, `"Name": "HTTP"`))
}

func TestServiceUsage_WithReferences(t *testing.T) {
	body := map[string][]json.RawMessage{
		"ServicesStatistics": {json.RawMessage(`{"Name":"HTTP","HitCount":"42"}`)},
		"ServiceGroup":       {json.RawMessage(`{"Name":"Web-svcs","ServiceList":["HTTP","HTTPS"]}`)},
		"FirewallRule":       {json.RawMessage(`{"Name":"Web-Out","Services":["HTTP"]}`)},
		"NATRule":            {},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceUsage(context.Background(), nil, ServiceUsageInput{Name: "HTTP", WithReferences: true})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.serviceUsage"`)
	require.Contains(t, body2, `"references"`)
	require.Contains(t, body2, `"Web-svcs"`)
}
