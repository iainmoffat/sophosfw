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

type fakeMcpMutClient struct {
	sent [][]byte
	body map[string][]json.RawMessage
}

func (f *fakeMcpMutClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (f *fakeMcpMutClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newMutMcpServer(t *testing.T, body map[string][]json.RawMessage) (*Server, *fakeMcpMutClient) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	fc := &fakeMcpMutClient{body: body}
	audit := svc.NewAuditLog(t.TempDir(), true)
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fc },
		DefaultProfile: "home",
		Audit:          audit,
		BaseDir:        t.TempDir(),
	}), fc
}

func TestHostIpCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleHostIpCreate(context.Background(), nil, HostIpCreateInput{
		Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestHostIpCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleHostIpCreate(context.Background(), nil, HostIpCreateInput{
		Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestHostIpCreate_Handler_Apply(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	s, fc := newMutMcpServer(t, body)
	out, _, err := s.handleHostIpCreate(context.Background(), nil, HostIpCreateInput{
		Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
		Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
}

func TestHostIpUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	})
	out, _, err := s.handleHostIpUpdate(context.Background(), nil, HostIpUpdateInput{
		HostIpCreateInput: HostIpCreateInput{
			Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
			Confirm: true, DryRun: false,
		},
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestHostIpDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, _ := svc.DiffHash(current)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	})
	out, _, err := s.handleHostIpDelete(context.Background(), nil, HostIpDeleteInput{
		Name: "X", ExpectedDiffHash: hash,
		Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
}

func TestHostIpUpdate_Handler_DryRun(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, _ := svc.DiffHash(current)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	})
	out, _, err := s.handleHostIpUpdate(context.Background(), nil, HostIpUpdateInput{
		HostIpCreateInput: HostIpCreateInput{
			Name: "X", HostType: "IP", IpAddress: "9.9.9.9",
			Confirm: true, DryRun: true,
		},
		ExpectedDiffHash: hash,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent, "dry-run must not send the envelope")
}

func TestHostIpUpdate_Handler_Apply_Succeeds(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, _ := svc.DiffHash(current)
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	s, fc := newMutMcpServer(t, body)
	out, _, err := s.handleHostIpUpdate(context.Background(), nil, HostIpUpdateInput{
		HostIpCreateInput: HostIpCreateInput{
			Name: "X", HostType: "IP", IpAddress: "9.9.9.9",
			Confirm: true, DryRun: false,
		},
		ExpectedDiffHash: hash,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Len(t, fc.sent, 1)
}

func TestHostIpDelete_Handler_DryRun(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, _ := svc.DiffHash(current)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	})
	out, _, err := s.handleHostIpDelete(context.Background(), nil, HostIpDeleteInput{
		Name: "X", ExpectedDiffHash: hash,
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent, "dry-run must not send the envelope")
}
