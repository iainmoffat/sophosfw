package svc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeFwClient struct {
	body map[string][]json.RawMessage
}

func (f fakeFwClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeFwClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newFwSvc(t *testing.T, body map[string][]json.RawMessage) *FirewallRuleSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeFwClient{body: body} },
	}
	return &FirewallRuleSvc{Inner: inner}
}

func TestFirewallRuleSvc_List_UntypedItems(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","SourceZones":["LAN"],"DestinationZones":["WAN"],"Status":"Enable"}`),
			json.RawMessage(`{"Name":"DMZ-Inbound","Action":"Drop","SourceZones":["WAN"],"DestinationZones":["DMZ"],"Status":"Enable"}`),
		},
	}
	s := newFwSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 2)
	require.Equal(t, "LAN-To-WAN", out.Items[0]["Name"])
	require.Equal(t, "Accept", out.Items[0]["Action"])
}

func TestFirewallRuleSvc_Get_ByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable"}`),
		},
	}
	s := newFwSvc(t, body)
	rule, err := s.Get(context.Background(), "home", "LAN-To-WAN")
	require.NoError(t, err)
	require.Equal(t, "LAN-To-WAN", rule["Name"])
	require.Equal(t, "Accept", rule["Action"])
}

func TestFirewallRuleSvc_Get_NotFound(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {},
	}
	s := newFwSvc(t, body)
	_, err := s.Get(context.Background(), "home", "missing")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrNotFound)
}
