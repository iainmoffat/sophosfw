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

type fakeNATClient struct {
	body map[string][]json.RawMessage
}

func (f fakeNATClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeNATClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newNATSvc(t *testing.T, body map[string][]json.RawMessage) *NATRuleSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeNATClient{body: body} },
	}
	return &NATRuleSvc{Inner: inner}
}

func TestNATRuleSvc_List(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Outbound","Status":"Enable","OriginalSourceNetworks":["LAN-network"]}`),
			json.RawMessage(`{"Name":"DMZ-DNAT","Status":"Enable","OriginalSourceNetworks":["Any"]}`),
		},
	}
	s := newNATSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 2)
	require.Equal(t, "WAN-Outbound", out.Items[0]["Name"])
}

func TestNATRuleSvc_Get_ByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Outbound","Status":"Enable"}`),
		},
	}
	s := newNATSvc(t, body)
	rule, err := s.Get(context.Background(), "home", "WAN-Outbound")
	require.NoError(t, err)
	require.Equal(t, "WAN-Outbound", rule["Name"])
}

func TestNATRuleSvc_Get_NotFound(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {},
	}
	s := newNATSvc(t, body)
	_, err := s.Get(context.Background(), "home", "missing")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrNotFound)
}
