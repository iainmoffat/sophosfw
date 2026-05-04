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

type fakeIPsecClient struct {
	body map[string][]json.RawMessage
}

func (f fakeIPsecClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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

func (fakeIPsecClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newVPNIPsecSvc(t *testing.T, body map[string][]json.RawMessage) *VPNIPsecSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeIPsecClient{body: body} },
	}
	return &VPNIPsecSvc{Inner: inner}
}

func TestVPNIPsec_Get_ReturnsBody(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {
			json.RawMessage(`{"Name":"site-a","Status":"Enable","ConnectionType":"SiteToSite","AuthenticationType":"PresharedKey","Strategy":"Respond"}`),
		},
	}
	s := newVPNIPsecSvc(t, body)
	got, err := s.Get(context.Background(), "home", "site-a")
	require.NoError(t, err)
	require.Equal(t, "site-a", got["Name"])
	require.Equal(t, "Enable", got["Status"])
	require.Equal(t, "SiteToSite", got["ConnectionType"])
}

func TestVPNIPsec_Get_NotFound_ReturnsErrNotFound(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {},
	}
	s := newVPNIPsecSvc(t, body)
	_, err := s.Get(context.Background(), "home", "missing")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrNotFound)
}

func TestVPNIPsec_Get_InjectsDiffHash(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {
			json.RawMessage(`{"Name":"site-a","Status":"Enable","ConnectionType":"SiteToSite"}`),
		},
	}
	s := newVPNIPsecSvc(t, body)
	got, err := s.Get(context.Background(), "home", "site-a")
	require.NoError(t, err)
	hash, ok := got["_diffHash"]
	require.True(t, ok, "_diffHash should be injected for mutable catalog entries")
	require.NotEmpty(t, hash)
}
