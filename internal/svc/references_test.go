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

// fakeRefClient returns canned responses keyed by the GetOp's XMLTag.
// errs[tag] makes that tag's lookup fail.
type fakeRefClient struct {
	body map[string][]json.RawMessage
	errs map[string]error
}

func (f fakeRefClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	if len(env.Operations) == 0 {
		return &sophos.Response{LoginOK: true}, nil
	}
	op, ok := env.Operations[0].(sophos.GetOp)
	if !ok {
		return &sophos.Response{LoginOK: true}, nil
	}
	if e := f.errs[op.XMLTag]; e != nil {
		return nil, e
	}
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if recs, ok := f.body[op.XMLTag]; ok {
		resp.Body[op.XMLTag] = recs
	}
	return resp, nil
}
func (fakeRefClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRefSvc(t *testing.T, body map[string][]json.RawMessage, errs map[string]error) *ObjectSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return &ObjectSvc{
		Config:    cfg,
		Creds:     store,
		Catalog:   cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeRefClient{body: body, errs: errs} },
	}
}

func TestFindReferences_AllSucceed(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"LAN-group","HostList":["LAN-network","LAN-DHCP"]}`)},
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN-network"],"Action":"Accept"}`),
			json.RawMessage(`{"Name":"DMZ-To-WAN","Sources":["DMZ-network"],"Action":"Accept"}`),
		},
		"NATRule": {},
	}
	svc := newRefSvc(t, body, nil)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, []string{"LAN-group"}, got.Refs["IPHostGroup"])
	require.Equal(t, []string{"LAN-To-WAN"}, got.Refs["FirewallRule"])
	require.Equal(t, []string{}, got.Refs["NATRule"])
	require.Empty(t, got.Errors)
}

func TestFindReferences_OneReferrerFails(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"LAN-group","HostList":["LAN-network"]}`)},
		"NATRule":     {},
	}
	errs := map[string]error{"FirewallRule": sophos.ErrPermissionDenied}
	svc := newRefSvc(t, body, errs)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, []string{"LAN-group"}, got.Refs["IPHostGroup"])
	require.Equal(t, []string{}, got.Refs["NATRule"])
	require.Contains(t, got.Errors["FirewallRule"], "permission")
}

func TestFindReferences_PrimaryNotInMap(t *testing.T) {
	svc := newRefSvc(t, nil, nil)
	_, err := FindReferences(context.Background(), svc, "home", "Interface", "eth0")
	require.Error(t, err)
}

func TestFindReferences_ExactMatchOnly(t *testing.T) {
	// "LAN-network-extra" must NOT match a query for "LAN-network".
	body := map[string][]json.RawMessage{
		"IPHostGroup":  {json.RawMessage(`{"Name":"LAN-extra-group","HostList":["LAN-network-extra"]}`)},
		"FirewallRule": {},
		"NATRule":      {},
	}
	svc := newRefSvc(t, body, nil)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Empty(t, got.Refs["IPHostGroup"])
}
