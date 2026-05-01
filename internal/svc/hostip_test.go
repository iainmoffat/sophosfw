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

// fakeIPHostClient returns the same body for any IPHost Get.
type fakeIPHostClient struct {
	body map[string][]json.RawMessage
}

func (f fakeIPHostClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeIPHostClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newHostIPSvc(t *testing.T, body map[string][]json.RawMessage) *HostIPSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeIPHostClient{body: body} },
	}
	return &HostIPSvc{Inner: inner}
}

func TestHostIPSvc_List_EnrichesCidrForNetwork(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newHostIPSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "10.0.0.0/24", out.Items[0].Derived.CIDR)
	require.Equal(t, "network", out.Items[0].Derived.Kind)
}

func TestHostIPSvc_List_OmitsCidrForHost(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"Public-DNS","IPFamily":"IPv4","HostType":"IP","IPAddress":"8.8.8.8"}`),
		},
	}
	s := newHostIPSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "host", out.Items[0].Derived.Kind)
	require.Empty(t, out.Items[0].Derived.CIDR)
}

func TestHostIPSvc_List_NormalizesUnknownHostType(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"WeirdNew"}`)},
	}
	s := newHostIPSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	// Unknown HostType leaves Kind empty (no false claim).
	require.Empty(t, out.Items[0].Derived.Kind)
}

func TestHostIPSvc_Get_ReturnsTypedAndEnriched(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newHostIPSvc(t, body)
	out, err := s.Get(context.Background(), "home", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, "LAN-network", out.Name)
	require.Equal(t, "10.0.0.0/24", out.Derived.CIDR)
}

func TestSubnetToPrefix_Common(t *testing.T) {
	cases := []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.0.0.0", 8},
		{"255.255.255.255", 32},
		{"0.0.0.0", 0},
		{"255.255.255.128", 25},
	}
	for _, c := range cases {
		got, err := subnetToPrefix(c.mask)
		require.NoError(t, err, "mask=%s", c.mask)
		require.Equal(t, c.want, got, "mask=%s", c.mask)
	}
}

func TestSubnetToPrefix_Invalid(t *testing.T) {
	_, err := subnetToPrefix("not-a-mask")
	require.Error(t, err)
}
