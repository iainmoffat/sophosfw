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

func TestHostIPSvc_Search_MultiField(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"Public-DNS","IPFamily":"IPv4","HostType":"IP","IPAddress":"8.8.8.8"}`),
		},
	}
	s := newHostIPSvc(t, body)
	// "10.0.0.0" matches one record's IPAddress
	out, err := s.Search(context.Background(), "home", "10.0.0.0")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "LAN-network", out.Items[0].Name)
}

func TestHostIPSvc_Search_CaseInsensitive(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIPSvc(t, body)
	out, err := s.Search(context.Background(), "home", "lan")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
}

func TestHostIPSvc_Search_NoMatches(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIPSvc(t, body)
	out, err := s.Search(context.Background(), "home", "xyz-nope")
	require.NoError(t, err)
	require.Empty(t, out.Items)
	require.Equal(t, 0, out.Count)
}

// fakeIPHostUsageClient routes Get/Statistics differently. For "IPHostStatistics"
// it returns one stats record; for IPHost it returns nothing (Get-by-name fails);
// for IPHostGroup/FirewallRule/NATRule it returns their canned bodies.
type fakeIPHostUsageClient struct {
	stats     []json.RawMessage
	groupBody []json.RawMessage
	fwBody    []json.RawMessage
	natBody   []json.RawMessage
}

func (f fakeIPHostUsageClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	switch op := env.Operations[0].(type) {
	case sophos.StatisticsOp:
		if op.XMLTag == "IPHostStatistics" {
			resp.Body["IPHostStatistics"] = f.stats
		}
	case sophos.GetOp:
		switch op.XMLTag {
		case "IPHostGroup":
			resp.Body["IPHostGroup"] = f.groupBody
		case "FirewallRule":
			resp.Body["FirewallRule"] = f.fwBody
		case "NATRule":
			resp.Body["NATRule"] = f.natBody
		}
	}
	return resp, nil
}
func (fakeIPHostUsageClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func TestHostIPSvc_Usage_NoRefs(t *testing.T) {
	stats := []json.RawMessage{json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)}
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client {
			return fakeIPHostUsageClient{stats: stats}
		},
	}
	s := &HostIPSvc{Inner: inner}
	out, err := s.Usage(context.Background(), "home", "LAN", false)
	require.NoError(t, err)
	require.Len(t, out.Records, 1)
	require.Nil(t, out.References)
}

func TestHostIPSvc_Usage_WithRefs(t *testing.T) {
	stats := []json.RawMessage{json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)}
	groupBody := []json.RawMessage{
		json.RawMessage(`{"Name":"LAN-group","HostList":["LAN","DMZ"]}`),
	}
	fwBody := []json.RawMessage{
		json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN"],"Action":"Accept"}`),
	}
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client {
			return fakeIPHostUsageClient{stats: stats, groupBody: groupBody, fwBody: fwBody}
		},
	}
	s := &HostIPSvc{Inner: inner}
	out, err := s.Usage(context.Background(), "home", "LAN", true)
	require.NoError(t, err)
	require.Len(t, out.Records, 1)
	require.NotNil(t, out.References)
	require.Equal(t, []string{"LAN-group"}, out.References.Refs["IPHostGroup"])
	require.Equal(t, []string{"LAN-To-WAN"}, out.References.Refs["FirewallRule"])
	require.Equal(t, []string{}, out.References.Refs["NATRule"])
}
