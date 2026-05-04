package svc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type cannedClient struct {
	resp *sophos.Response
	err  error
	last sophos.Envelope
}

func (c *cannedClient) Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error) {
	c.last = env
	return c.resp, c.err
}
func (c *cannedClient) DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error) {
	return c.resp, c.err
}

func newObjectSvc(t *testing.T, cl Client) *ObjectSvc {
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
		NewClient: func(p config.Profile, c creds.Credentials) Client { return cl },
	}
}

func TestObjectSvc_List_TypedParser(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {
				json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			},
		},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.List(context.Background(), "home", "IPHost", nil)
	require.NoError(t, err)
	require.Equal(t, "IPHost", out.Tag)
	require.Equal(t, 1, out.Count)
	host, ok := out.Items[0].(catalog.IPHost)
	require.True(t, ok)
	require.Equal(t, "LAN", host.Name)
}

func TestObjectSvc_List_AliasResolves(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body:    map[string][]json.RawMessage{"IPHost": {json.RawMessage(`{"Name":"x"}`)}},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.List(context.Background(), "home", "host-ip", nil)
	require.NoError(t, err)
	require.Equal(t, "IPHost", out.Tag)
}

// TestObjectSvc_List_FiltersEmptyStub covers a Sophos quirk: list queries
// against tags with no records sometimes return one stub row with all
// fields blank instead of an empty body. ObjectSvc.List filters those
// out so callers see Count=0.
func TestObjectSvc_List_FiltersEmptyStub(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {json.RawMessage(`{"Name":"","IPFamily":"","HostType":""}`)},
		},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.List(context.Background(), "home", "IPHost", nil)
	require.NoError(t, err)
	require.Equal(t, 0, out.Count)
}

func TestObjectSvc_List_FiltersStubAmongRealRecords(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {
				json.RawMessage(`{"Name":"","IPFamily":"","HostType":""}`),
				json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			},
		},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.List(context.Background(), "home", "IPHost", nil)
	require.NoError(t, err)
	require.Equal(t, 1, out.Count)
	host, ok := out.Items[0].(catalog.IPHost)
	require.True(t, ok)
	require.Equal(t, "LAN", host.Name)
}

func TestObjectSvc_List_UnknownTag(t *testing.T) {
	s := newObjectSvc(t, &cannedClient{})
	_, err := s.List(context.Background(), "home", "Nope", nil)
	require.ErrorIs(t, err, ErrCatalogUnknownTag)
}

func TestObjectSvc_List_FilterPassedThrough(t *testing.T) {
	cl := &cannedClient{resp: &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{"IPHost": {}}}}
	s := newObjectSvc(t, cl)
	_, err := s.List(context.Background(), "home", "IPHost", &sophos.FilterClause{Field: "Name", Criteria: "like", Value: "LAN"})
	require.NoError(t, err)
	require.Len(t, cl.last.Operations, 1)
	got, ok := cl.last.Operations[0].(sophos.GetOp)
	require.True(t, ok, "got %T", cl.last.Operations[0])
	require.NotNil(t, got.Filter)
	require.Equal(t, "like", got.Filter.Criteria)
}

func TestObjectSvc_Get_NotFoundSurfacedAsError(t *testing.T) {
	cl := &cannedClient{err: sophos.ErrNotFound}
	s := newObjectSvc(t, cl)
	_, err := s.Get(context.Background(), "home", "IPHost", "nope")
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestObjectSvc_Usage_UsesUsageTagFromCatalog(t *testing.T) {
	cl := &cannedClient{resp: &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{"IPHostStatistics": {}}}}
	s := newObjectSvc(t, cl)
	_, err := s.Usage(context.Background(), "home", "IPHost", "LAN")
	require.NoError(t, err)
	op, ok := cl.last.Operations[0].(sophos.StatisticsOp)
	require.True(t, ok, "got %T", cl.last.Operations[0])
	require.Equal(t, "IPHostStatistics", op.XMLTag)
}

func TestObjectSvc_Usage_RejectsObjectsWithoutUsageTag(t *testing.T) {
	cl := &cannedClient{}
	s := newObjectSvc(t, cl)
	_, err := s.Usage(context.Background(), "home", "FirewallRule", "X")
	require.Error(t, err)
}

func TestObjectSvc_Schema_ReturnsCatalogEntry(t *testing.T) {
	s := newObjectSvc(t, &cannedClient{})
	e, err := s.Schema("IPHost")
	require.NoError(t, err)
	require.Equal(t, "IPHost", e.Tag)
}

// TestObjectSvc_Get_InjectsDiffHashForMutableTypes covers the Phase 12
// generalization of the firewall_rule_show / nat_rule_show pattern:
// ObjectSvc.Get coerces the parsed body to map[string]any and injects
// _diffHash for catalog-mutable types so update/delete callers can use it
// as expectedDiffHash without a separate query.
func TestObjectSvc_Get_InjectsDiffHashForMutableTypes(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {
				json.RawMessage(`{"Name":"x","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`),
			},
		},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.Get(context.Background(), "home", "IPHost", "x")
	require.NoError(t, err)
	require.NotNil(t, out)
	m, ok := out.Data.(map[string]any)
	require.True(t, ok, "Data should be map[string]any for mutable types, got %T", out.Data)
	require.NotEmpty(t, m["_diffHash"])
}

// TestObjectSvc_Get_DoesNotInjectDiffHashForImmutableTypes ensures the
// injection is gated on catalog.Entry.Mutable. Zone is not mutable in
// Phase 12, so the body must not carry _diffHash.
func TestObjectSvc_Get_DoesNotInjectDiffHashForImmutableTypes(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"Zone": {json.RawMessage(`{"Name":"LAN","Type":"LAN"}`)},
		},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.Get(context.Background(), "home", "Zone", "LAN")
	require.NoError(t, err)
	require.NotNil(t, out)
	// Zone has a typed parser, so Data is the catalog struct, not a map.
	// Re-marshal to JSON to confirm _diffHash isn't present.
	b, err := json.Marshal(out.Data)
	require.NoError(t, err)
	require.NotContains(t, string(b), `"_diffHash"`,
		"Zone is immutable; _diffHash should not be injected")
}
