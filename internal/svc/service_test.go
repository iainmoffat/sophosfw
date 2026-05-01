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

type fakeSvcClient struct {
	body map[string][]json.RawMessage
}

func (f fakeSvcClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeSvcClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newServiceSvc(t *testing.T, body map[string][]json.RawMessage) *ServiceSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeSvcClient{body: body} },
	}
	return &ServiceSvc{Inner: inner}
}

func TestServiceSvc_List_DerivedSinglePort(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","SourcePort":"1:65535","DestinationPort":"80"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "tcp", out.Items[0].Derived.Protocol)
	require.Equal(t, "80", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedRange(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"WebPorts","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80:443"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "80-443", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedMultiPort(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTPandHTTPS","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"},{"Protocol":"TCP","DestinationPort":"443"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "80,443", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedContiguousCollapse(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"Triplet","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"},{"Protocol":"TCP","DestinationPort":"81"},{"Protocol":"TCP","DestinationPort":"82"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "80-82", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedMultiProtocol(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"DNS","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"53"},{"Protocol":"UDP","DestinationPort":"53"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "tcp,udp", out.Items[0].Derived.Protocol)
	require.Equal(t, "53", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedICMP_NoPortRange(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"PING","Type":"IP","ServiceDetails":{"ServiceDetail":[{"Protocol":"ICMP","ICMPType":"8","ICMPCode":"0"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "icmp", out.Items[0].Derived.Protocol)
	require.Empty(t, out.Items[0].Derived.PortRange)
}

func TestServiceSvc_Search_ByNameAndPort(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`),
			json.RawMessage(`{"Name":"SSH","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"22"}]}}`),
		},
	}
	s := newServiceSvc(t, body)

	// match by name substring
	out, err := s.Search(context.Background(), "home", "HTTP")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "HTTP", out.Items[0].Name)

	// match by port (in derived.portRange)
	out, err = s.Search(context.Background(), "home", "22")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "SSH", out.Items[0].Name)
}
