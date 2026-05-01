package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeServiceCliClient struct{ body map[string][]json.RawMessage }

func (f fakeServiceCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeServiceCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForServiceTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeServiceCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestService_List_JSONHasDerivedBlockAndXmlTag(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceList"`)
	require.Contains(t, out.String(), `"xmlTag": "Services"`)
	require.Contains(t, out.String(), `"protocol": "tcp"`)
	require.Contains(t, out.String(), `"portRange": "80"`)
}

func TestService_Show_Positional(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "show", "HTTP", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.service"`)
	require.Contains(t, out.String(), `"Name": "HTTP"`)
}

func TestService_Search_FiltersClientSide(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`),
			json.RawMessage(`{"Name":"SSH","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"22"}]}}`),
		},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "search", "SSH", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceSearch"`)
	require.Contains(t, out.String(), `"xmlTag": "Services"`)
	require.Contains(t, out.String(), `"Name": "SSH"`)
	require.False(t, strings.Contains(out.String(), `"Name": "HTTP"`))
}

func TestService_Usage_WithReferences(t *testing.T) {
	body := map[string][]json.RawMessage{
		"ServicesStatistics": {json.RawMessage(`{"Name":"HTTP","HitCount":"42"}`)},
		"ServiceGroup":       {json.RawMessage(`{"Name":"Web-svcs","ServiceList":["HTTP","HTTPS"]}`)},
		"FirewallRule":       {json.RawMessage(`{"Name":"Web-Out","Services":["HTTP"]}`)},
		"NATRule":            {},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "usage", "HTTP", "--with-references", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceUsage"`)
	require.Contains(t, out.String(), `"references"`)
	require.Contains(t, out.String(), `"Web-svcs"`)
}
