package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeNATCliClient struct{ body map[string][]json.RawMessage }

func (f fakeNATCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeNATCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForNATTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeNATCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestNATRule_List_JSON(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Out","Status":"Enable","OriginalSourceNetworks":["LAN-network"]}`),
		},
	}
	d := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRuleList"`)
	require.Contains(t, out.String(), `"xmlTag": "NATRule"`)
	require.Contains(t, out.String(), `"Name": "WAN-Out"`)
}

func TestNATRule_Show(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Out","Status":"Enable"}`),
		},
	}
	d := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "show", "WAN-Out", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRule"`)
	require.Contains(t, out.String(), `"Name": "WAN-Out"`)
}
