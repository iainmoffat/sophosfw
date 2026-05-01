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

type fakeObjectClient struct{ resp *sophos.Response }

func (f fakeObjectClient) Do(context.Context, sophos.Envelope) (*sophos.Response, error) {
	return f.resp, nil
}
func (f fakeObjectClient) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return f.resp, nil
}

func newRootForObjectTest(t *testing.T, resp *sophos.Response) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeObjectClient{resp: resp}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestObject_List_TablePrintsRows(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
		},
	}
	d := newRootForObjectTest(t, resp)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"object", "list", "IPHost"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN")
	require.Contains(t, out.String(), "10.0.0.0")
}

func TestObject_List_JSONIncludesEnvelope(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network"}`)},
		},
	}
	d := newRootForObjectTest(t, resp)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"object", "list", "IPHost", "--json"})
	require.NoError(t, root.Execute())
	require.True(t, strings.Contains(out.String(), `"schema": "sophosfw.v1.objectList"`))
	require.True(t, strings.Contains(out.String(), `"xmlTag": "IPHost"`))
}

func TestObject_Schema_PrintsCatalogEntry(t *testing.T) {
	d := newRootForObjectTest(t, &sophos.Response{LoginOK: true})
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"object", "schema", "IPHost", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"tag": "IPHost"`)
	require.Contains(t, out.String(), `"usageTag": "IPHostStatistics"`)
}

func TestObject_List_ColumnsOverride(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
		},
	}
	d := newRootForObjectTest(t, resp)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"object", "list", "IPHost", "--columns", "Name,IPAddress"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN")
	require.Contains(t, out.String(), "10.0.0.0")
	// HostType column was in default but is NOT requested; substring "Network"
	// must NOT appear in the table view.
	require.NotContains(t, out.String(), "Network")
}
