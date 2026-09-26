package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestScheduleCreateBodyNameGuardsAndDryRun(t *testing.T) {
	d, _ := newRootForTest(t)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	for _, tc := range []struct{ body, want string }{
		{`{"Name":"Y","Type":"Recurring","ScheduleDetails":{"ScheduleDetail":{"Days":"Sunday","StartTime":"00:00","StopTime":"01:00"}}}`, `does not match positional arg`},
		{`{"Name":"  ","Type":"Recurring","ScheduleDetails":{"ScheduleDetail":{"Days":"Sunday","StartTime":"00:00","StopTime":"01:00"}}}`, `body Name must be a non-empty string`},
	} {
		cmd := newScheduleCmd(*d, cat)
		cmd.SetArgs([]string{"create", "X", "--body", tc.body})
		err := cmd.Execute()
		require.ErrorContains(t, err, tc.want)
	}

	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"schedule", "create", "X", "--body", `{"Type":"Recurring","ScheduleDetails":{"ScheduleDetail":{"Days":"Sunday","StartTime":"00:00","StopTime":"01:00"}}}`, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"applied": false`)
}

type fakeScheduleCommandClient struct{ referenced bool }

func (f fakeScheduleCommandClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) > 0 {
		if op, ok := env.Operations[0].(sophos.GetOp); ok {
			switch op.XMLTag {
			case "Schedule":
				resp.Body["Schedule"] = []json.RawMessage{json.RawMessage(`{"Name":"Night","Type":"Recurring"}`)}
			case "FirewallRule":
				if f.referenced {
					resp.Body["FirewallRule"] = []json.RawMessage{json.RawMessage(`{"Name":"Allow","NetworkPolicy":{"Schedule":"Night"}}`)}
				}
			}
		}
	}
	return resp, nil
}
func (fakeScheduleCommandClient) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func TestScheduleDeleteSurfacesReferenceGuard(t *testing.T) {
	d, _ := newRootForTest(t)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(config.Profile, creds.Credentials) svc.Client { return fakeScheduleCommandClient{referenced: true} }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	root := NewRoot(*d)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "delete", "Night", "--yes", "--ignore-diff-hash"})
	err := root.Execute()
	require.ErrorContains(t, err, "referenced by firewall rules")
}
