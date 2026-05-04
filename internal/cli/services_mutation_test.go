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

// fakeServicesCliClient is the test double for the CLI mutation
// commands. It mirrors fakeFqdnHostCliClient but answers Services
// Get queries.
type fakeServicesCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeServicesCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "Services" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["Services"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}
func (f *fakeServicesCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForServicesTest(t *testing.T, body map[string]any) (*RootDeps, *fakeServicesCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeServicesCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func validServicesCliBody() map[string]any {
	return map[string]any{
		"Name": "ssh",
		"Type": "TCPorUDP",
		"ServiceDetails": map[string]any{
			"ServiceDetail": map[string]any{
				"Protocol":        "TCP",
				"SourcePort":      "1:65535",
				"DestinationPort": "22",
			},
		},
	}
}

func TestCmd_ServiceCreate_DryRun_Smoke(t *testing.T) {
	d, fc := newRootForServicesTest(t, nil)
	bodyPath := writeBodyFile(t, d.BaseDir, validServicesCliBody())

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "create", "ssh", "--body", "@" + bodyPath, "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.servicesMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_ServiceCreate_RejectsBodyNameMismatch(t *testing.T) {
	d, fc := newRootForServicesTest(t, nil)
	body := validServicesCliBody()
	body["Name"] = "Mismatch"
	bodyPath := writeBodyFile(t, d.BaseDir, body)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "create", "ssh", "--body", "@" + bodyPath})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
	require.Empty(t, fc.sent)
}

func TestCmd_ServiceUpdate_DryRun_Smoke(t *testing.T) {
	live := validServicesCliBody()
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForServicesTest(t, live)
	bodyPath := writeBodyFile(t, d.BaseDir, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "update", "ssh",
		"--body", "@" + bodyPath,
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.servicesMutation"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestCmd_ServiceDelete_DryRun_Smoke(t *testing.T) {
	live := validServicesCliBody()
	hash, _ := svc.DiffHash(live)
	d, fc := newRootForServicesTest(t, live)

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "delete", "ssh",
		"--expected-diff-hash", hash,
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.servicesMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Contains(t, out.String(), `"applied": false`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}
