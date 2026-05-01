package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type rawFakeClient struct{}

func (rawFakeClient) Do(context.Context, sophos.Envelope) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}
func (rawFakeClient) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForRawTest(t *testing.T) *RootDeps {
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return rawFakeClient{} }
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestRaw_Get_PrintsEnvelope(t *testing.T) {
	d := newRootForRawTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "get", "IPHost", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.rawResponse"`)
}

func TestRaw_Request_DryRunDetectsMutating(t *testing.T) {
	d := newRootForRawTest(t)
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "mut.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--dry-run", "--json"})
	require.NoError(t, root.Execute())

	require.Contains(t, out.String(), `"mutating": true`)
	require.Contains(t, out.String(), `"Set:add"`)
	require.False(t, strings.Contains(out.String(), "<Username>u</Username>"), "credentials must not appear unredacted")
}

func TestRaw_Request_YesAppliesMutatingRequest(t *testing.T) {
	d := newRootForRawTest(t)
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "x.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--yes"})
	require.NoError(t, root.Execute())
}
