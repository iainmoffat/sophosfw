package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestRaw_Request_Yes_RequiresConfirmMutating(t *testing.T) {
	d, _ := newRootForTest(t)
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return rawFakeClient{} }

	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "mut.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--yes"})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "--confirm-mutating"))
}

func TestRaw_Request_Yes_ConfirmMutating_Applies(t *testing.T) {
	d, _ := newRootForTest(t)
	auditDir := t.TempDir()
	d.Audit = svc.NewAuditLog(auditDir, true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return rawFakeClient{} }

	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "mut.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--yes", "--confirm-mutating"})
	require.NoError(t, root.Execute())

	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"raw_apply_mutating"`)
}
