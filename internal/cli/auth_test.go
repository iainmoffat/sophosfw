package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeAllOK struct{}

func (fakeAllOK) Do(context.Context, sophos.Envelope) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}
func (fakeAllOK) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForTest(t *testing.T) (*RootDeps, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.New()
	store := creds.NewFileStore(dir)
	d := &RootDeps{
		Version: "test",
		BaseDir: dir,
		Config:  cfg,
		Creds:   store,
		NewClient: func(p config.Profile, c creds.Credentials) svc.Client {
			return fakeAllOK{}
		},
	}
	return d, dir
}

func TestAuth_ProfileAdd_AndList(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	root.SetArgs([]string{"auth", "profile", "add", "home", "--url", "https://x:4444"})
	require.NoError(t, root.Execute())

	out.Reset()
	root.SetArgs([]string{"auth", "profile", "list"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "home")
}

func TestAuth_Status_NotLoggedInInitially(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"auth", "profile", "add", "home", "--url", "https://x:4444"})
	require.NoError(t, root.Execute())

	out.Reset()
	root.SetArgs([]string{"auth", "status", "--json"})
	require.NoError(t, root.Execute())
	require.True(t, strings.Contains(out.String(), `"loggedIn": false`),
		"got: %s", out.String())
}
