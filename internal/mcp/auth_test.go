package mcp

import (
	"context"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// fakeAuthCli implements svc.Client. AuthSvc.Test calls Do (login probe);
// AuthSvc.Status does not call Do at all (it just inspects config + creds).
type fakeAuthCli struct {
	loginOK bool
}

func (f fakeAuthCli) Do(_ context.Context, _ sophos.Envelope) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: f.loginOK}, nil
}
func (fakeAuthCli) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newAuthTestServer(t *testing.T, loginOK bool, withCreds bool) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	if withCreds {
		require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	}
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeAuthCli{loginOK: loginOK} },
		DefaultProfile: "home",
	})
}

// textOf concatenates the text content from an MCP tool result. Used by
// every per-group test to inspect the JSON body the handler emitted.
func textOf(out *sdkmcp.CallToolResult) string {
	if out == nil {
		return ""
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if t, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(t.Text)
		}
	}
	return sb.String()
}

func TestAuthStatus_Handler(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthStatus(context.Background(), nil, AuthStatusInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.authStatus"`)
	require.Contains(t, body, `"profile": "home"`)
}

func TestAuthProfileList_Handler(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthProfileList(context.Background(), nil, AuthProfileListInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.profileList"`)
	require.Contains(t, body, `"home"`)
}

func TestAuthProfileCurrent_Handler(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthProfileCurrent(context.Background(), nil, AuthProfileCurrentInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.profileList"`)
	require.Contains(t, body, `"current": "home"`)
}

func TestAuthTest_Handler_Success(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthTest(context.Background(), nil, AuthTestInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.connectionTest"`)
	require.Contains(t, body, `"ok": true`)
}

func TestAuthStatus_NoCredsConfigured(t *testing.T) {
	s := newAuthTestServer(t, true, false) // no creds saved
	out, _, err := s.handleAuthStatus(context.Background(), nil, AuthStatusInput{})
	require.NoError(t, err) // never errors at the Go level
	body := textOf(out)
	// Status with no creds: loggedIn=false (foundation behavior).
	require.Contains(t, body, `"loggedIn": false`)
}
