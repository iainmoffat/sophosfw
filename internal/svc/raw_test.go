package svc

import (
	"context"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func newRawSvc(t *testing.T, cl Client) *RawSvc {
	t.Helper()
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "ADMINUSR", Password: "SEKRET99"}))
	return &RawSvc{
		Config:    cfg,
		Creds:     store,
		NewClient: func(p config.Profile, c creds.Credentials) Client { return cl },
	}
}

func TestRawSvc_Get_RoundTrips(t *testing.T) {
	cl := &cannedClient{resp: &sophos.Response{LoginOK: true}}
	s := newRawSvc(t, cl)
	out, err := s.Get(context.Background(), "home", "IPHost")
	require.NoError(t, err)
	require.Equal(t, "IPHost", out.Tag)
}

func TestRawSvc_Preview_DetectsMutating(t *testing.T) {
	s := newRawSvc(t, &cannedClient{})
	body := []byte(`<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>`)
	pv, err := s.Preview(context.Background(), "home", body)
	require.NoError(t, err)
	require.True(t, pv.Mutating)
	require.Contains(t, pv.Verbs, "Set:add")
}

func TestRawSvc_Preview_RedactsCredentials(t *testing.T) {
	s := newRawSvc(t, &cannedClient{})
	body := []byte(`<Get><IPHost></IPHost></Get>`)
	pv, err := s.Preview(context.Background(), "home", body)
	require.NoError(t, err)
	require.False(t, strings.Contains(pv.RedactedXML, "ADMINUSR"), "username must be redacted")
	require.False(t, strings.Contains(pv.RedactedXML, "SEKRET99"), "password must be redacted")
	require.Contains(t, pv.RedactedXML, "<Username>***</Username>")
	require.Contains(t, pv.RedactedXML, "<Password>***</Password>")
}
