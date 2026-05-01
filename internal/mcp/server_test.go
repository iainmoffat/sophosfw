package mcp

import (
	"context"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return nil },
		DefaultProfile: "home",
	})
}

func TestServer_BootsAndListsZeroTools(t *testing.T) {
	s := newTestServer(t)
	require.NotNil(t, s.impl)

	// Connect via in-memory transport pair, list tools.
	ctx := context.Background()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()

	ss, err := s.impl.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Wait()
	})

	result, err := cs.ListTools(ctx, nil)
	require.NoError(t, err)
	require.Len(t, result.Tools, 4, "T4 registers 4 auth tools")
}
