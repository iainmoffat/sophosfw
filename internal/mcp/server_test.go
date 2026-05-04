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
	audit := svc.NewAuditLog(t.TempDir(), true)
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return nil },
		DefaultProfile: "home",
		Audit:          audit,
	})
}

func TestServer_RegistersAllTools(t *testing.T) {
	s := newTestServer(t)

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
	require.Len(t, result.Tools, 51,
		"expected 51 tools, got %d", len(result.Tools))

	names := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		names[i] = tool.Name
	}
	for _, want := range []string{
		"auth_status", "auth_test", "auth_profile_list", "auth_profile_current",
		"object_list", "object_get", "object_search", "object_usage",
		"raw_get",
		"host_ip_list", "host_ip_show", "host_ip_search", "host_ip_usage",
		"host_ip_create", "host_ip_update", "host_ip_delete",
		"host_group_create", "host_group_update", "host_group_delete",
		"host_fqdn_create", "host_fqdn_update", "host_fqdn_delete",
		"host_fqdn_group_create", "host_fqdn_group_update", "host_fqdn_group_delete",
		"host_mac_create", "host_mac_update", "host_mac_delete",
		"service_list", "service_show", "service_search", "service_usage",
		"service_create", "service_update", "service_delete",
		"service_group_create", "service_group_update", "service_group_delete",
		"firewall_rule_list", "firewall_rule_show",
		"firewall_rule_create", "firewall_rule_update", "firewall_rule_delete",
		"nat_rule_list", "nat_rule_show",
		"nat_rule_create", "nat_rule_update", "nat_rule_delete",
		"backup_create", "backup_list", "drift_check",
	} {
		require.Contains(t, names, want)
	}
}

func TestServer_DispatchesAuthStatus_OverWire(t *testing.T) {
	s := newTestServer(t)

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

	result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "auth_status",
		Arguments: map[string]any{},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	require.NotEmpty(t, result.Content)
	tc, ok := result.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"schema": "sophosfw.v1.authStatus"`)
}
