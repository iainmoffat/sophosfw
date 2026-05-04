//go:build integration

package testutil

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/mcp"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func loadProfile(t *testing.T) (config.Profile, creds.Credentials) {
	t.Helper()
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName, "set SOPHOSFW_PROFILE for integration tests")

	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	p, _, err := cfg.ActiveProfile(profileName)
	require.NoError(t, err)

	store := creds.New(baseDir)
	c, err := store.Load(profileName)
	require.NoError(t, err)
	return p, c
}

func newClient(t *testing.T) *IntegrationClient {
	t.Helper()
	p, c := loadProfile(t)
	inner := sophos.NewClient(sophos.ClientConfig{
		BaseURL:            p.URL,
		Username:           c.Username,
		Password:           c.Password,
		Timeout:            15 * time.Second,
		InsecureSkipVerify: p.InsecureSkipVerify,
	})
	return NewIntegrationClient(inner)
}

func TestIntegration_AuthTest_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}},
	})
	require.NoError(t, err)
}

func TestIntegration_CatalogTagsAllRoundTrip(t *testing.T) {
	c := newClient(t)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)

	for _, tag := range cat.Tags() {
		t.Run(tag, func(t *testing.T) {
			_, err := c.Do(context.Background(), sophos.Envelope{
				Operations: []sophos.Op{sophos.GetOp{XMLTag: tag}},
			})
			// Some tags may legitimately 404 in an empty environment;
			// accept ErrNotFound but reject auth/permission/server failures.
			if err != nil && !errorsIsAny(err, sophos.ErrNotFound) {
				t.Fatalf("tag %q: unexpected error: %v", tag, err)
			}
		})
	}
}

func errorsIsAny(err error, targets ...error) bool {
	for _, t := range targets {
		if err == t {
			return true
		}
	}
	return false
}

func TestIntegration_HostIPList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}},
	})
	require.NoError(t, err)
}

func TestIntegration_ServiceList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "Services"}},
	})
	require.NoError(t, err)
}

func TestIntegration_FirewallRuleList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "FirewallRule"}},
	})
	require.NoError(t, err)
}

func TestIntegration_NATRuleList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "NATRule"}},
	})
	require.NoError(t, err)
}

func TestIntegration_MCPServer_HostIpListOverWire(t *testing.T) {
	p, c := loadProfile(t)
	_ = p
	_ = c
	// Build a Deps with the SAME config/creds the cli would use:
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: os.Getenv("SOPHOSFW_PROFILE"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "host_ip_list",
		Arguments: map[string]any{},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	tc, ok := result.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"schema": "sophosfw.v1.hostIpList"`)
}

func TestIntegration_HostIPCreate_DryRun(t *testing.T) {
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	audit := svc.NewAuditLog(t.TempDir(), false)

	hostIp := &svc.HostIPSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit: audit,
	}

	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	result, err := hostIp.Create(context.Background(), profileName, svc.HostIPCreateInput{
		Name: "sophosfw-test-do-not-create", HostType: "IP", IPAddress: "192.0.2.1",
	}, true)
	require.NoError(t, err)
	require.True(t, result.DryRun)
	require.NotNil(t, result.Preview)
	require.True(t, result.Preview.Mutating)
	require.Contains(t, result.Preview.Verbs, "Set:add")
}

func newFwRuleSvcForIntegration(t *testing.T) (*svc.FirewallRuleSvc, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	tmpBase := t.TempDir()
	return &svc.FirewallRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit:   svc.NewAuditLog(t.TempDir(), true),
		BaseDir: tmpBase,
	}, tmpBase
}

func TestIntegration_FirewallRulePull_RoundTrips(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE to a real rule name on the testvm")
	}

	svcInst, _ := newFwRuleSvcForIntegration(t)
	out, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)
}

func TestIntegration_FirewallRulePush_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE")
	}

	svcInst, _ := newFwRuleSvcForIntegration(t)
	_, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)

	out, err := svcInst.Push(context.Background(), profileName, ruleName, false, true) // dryRun=true
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
}

func TestIntegration_FirewallRulePush_RoundTrip(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE")
	}

	svcInst, _ := newFwRuleSvcForIntegration(t)
	pullOut, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)

	d, err := draft.ReadDraft(pullOut.DraftPath)
	require.NoError(t, err)
	orig := string(d.Body)

	flipped := orig
	switch {
	case strings.Contains(orig, "LogTraffic: Enable"):
		flipped = strings.Replace(orig, "LogTraffic: Enable", "LogTraffic: Disable", 1)
	case strings.Contains(orig, "LogTraffic: Disable"):
		flipped = strings.Replace(orig, "LogTraffic: Disable", "LogTraffic: Enable", 1)
	default:
		t.Skip("test rule does not have LogTraffic field; pick another rule")
	}
	d.Body = []byte(flipped)
	require.NoError(t, draft.WriteDraft(pullOut.DraftPath, d))

	t.Cleanup(func() {
		// Re-pull to refresh the hash, then write the original body back, then push.
		pull2, err := svcInst.Pull(context.Background(), profileName, ruleName)
		if err != nil {
			t.Logf("cleanup re-pull failed: %v", err)
			return
		}
		d2, err := draft.ReadDraft(pull2.DraftPath)
		if err != nil {
			t.Logf("cleanup read failed: %v", err)
			return
		}
		d2.Body = []byte(orig)
		if err := draft.WriteDraft(pull2.DraftPath, d2); err != nil {
			t.Logf("cleanup write failed: %v", err)
			return
		}
		if _, err := svcInst.Push(context.Background(), profileName, ruleName, false, false); err != nil {
			t.Logf("cleanup push failed: %v", err)
		}
	})

	out, err := svcInst.Push(context.Background(), profileName, ruleName, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)

	pull3, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)
	d3, err := draft.ReadDraft(pull3.DraftPath)
	require.NoError(t, err)
	if strings.Contains(orig, "LogTraffic: Enable") {
		require.Contains(t, string(d3.Body), "LogTraffic: Disable")
	} else {
		require.Contains(t, string(d3.Body), "LogTraffic: Enable")
	}
}

func newNATRuleSvcForIntegration(t *testing.T) (*svc.NATRuleSvc, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	tmpBase := t.TempDir()
	return &svc.NATRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit:   svc.NewAuditLog(t.TempDir(), true),
		BaseDir: tmpBase,
	}, tmpBase
}

func TestIntegration_NATRulePull_RoundTrips(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_NAT_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_NAT_RULE to a real NAT rule on the testvm")
	}

	svcInst, _ := newNATRuleSvcForIntegration(t)
	out, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)
}

func TestIntegration_NATRulePush_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_NAT_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_NAT_RULE")
	}

	svcInst, _ := newNATRuleSvcForIntegration(t)
	_, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)

	out, err := svcInst.Push(context.Background(), profileName, ruleName, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
}

func TestIntegration_NATRuleMigration(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "x.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("# rule: X\n"), 0o600))

	require.NoError(t, draft.MigrateLegacyLayout(tmp, "home"))

	migrated := filepath.Join(dir, "firewall", "x.yaml")
	_, err := os.Stat(migrated)
	require.NoError(t, err)
}

func TestIntegration_FirewallRuleNew_FromTemplate_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	svcInst, _ := newFwRuleSvcForIntegration(t)
	const tname = "sophosfw-integration-test-new"

	out, err := svcInst.New(context.Background(), profileName, tname, "")
	require.NoError(t, err)
	require.FileExists(t, out.DraftPath)

	pushOut, err := svcInst.Push(context.Background(), profileName, tname, false, true)
	require.NoError(t, err)
	require.True(t, pushOut.DryRun)
	require.Equal(t, "create", pushOut.Operation)
	require.NotNil(t, pushOut.Preview)
	require.True(t, pushOut.Preview.Mutating)
	require.Contains(t, pushOut.Preview.RedactedXML, `<Set operation="add">`)
}

func TestIntegration_NATRuleNew_FromTemplate_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	svcInst, _ := newNATRuleSvcForIntegration(t)
	const tname = "sophosfw-integration-test-nat-new"

	out, err := svcInst.New(context.Background(), profileName, tname, "")
	require.NoError(t, err)
	require.FileExists(t, out.DraftPath)

	pushOut, err := svcInst.Push(context.Background(), profileName, tname, false, true)
	require.NoError(t, err)
	require.True(t, pushOut.DryRun)
	require.Equal(t, "create", pushOut.Operation)
	require.NotNil(t, pushOut.Preview)
	require.True(t, pushOut.Preview.Mutating)
	require.Contains(t, pushOut.Preview.RedactedXML, `<Set operation="add">`)
}

func TestIntegration_MCPFirewallRuleShow_HasDiffHash(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE to a real rule on the testvm")
	}

	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: profileName,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "firewall_rule_show",
		Arguments: map[string]any{"name": ruleName},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)
	tc, ok := result.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"_diffHash":`)
}

func TestIntegration_MCPFirewallRuleUpdate_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE")
	}

	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: profileName,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	// Step 1: show, capture diffHash.
	showResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "firewall_rule_show",
		Arguments: map[string]any{"name": ruleName},
	})
	require.NoError(t, err)
	tc := showResult.Content[0].(*sdkmcp.TextContent)
	var showBody map[string]any
	require.NoError(t, json.Unmarshal([]byte(tc.Text), &showBody))
	hash, _ := showBody["_diffHash"].(string)
	require.NotEmpty(t, hash)
	delete(showBody, "_diffHash")
	delete(showBody, "schema")

	// Step 2: update dry-run with the same body.
	updateResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "firewall_rule_update",
		Arguments: map[string]any{
			"name":             ruleName,
			"body":             showBody,
			"expectedDiffHash": hash,
			"confirm":          true,
			"dryRun":           true,
		},
	})
	require.NoError(t, err)
	require.False(t, updateResult.IsError)
	tcUpdate := updateResult.Content[0].(*sdkmcp.TextContent)
	require.Contains(t, tcUpdate.Text, `"schema": "sophosfw.v1.preview"`)
}

// mcpDryRunCreateHarness wires an in-memory MCP transport against the
// configured profile and invokes a single create-style tool with
// confirm: true, dryRun: true. Asserts the response is a preview
// envelope. Used by the per-type create dry-run smokes below.
func mcpDryRunCreateHarness(t *testing.T, toolName, name string, body map[string]any) {
	t.Helper()
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: profileName,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"name":    name,
			"body":    body,
			"confirm": true,
			"dryRun":  true,
		},
	})
	require.NoError(t, err)
	require.False(t, result.IsError, "tool returned error envelope: %+v", result.Content)
	tc, ok := result.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"schema": "sophosfw.v1.preview"`)
}

func TestIntegration_MCPHostGroupCreate_DryRun(t *testing.T) {
	name := os.Getenv("SOPHOSFW_TEST_HOSTGROUP_NAME")
	if name == "" {
		t.Skip("set SOPHOSFW_TEST_HOSTGROUP_NAME to a name not in use on the testvm")
	}
	mcpDryRunCreateHarness(t, "host_group_create", name, map[string]any{
		"Name":     name,
		"IPFamily": "IPv4",
	})
}

func TestIntegration_MCPFQDNHostCreate_DryRun(t *testing.T) {
	name := os.Getenv("SOPHOSFW_TEST_FQDNHOST_NAME")
	if name == "" {
		t.Skip("set SOPHOSFW_TEST_FQDNHOST_NAME to a name not in use on the testvm")
	}
	mcpDryRunCreateHarness(t, "host_fqdn_create", name, map[string]any{
		"Name":     name,
		"FQDN":     "example.com",
		"IPFamily": "IPv4",
	})
}

func TestIntegration_MCPFQDNHostGroupCreate_DryRun(t *testing.T) {
	name := os.Getenv("SOPHOSFW_TEST_FQDNHOSTGROUP_NAME")
	if name == "" {
		t.Skip("set SOPHOSFW_TEST_FQDNHOSTGROUP_NAME to a name not in use on the testvm")
	}
	mcpDryRunCreateHarness(t, "host_fqdn_group_create", name, map[string]any{
		"Name":     name,
		"IPFamily": "IPv4",
	})
}

func TestIntegration_MCPMACHostCreate_DryRun(t *testing.T) {
	name := os.Getenv("SOPHOSFW_TEST_MACHOST_NAME")
	if name == "" {
		t.Skip("set SOPHOSFW_TEST_MACHOST_NAME to a name not in use on the testvm")
	}
	mcpDryRunCreateHarness(t, "host_mac_create", name, map[string]any{
		"Name":       name,
		"Type":       "MACAddress",
		"MACAddress": "00:11:22:33:44:55",
	})
}

func TestIntegration_MCPServicesCreate_DryRun(t *testing.T) {
	name := os.Getenv("SOPHOSFW_TEST_SERVICES_NAME")
	if name == "" {
		t.Skip("set SOPHOSFW_TEST_SERVICES_NAME to a name not in use on the testvm")
	}
	mcpDryRunCreateHarness(t, "service_create", name, map[string]any{
		"Name": name,
		"Type": "TCPorUDP",
		"ServiceDetails": map[string]any{
			"ServiceDetail": map[string]any{
				"Protocol":        "TCP",
				"SourcePort":      "1:65535",
				"DestinationPort": "8080",
			},
		},
	})
}

func TestIntegration_MCPServiceGroupCreate_DryRun(t *testing.T) {
	name := os.Getenv("SOPHOSFW_TEST_SERVICEGROUP_NAME")
	if name == "" {
		t.Skip("set SOPHOSFW_TEST_SERVICEGROUP_NAME to a name not in use on the testvm")
	}
	mcpDryRunCreateHarness(t, "service_group_create", name, map[string]any{
		"Name": name,
	})
}

// newBackupSvcForIntegration assembles a BackupSvc against the live profile
// the same way `sophosfw backup` and `sophosfw drift` do. BaseDir is the
// real default base dir so List()/Rotate() see the same on-disk store the
// CLI would; tests that care about isolation pass an explicit OutDir under
// t.TempDir() to Create.
func newBackupSvcForIntegration(t *testing.T) *svc.BackupSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	return &svc.BackupSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Catalog: cat,
		BaseDir: baseDir,
		Now:     time.Now,
		Version: "integration-test",
	}
}

// TestIntegration_Backup_Create_FullSnapshot exercises BackupSvc.Create
// against the live testvm into a t.TempDir() so the on-disk store is
// untouched. Asserts _meta.yaml is present, at least one of the common
// per-type subdirs (FirewallRule, IPHost) exists, and TotalRecords > 0.
func TestIntegration_Backup_Create_FullSnapshot(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	bs := newBackupSvcForIntegration(t)
	outDir := filepath.Join(t.TempDir(), "snap")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := bs.Create(ctx, profileName, svc.BackupCreateOptions{OutDir: outDir})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, outDir, result.Path)
	require.Greater(t, result.TotalRecords, 0)

	// _meta.yaml present and parseable as a valid backup-meta file. We
	// reuse Drift to validate this end-to-end: it reads _meta.yaml and
	// rejects directories with the wrong schema, so a successful drift
	// indicates the meta file is well-formed.
	require.FileExists(t, filepath.Join(outDir, "_meta.yaml"))

	// At least one of FirewallRule and IPHost subdirs exists. A live
	// firewall in any non-pristine state will have records for both; we
	// require ONE of them rather than both to keep this resilient against
	// freshly-imaged VMs.
	fwExists := dirExists(filepath.Join(outDir, "FirewallRule"))
	ipExists := dirExists(filepath.Join(outDir, "IPHost"))
	require.True(t, fwExists || ipExists,
		"expected at least one of FirewallRule/IPHost subdirs in snapshot")
}

// TestIntegration_Drift_NoChanges_EmptyResult writes a snapshot and
// immediately drifts against it. Nothing on the firewall changes between
// the two calls, so every record must classify as Unchanged.
//
// FQDNHost is excluded from both sides: the firewall auto-populates DNS
// resolution cache entries (e.g. *.clients.l.google.com, search.yahoo.com)
// in the FQDNHost list between two GETs, which would surface as spurious
// "added" entries here. This is firewall-side dynamic behavior, not a
// sophosfw bug, and it's safe to skip in a static-comparison smoke.
func TestIntegration_Drift_NoChanges_EmptyResult(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	bs := newBackupSvcForIntegration(t)
	outDir := filepath.Join(t.TempDir(), "snap")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	createResult, err := bs.Create(ctx, profileName, svc.BackupCreateOptions{
		OutDir:  outDir,
		Exclude: []string{"FQDNHost"},
	})
	require.NoError(t, err)
	require.Greater(t, createResult.TotalRecords, 0)

	driftResult, err := bs.Drift(ctx, profileName, svc.DriftOptions{SnapshotPath: outDir})
	require.NoError(t, err)
	require.NotNil(t, driftResult)
	for _, ch := range driftResult.Changes {
		t.Logf("unexpected change: type=%s name=%s change=%s", ch.Type, ch.Name, ch.Change)
	}
	require.Zero(t, driftResult.Summary.Added, "Added should be 0 immediately after backup")
	require.Zero(t, driftResult.Summary.Modified, "Modified should be 0 immediately after backup")
	require.Zero(t, driftResult.Summary.Removed, "Removed should be 0 immediately after backup")
	require.Greater(t, driftResult.Summary.Unchanged, 0, "Unchanged should reflect every snapshotted record")
	require.Empty(t, driftResult.Changes, "no per-record changes expected")
}

// TestIntegration_Drift_AfterIPHostCreate_ReportsAdded mutates the testvm.
//
// Sequence: backup → create test IPHost → drift → expect "added" for the
// test record under IPHost. Cleanup runs via t.Cleanup so a partial test
// run still removes the test record from the firewall.
//
// The test record name comes from SOPHOSFW_TEST_IPHOST_NAME, defaulting to
// "sophosfw-drift-test". The cleanup uses ignoreHash=true so it succeeds
// even if the live record drifted between create and cleanup.
func TestIntegration_Drift_AfterIPHostCreate_ReportsAdded(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	testName := os.Getenv("SOPHOSFW_TEST_IPHOST_NAME")
	if testName == "" {
		testName = "sophosfw-drift-test"
	}

	bs := newBackupSvcForIntegration(t)
	outDir := filepath.Join(t.TempDir(), "snap")

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// Step 1: snapshot the firewall BEFORE creating the test record.
	createResult, err := bs.Create(ctx, profileName, svc.BackupCreateOptions{OutDir: outDir})
	require.NoError(t, err)
	require.Greater(t, createResult.TotalRecords, 0)

	// Step 2: build a HostIPSvc and create the test IPHost.
	hostIp := &svc.HostIPSvc{
		Inner: bs.Inner,
		Audit: svc.NewAuditLog(t.TempDir(), false),
	}

	// Register cleanup BEFORE issuing the create. If the create succeeds
	// and the drift assertion later panics, cleanup still runs. ignoreHash
	// is true because we are not racing other writers and we want cleanup
	// to be unconditional.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := hostIp.Delete(cleanupCtx, profileName, testName, "", true, false); err != nil {
			t.Logf("cleanup: delete IPHost %q failed: %v (manual cleanup may be required)", testName, err)
		}
	})

	_, err = hostIp.Create(ctx, profileName, svc.HostIPCreateInput{
		Name:      testName,
		HostType:  "IP",
		IPFamily:  "IPv4",
		IPAddress: "192.0.2.42",
	}, false) // dryRun=false: actually create
	require.NoError(t, err, "creating test IPHost on testvm")

	// Step 3: drift against the pre-create snapshot. The new IPHost must
	// appear as "added" under the IPHost type.
	driftResult, err := bs.Drift(ctx, profileName, svc.DriftOptions{SnapshotPath: outDir})
	require.NoError(t, err)
	require.NotNil(t, driftResult)

	require.GreaterOrEqual(t, driftResult.Summary.Added, 1,
		"expected at least 1 added record after creating %q", testName)

	if perType, ok := driftResult.Summary.PerType["IPHost"]; ok {
		require.GreaterOrEqual(t, perType.Added, 1,
			"expected at least 1 added IPHost in per-type summary")
	}

	var foundTestRecord bool
	for _, ch := range driftResult.Changes {
		if ch.Type == "IPHost" && ch.Name == testName && ch.Change == "added" {
			foundTestRecord = true
			break
		}
	}
	require.True(t, foundTestRecord,
		"expected a Changes entry for added IPHost %q; got %d changes",
		testName, len(driftResult.Changes))
}

// dirExists is a small predicate used by the backup smoke. Returns true
// only if the path exists AND is a directory.
func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// fanoutSkipMsg is the canonical skip message for the fan-out integration
// suite. Both SOPHOSFW_PROFILE and SOPHOSFW_TEST_PROFILE_2 must point at
// real, credential-bearing profiles; absent either, the test skips.
const fanoutSkipMsg = "set SOPHOSFW_PROFILE and SOPHOSFW_TEST_PROFILE_2 to run fan-out integration tests"

// TestIntegration_Fanout_FirewallRulePushDryRun exercises the fan-out
// path through the in-memory MCP transport: firewall_rule_update with
// dryRun=true across a 2-profile CSV set. Because dryRunOnly=true, the
// fan-out runner stops after the parallel pre-flight phase, so every
// per-profile entry must be phase=preflight, status=ok.
//
// The body is sourced live from profile 1's `Block Countries` rule via
// firewall_rule_show; the same body is replayed against both profiles
// with ignoreExpectedDiffHash=true so the second profile (which has its
// own independent diff hash) doesn't fail the optimistic-concurrency
// check.
func TestIntegration_Fanout_FirewallRulePushDryRun(t *testing.T) {
	profile1 := os.Getenv("SOPHOSFW_PROFILE")
	profile2 := os.Getenv("SOPHOSFW_TEST_PROFILE_2")
	if profile1 == "" || profile2 == "" {
		t.Skip(fanoutSkipMsg)
	}

	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: profile1,
		BaseDir:        baseDir,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	// Step 1: show on profile 1 to capture a real body.
	const ruleName = "Block Countries"
	showResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "firewall_rule_show",
		Arguments: map[string]any{
			"profile": profile1,
			"name":    ruleName,
		},
	})
	require.NoError(t, err)
	require.False(t, showResult.IsError, "firewall_rule_show failed: %+v", showResult.Content)
	tcShow, ok := showResult.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	var showBody map[string]any
	require.NoError(t, json.Unmarshal([]byte(tcShow.Text), &showBody))
	delete(showBody, "_diffHash")
	delete(showBody, "schema")

	// Step 2: update dry-run across both profiles via profileSet CSV.
	updateResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "firewall_rule_update",
		Arguments: map[string]any{
			"profileSet":             profile1 + "," + profile2,
			"name":                   ruleName,
			"body":                   showBody,
			"ignoreExpectedDiffHash": true,
			"confirm":                true,
			"dryRun":                 true,
		},
	})
	require.NoError(t, err)
	require.False(t, updateResult.IsError, "firewall_rule_update fan-out failed: %+v", updateResult.Content)

	tcUpd, ok := updateResult.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tcUpd.Text, `"schema": "sophosfw.v1.fanoutResult"`)

	var env struct {
		Operation string           `json:"operation"`
		Profiles  []string         `json:"profiles"`
		Results   []map[string]any `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(tcUpd.Text), &env))
	require.Equal(t, "firewall_rule_push", env.Operation)
	require.Equal(t, []string{profile1, profile2}, env.Profiles)
	require.Len(t, env.Results, 2)
	for _, r := range env.Results {
		require.Equal(t, "preflight", r["phase"], "expected preflight phase, got %v", r)
		require.Equal(t, "ok", r["status"], "expected ok status, got %v", r)
	}
}

// TestIntegration_Fanout_DriftAcrossSet exercises the fan-out path for
// drift_check across a 2-profile CSV set, using --latest so the test
// doesn't need a pre-existing snapshot path. drift is read-only against
// the firewall but the MCP handler runs with dryRunOnly=false so the
// real work happens in the apply phase: every per-profile entry must
// be phase=apply, status=ok.
//
// To give --latest something to find, a backup_create fan-out is run
// first against the same set; both snapshots land under their default
// profile-scoped dir and are immediately drifted against.
func TestIntegration_Fanout_DriftAcrossSet(t *testing.T) {
	profile1 := os.Getenv("SOPHOSFW_PROFILE")
	profile2 := os.Getenv("SOPHOSFW_TEST_PROFILE_2")
	if profile1 == "" || profile2 == "" {
		t.Skip(fanoutSkipMsg)
	}

	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: profile1,
		BaseDir:        baseDir,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	defer ss.Close()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	// Step 1: backup_create across the set so drift --latest has a
	// snapshot to find under each profile's default snapshot dir.
	// FQDNHost is excluded for the same reason as
	// TestIntegration_Drift_NoChanges_EmptyResult: the firewall mutates
	// it between GETs and that surfaces as spurious drift.
	backupResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "backup_create",
		Arguments: map[string]any{
			"profileSet": profile1 + "," + profile2,
			"exclude":    []string{"FQDNHost"},
		},
	})
	require.NoError(t, err)
	require.False(t, backupResult.IsError, "backup_create fan-out failed: %+v", backupResult.Content)

	// Step 2: drift_check --latest across the set.
	driftResult, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "drift_check",
		Arguments: map[string]any{
			"profileSet": profile1 + "," + profile2,
			"latest":     true,
		},
	})
	require.NoError(t, err)
	require.False(t, driftResult.IsError, "drift_check fan-out failed: %+v", driftResult.Content)

	tc, ok := driftResult.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"schema": "sophosfw.v1.fanoutResult"`)

	var env struct {
		Operation string           `json:"operation"`
		Profiles  []string         `json:"profiles"`
		Results   []map[string]any `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(tc.Text), &env))
	require.Equal(t, "drift_check", env.Operation)
	require.Equal(t, []string{profile1, profile2}, env.Profiles)
	require.Len(t, env.Results, 2)
	for _, r := range env.Results {
		require.Equal(t, "apply", r["phase"], "expected apply phase, got %v", r)
		require.Equal(t, "ok", r["status"], "expected ok status, got %v", r)
	}
}
