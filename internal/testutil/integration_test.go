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
