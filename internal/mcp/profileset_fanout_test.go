// Package mcp profileset_fanout_test.go: per-handler fan-out smoke tests.
//
// One test per mutating tool exercises the multi-profile path through
// svc.Run + render.FanoutEnvelope. Each test uses a 2-profile MCP server
// with the test fakeMcpMutClient (or fakeBackupCli for backup/drift) and
// a CSV ProfileSet of "home,office". The assertion shape is the same for
// every handler:
//
//   - the response body is a sophosfw.v1.fanoutResult envelope
//   - the envelope contains both profile names in `profiles` and `results`
//   - the `operation` matches the audit op string
//
// These tests exist mainly so reviewers can grep for the schema name and
// confirm every mutating tool routes through the fan-out helper. Per-
// profile success/error semantics are exhaustively covered in the svc
// fanout_test.go suite.
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newMutMcpServerFanout builds a Server with two profiles registered
// (home, office) so handlers can fan out across a CSV ProfileSet.
// Returns the server and the fake client that records sent envelopes.
func newMutMcpServerFanout(t *testing.T, body map[string][]json.RawMessage) (*Server, *fakeMcpMutClient) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://h:4444"})
	cfg.AddProfile("office", config.Profile{URL: "https://o:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	require.NoError(t, store.Save("office", creds.Credentials{Username: "u", Password: "p"}))
	fc := &fakeMcpMutClient{body: body}
	audit := svc.NewAuditLog(t.TempDir(), true)
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fc },
		DefaultProfile: "home",
		Audit:          audit,
		BaseDir:        t.TempDir(),
	}), fc
}

// newBackupMcpServerFanout is the backup/drift twin of
// newMutMcpServerFanout: two profiles + per-profile creds + a fakeBackupCli
// that returns canned record bodies for any GetOp.
func newBackupMcpServerFanout(t *testing.T, bodies map[string][]json.RawMessage) (*Server, *fakeBackupCli, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://h:4444"})
	cfg.AddProfile("office", config.Profile{URL: "https://o:4444"})
	cfg.CurrentProfile = "home"
	baseDir := t.TempDir()
	store := creds.NewFileStore(baseDir)
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	require.NoError(t, store.Save("office", creds.Credentials{Username: "u", Password: "p"}))
	cli := &fakeBackupCli{bodies: bodies}
	audit := svc.NewAuditLog(t.TempDir(), true)
	s := NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return cli },
		DefaultProfile: "home",
		Audit:          audit,
		BaseDir:        baseDir,
	})
	return s, cli, baseDir
}

// requireFanoutOK decodes a fan-out response body and asserts that
// every entry reached the apply phase with status="ok". Used by all
// per-handler smoke tests below.
func requireFanoutOK(t *testing.T, body string, op string) {
	t.Helper()
	require.Contains(t, body, `"schema": "sophosfw.v1.fanoutResult"`)
	var env struct {
		Operation string           `json:"operation"`
		Profiles  []string         `json:"profiles"`
		Results   []map[string]any `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &env))
	require.Equal(t, op, env.Operation)
	require.Equal(t, []string{"home", "office"}, env.Profiles)
	require.Len(t, env.Results, 2)
	for _, r := range env.Results {
		require.Equal(t, "apply", r["phase"], "expected apply phase, got %v", r)
		require.Equal(t, "ok", r["status"], "expected ok status, got %v", r)
	}
}

// ---------- Hostip ----------

func TestHostIpCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	s, _ := newMutMcpServerFanout(t, body)
	out, _, err := s.handleHostIpCreate(context.Background(), nil, HostIpCreateInput{
		ProfileSet: "home,office",
		Name:       "X", HostType: "IP", IpAddress: "1.1.1.1",
		Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "host_ip_create")
}

func TestHostIpUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, _ := svc.DiffHash(current)
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	s, _ := newMutMcpServerFanout(t, body)
	out, _, err := s.handleHostIpUpdate(context.Background(), nil, HostIpUpdateInput{
		HostIpCreateInput: HostIpCreateInput{
			ProfileSet: "home,office",
			Name:       "X", HostType: "IP", IpAddress: "9.9.9.9",
			Confirm: true, DryRun: false,
		},
		ExpectedDiffHash: hash,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "host_ip_update")
}

func TestHostIpDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, _ := svc.DiffHash(current)
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	s, _ := newMutMcpServerFanout(t, body)
	out, _, err := s.handleHostIpDelete(context.Background(), nil, HostIpDeleteInput{
		ProfileSet: "home,office",
		Name:       "X", ExpectedDiffHash: hash,
		Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "host_ip_delete")
}

// ---------- IPHostGroup ----------

func TestIPHostGroupCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPHostGroupCreate(context.Background(), nil, IPHostGroupCreateInput{
		ProfileSet: "home,office",
		Name:       "G1", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "ip_host_group_create")
}

func TestIPHostGroupUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPHostGroupUpdate(context.Background(), nil, IPHostGroupUpdateInput{
		ProfileSet: "home,office",
		Name:       "G1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "ip_host_group_update")
}

func TestIPHostGroupDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPHostGroupDelete(context.Background(), nil, IPHostGroupDeleteInput{
		ProfileSet:       "home,office",
		Name:             "G1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "ip_host_group_delete")
}

// ---------- FQDNHost ----------

func TestFQDNHostCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "ex.com", "IPFamily": "IPv4"}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FQDNHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostCreate(context.Background(), nil, FQDNHostCreateInput{
		ProfileSet: "home,office",
		Name:       "F1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "fqdn_host_create")
}

func TestFQDNHostUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "ex.com", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FQDNHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostUpdate(context.Background(), nil, FQDNHostUpdateInput{
		ProfileSet: "home,office",
		Name:       "F1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "fqdn_host_update")
}

func TestFQDNHostDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "ex.com", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FQDNHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostDelete(context.Background(), nil, FQDNHostDeleteInput{
		ProfileSet:       "home,office",
		Name:             "F1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "fqdn_host_delete")
}

// ---------- FQDNHostGroup ----------

func TestFQDNHostGroupCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "FG", "IPFamily": "IPv4"}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostGroupCreate(context.Background(), nil, FQDNHostGroupCreateInput{
		ProfileSet: "home,office",
		Name:       "FG", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "fqdn_host_group_create")
}

func TestFQDNHostGroupUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "FG", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostGroupUpdate(context.Background(), nil, FQDNHostGroupUpdateInput{
		ProfileSet: "home,office",
		Name:       "FG", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "fqdn_host_group_update")
}

func TestFQDNHostGroupDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "FG", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostGroupDelete(context.Background(), nil, FQDNHostGroupDeleteInput{
		ProfileSet:       "home,office",
		Name:             "FG",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "fqdn_host_group_delete")
}

// ---------- MACHost ----------

func TestMACHostCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "aa:bb:cc:dd:ee:ff"}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleMACHostCreate(context.Background(), nil, MACHostCreateInput{
		ProfileSet: "home,office",
		Name:       "M1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "mac_host_create")
}

func TestMACHostUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "aa:bb:cc:dd:ee:ff"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleMACHostUpdate(context.Background(), nil, MACHostUpdateInput{
		ProfileSet: "home,office",
		Name:       "M1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "mac_host_update")
}

func TestMACHostDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "aa:bb:cc:dd:ee:ff"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleMACHostDelete(context.Background(), nil, MACHostDeleteInput{
		ProfileSet:       "home,office",
		Name:             "M1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "mac_host_delete")
}

// ---------- Services ----------

func TestServicesCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{
		"Name": "S1", "Type": "TCPorUDP",
		"ServiceDetails": map[string]any{
			"ServiceDetail": map[string]any{
				"Protocol": "TCP", "SourcePort": "1:65535", "DestinationPort": "80",
			},
		},
	}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, body)},
	})
	out, _, err := s.handleServicesCreate(context.Background(), nil, ServicesCreateInput{
		ProfileSet: "home,office",
		Name:       "S1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "services_create")
}

func TestServicesUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{
		"Name": "S1", "Type": "TCPorUDP",
		"ServiceDetails": map[string]any{
			"ServiceDetail": map[string]any{
				"Protocol": "TCP", "SourcePort": "1:65535", "DestinationPort": "80",
			},
		},
	}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, body)},
	})
	out, _, err := s.handleServicesUpdate(context.Background(), nil, ServicesUpdateInput{
		ProfileSet: "home,office",
		Name:       "S1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "services_update")
}

func TestServicesDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{
		"Name": "S1", "Type": "TCPorUDP",
		"ServiceDetails": map[string]any{
			"ServiceDetail": map[string]any{
				"Protocol": "TCP", "SourcePort": "1:65535", "DestinationPort": "80",
			},
		},
	}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, body)},
	})
	out, _, err := s.handleServicesDelete(context.Background(), nil, ServicesDeleteInput{
		ProfileSet:       "home,office",
		Name:             "S1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "services_delete")
}

// ---------- ServiceGroup ----------

func TestServiceGroupCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "SG1"}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleServiceGroupCreate(context.Background(), nil, ServiceGroupCreateInput{
		ProfileSet: "home,office",
		Name:       "SG1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "service_group_create")
}

func TestServiceGroupUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "SG1"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleServiceGroupUpdate(context.Background(), nil, ServiceGroupUpdateInput{
		ProfileSet: "home,office",
		Name:       "SG1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "service_group_update")
}

func TestServiceGroupDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "SG1"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleServiceGroupDelete(context.Background(), nil, ServiceGroupDeleteInput{
		ProfileSet:       "home,office",
		Name:             "SG1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "service_group_delete")
}

// ---------- FirewallRule ----------

func TestFirewallRuleCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "R1", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network"}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleCreate(context.Background(), nil, FirewallRuleCreateInput{
		ProfileSet: "home,office",
		Name:       "R1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "firewall_rule_create")
}

func TestFirewallRuleUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "R1", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleUpdate(context.Background(), nil, FirewallRuleUpdateInput{
		ProfileSet: "home,office",
		Name:       "R1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "firewall_rule_push")
}

func TestFirewallRuleDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "R1", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleDelete(context.Background(), nil, FirewallRuleDeleteInput{
		ProfileSet:       "home,office",
		Name:             "R1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "firewall_rule_delete")
}

// ---------- NATRule ----------

func TestNATRuleCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "N1", "Status": "Disable", "IPFamily": "IPv4"}
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleCreate(context.Background(), nil, NATRuleCreateInput{
		ProfileSet: "home,office",
		Name:       "N1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "nat_rule_create")
}

func TestNATRuleUpdate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "N1", "Status": "Disable", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleUpdate(context.Background(), nil, NATRuleUpdateInput{
		ProfileSet: "home,office",
		Name:       "N1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "nat_rule_push")
}

func TestNATRuleDelete_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string]any{"Name": "N1", "Status": "Disable", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, _ := newMutMcpServerFanout(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleDelete(context.Background(), nil, NATRuleDeleteInput{
		ProfileSet:       "home,office",
		Name:             "N1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "nat_rule_delete")
}

// ---------- Backup + Drift ----------

func TestBackupCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	s, _, _ := newBackupMcpServerFanout(t, map[string][]json.RawMessage{
		"IPHost": {rawIPHostMcp("LAN", "10.0.0.1")},
	})
	out, _, err := s.handleBackupCreate(context.Background(), nil, BackupCreateInput{
		ProfileSet: "home,office",
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "backup_create")
}

func TestDriftCheck_Handler_FanOut_TwoProfiles(t *testing.T) {
	s, _, _ := newBackupMcpServerFanout(t, map[string][]json.RawMessage{
		"IPHost": {rawIPHostMcp("LAN", "10.0.0.1")},
	})
	// Seed snapshots for both profiles so drift_check has --latest fodder.
	_, _, err := s.handleBackupCreate(context.Background(), nil, BackupCreateInput{
		ProfileSet: "home,office",
	})
	require.NoError(t, err)

	out, _, err := s.handleDriftCheck(context.Background(), nil, DriftCheckInput{
		ProfileSet: "home,office",
		Latest:     true,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "drift_check")
}
