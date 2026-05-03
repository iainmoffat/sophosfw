package render

import (
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestAuthStatusEnvelope(t *testing.T) {
	got, err := AuthStatusEnvelope(svc.AuthStatus{
		Profile: "home", URL: "https://x", LoggedIn: false, CredentialsBackend: "keychain",
	})
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.authStatus"`)
	require.Contains(t, s, `"profile": "home"`)
	require.Contains(t, s, `"loggedIn": false`)
	require.Contains(t, s, `"credentialsBackend": "keychain"`)
}

func TestProfileListEnvelope(t *testing.T) {
	got, err := ProfileListEnvelope("home", []svc.ProfileInfo{
		{Name: "home", URL: "https://x:4444", ReadOnly: false, Current: true},
	})
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.profileList"`)
	require.Contains(t, s, `"current": "home"`)
	require.Contains(t, s, `"profiles"`)
	require.Contains(t, s, `"name": "home"`)
}

func TestObjectListEnvelope_NoFilter(t *testing.T) {
	out := &svc.ObjectList{
		Profile: "home", Tag: "IPHost", Count: 0, Items: []any{},
	}
	got, err := ObjectListEnvelope(out)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, s, `"xmlTag": "IPHost"`)
	require.Contains(t, s, `"count": 0`)
	require.False(t, strings.Contains(s, `"filter"`), "no filter clause should mean no filter key")
}

func TestHostIPListEnvelope_HasXmlTag(t *testing.T) {
	list := &svc.HostIPList{Profile: "home", Count: 0, Items: []svc.HostIP{}}
	got, err := HostIPListEnvelope("sophosfw.v1.hostIpList", list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.hostIpList"`)
	require.Contains(t, s, `"xmlTag": "IPHost"`)
}

func TestServiceListEnvelope_SearchSchema(t *testing.T) {
	list := &svc.ServiceList{Profile: "home", Count: 0, Items: []svc.Service{}}
	got, err := ServiceListEnvelope("sophosfw.v1.serviceSearch", list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.serviceSearch"`)
	require.Contains(t, s, `"xmlTag": "Services"`)
}

func TestFirewallRuleListEnvelope(t *testing.T) {
	list := &svc.FirewallRuleList{Profile: "home", Count: 0, Items: []map[string]any{}}
	got, err := FirewallRuleListEnvelope(list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.firewallRuleList"`)
	require.Contains(t, s, `"xmlTag": "FirewallRule"`)
}

func TestNATRuleListEnvelope(t *testing.T) {
	list := &svc.NATRuleList{Profile: "home", Count: 0, Items: []map[string]any{}}
	got, err := NATRuleListEnvelope(list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.natRuleList"`)
	require.Contains(t, s, `"xmlTag": "NATRule"`)
}

func TestErrorEnvelope(t *testing.T) {
	got, err := ErrorEnvelope("not_found", "host LAN: not found", "home")
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.error"`)
	require.Contains(t, s, `"kind": "not_found"`)
	require.Contains(t, s, `"profile": "home"`)
}

func TestErrorEnvelope_NoProfile(t *testing.T) {
	got, err := ErrorEnvelope("config_error", "no current profile", "")
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.error"`)
	require.False(t, strings.Contains(s, `"profile"`), "empty profile should be omitted")
}

func TestFirewallRulePullEnvelope_Schema(t *testing.T) {
	r := &svc.FirewallRulePullResult{
		Profile:      "home",
		Rule:         "WAN-to-LAN",
		DraftPath:    "/path/draft.yaml",
		SnapshotPath: "/path/snapshot.yaml",
		DiffHash:     "abc123",
		References: []svc.ReferenceSummary{
			{Type: "IPHost", Names: []string{"LAN-network"}},
		},
	}
	b, err := FirewallRulePullEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.firewallRulePull"`)
	require.Contains(t, string(b), `"draftPath": "/path/draft.yaml"`)
	require.Contains(t, string(b), `"diffHash": "abc123"`)
	require.Contains(t, string(b), `"LAN-network"`)
}

func TestFirewallRuleDiffEnvelope_Schema(t *testing.T) {
	r := &svc.FirewallRuleDiffResult{
		Profile:        "home",
		Rule:           "WAN-to-LAN",
		HasChanges:     true,
		UnifiedDiff:    "--- snapshot\n+++ draft\n",
		StructuredDiff: []svc.DiffEntry{{Path: "Status", Op: "changed", OldValue: "Enable", NewValue: "Disable"}},
	}
	b, err := FirewallRuleDiffEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.firewallRuleDiff"`)
	require.Contains(t, string(b), `"hasChanges": true`)
	require.Contains(t, string(b), `"path": "Status"`)
}

func TestFirewallRulePushEnvelope_DryRun(t *testing.T) {
	r := &svc.FirewallRulePushResult{
		Profile:   "home",
		Rule:      "X",
		Operation: "update",
		DryRun:    true,
		Preview:   &svc.Preview{Mutating: true, Verbs: []string{"Set:update"}},
	}
	b, err := FirewallRulePushEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Contains(t, string(b), `"applied": false`)
	require.Contains(t, string(b), `"dryRun": true`)
}

func TestFirewallRulePushEnvelope_Apply(t *testing.T) {
	r := &svc.FirewallRulePushResult{
		Profile:     "home",
		Rule:        "X",
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: "def456",
		Item:        map[string]any{"Name": "X", "Status": "Enable"},
	}
	b, err := FirewallRulePushEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"applied": true`)
	require.Contains(t, string(b), `"newDiffHash": "def456"`)
	require.Contains(t, string(b), `"item":`)
}
