package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestFirewallRuleCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFirewallRuleCreate(context.Background(), nil, FirewallRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
		},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFirewallRuleCreate(context.Background(), nil, FirewallRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
		},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleCreate(context.Background(), nil, FirewallRuleCreateInput{
		Name: "X", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
}

func TestFirewallRuleUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleUpdate(context.Background(), nil, FirewallRuleUpdateInput{
		Name: "X", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleFirewallRuleUpdate(context.Background(), nil, FirewallRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, live)},
	})
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	out, _, err := s.handleFirewallRuleUpdate(context.Background(), nil, FirewallRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestFirewallRuleDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFirewallRuleDelete(context.Background(), nil, FirewallRuleDeleteInput{
		Name:    "X",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFirewallRuleDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FirewallRule": {mustJSON(t, live)},
	})
	out, _, err := s.handleFirewallRuleDelete(context.Background(), nil, FirewallRuleDeleteInput{
		Name:             "X",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
}
