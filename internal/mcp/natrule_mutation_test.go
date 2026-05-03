package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestNATRuleCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleNATRuleCreate(context.Background(), nil, NATRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleNATRuleCreate(context.Background(), nil, NATRuleCreateInput{
		Name: "X",
		Body: map[string]any{
			"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleCreate(context.Background(), nil, NATRuleCreateInput{
		Name: "X", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
}

func TestNATRuleUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleUpdate(context.Background(), nil, NATRuleUpdateInput{
		Name: "X", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, body)},
	})
	out, _, err := s.handleNATRuleUpdate(context.Background(), nil, NATRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, live)},
	})
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	out, _, err := s.handleNATRuleUpdate(context.Background(), nil, NATRuleUpdateInput{
		Name: "X", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRulePush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestNATRuleDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleNATRuleDelete(context.Background(), nil, NATRuleDeleteInput{
		Name:    "X",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestNATRuleDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"NATRule": {mustJSON(t, live)},
	})
	out, _, err := s.handleNATRuleDelete(context.Background(), nil, NATRuleDeleteInput{
		Name:             "X",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRulePush"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
}
