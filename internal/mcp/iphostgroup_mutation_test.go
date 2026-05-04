package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// IPHostGroup mutation handler tests. Mirror firewall_rule_mutation_test.go
// exactly, with IPHostGroup tag, host_group_* tools, and the sophosfw.v1.
// ipHostGroupMutation schema name on apply.

func TestIPHostGroupCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleIPHostGroupCreate(context.Background(), nil, IPHostGroupCreateInput{
		Name:    "G1",
		Body:    map[string]any{"Name": "G1", "IPFamily": "IPv4"},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestIPHostGroupCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleIPHostGroupCreate(context.Background(), nil, IPHostGroupCreateInput{
		Name:    "G1",
		Body:    map[string]any{"Name": "G1", "IPFamily": "IPv4"},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestIPHostGroupCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPHostGroupCreate(context.Background(), nil, IPHostGroupCreateInput{
		Name: "G1", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.ipHostGroupMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<IPHostGroup>`)
}

func TestIPHostGroupUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPHostGroupUpdate(context.Background(), nil, IPHostGroupUpdateInput{
		Name: "G1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestIPHostGroupUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPHostGroupUpdate(context.Background(), nil, IPHostGroupUpdateInput{
		Name: "G1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestIPHostGroupUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, live)},
	})
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	out, _, err := s.handleIPHostGroupUpdate(context.Background(), nil, IPHostGroupUpdateInput{
		Name: "G1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.ipHostGroupMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestIPHostGroupDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleIPHostGroupDelete(context.Background(), nil, IPHostGroupDeleteInput{
		Name:    "G1",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestIPHostGroupDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHostGroup": {mustJSON(t, live)},
	})
	out, _, err := s.handleIPHostGroupDelete(context.Background(), nil, IPHostGroupDeleteInput{
		Name:             "G1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.ipHostGroupMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<IPHostGroup>`)
}
