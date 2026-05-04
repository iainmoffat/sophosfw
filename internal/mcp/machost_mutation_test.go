package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// MACHost mutation handler tests. Mirror iphostgroup_mutation_test.go
// exactly, with MACHost tag, host_mac_* tools, and the sophosfw.v1.
// macHostMutation schema name on apply.

func TestMACHostCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleMACHostCreate(context.Background(), nil, MACHostCreateInput{
		Name:    "M1",
		Body:    map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestMACHostCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleMACHostCreate(context.Background(), nil, MACHostCreateInput{
		Name:    "M1",
		Body:    map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestMACHostCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleMACHostCreate(context.Background(), nil, MACHostCreateInput{
		Name: "M1", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.macHostMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<MACHost>`)
}

func TestMACHostUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleMACHostUpdate(context.Background(), nil, MACHostUpdateInput{
		Name: "M1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestMACHostUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, body)},
	})
	out, _, err := s.handleMACHostUpdate(context.Background(), nil, MACHostUpdateInput{
		Name: "M1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestMACHostUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, live)},
	})
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	out, _, err := s.handleMACHostUpdate(context.Background(), nil, MACHostUpdateInput{
		Name: "M1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.macHostMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestMACHostDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleMACHostDelete(context.Background(), nil, MACHostDeleteInput{
		Name:    "M1",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestMACHostDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"MACHost": {mustJSON(t, live)},
	})
	out, _, err := s.handleMACHostDelete(context.Background(), nil, MACHostDeleteInput{
		Name:             "M1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.macHostMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<MACHost>`)
}
