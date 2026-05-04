package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// ServiceGroup mutation handler tests. Mirror fqdnhostgroup_mutation_test.go
// exactly, with ServiceGroup tag, service_group_* tools, and the
// sophosfw.v1.serviceGroupMutation schema name on apply.

func TestServiceGroupCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleServiceGroupCreate(context.Background(), nil, ServiceGroupCreateInput{
		Name:    "g",
		Body:    map[string]any{"Name": "g"},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestServiceGroupCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleServiceGroupCreate(context.Background(), nil, ServiceGroupCreateInput{
		Name:    "g",
		Body:    map[string]any{"Name": "g"},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestServiceGroupCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{"Name": "g"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleServiceGroupCreate(context.Background(), nil, ServiceGroupCreateInput{
		Name: "g", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.serviceGroupMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<ServiceGroup>`)
}

func TestServiceGroupUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "g"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleServiceGroupUpdate(context.Background(), nil, ServiceGroupUpdateInput{
		Name: "g", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestServiceGroupUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{"Name": "g"}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleServiceGroupUpdate(context.Background(), nil, ServiceGroupUpdateInput{
		Name: "g", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestServiceGroupUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{"Name": "g"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, live)},
	})
	body := map[string]any{"Name": "g"}
	out, _, err := s.handleServiceGroupUpdate(context.Background(), nil, ServiceGroupUpdateInput{
		Name: "g", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.serviceGroupMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestServiceGroupDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleServiceGroupDelete(context.Background(), nil, ServiceGroupDeleteInput{
		Name:    "g",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestServiceGroupDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{"Name": "g"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"ServiceGroup": {mustJSON(t, live)},
	})
	out, _, err := s.handleServiceGroupDelete(context.Background(), nil, ServiceGroupDeleteInput{
		Name:             "g",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.serviceGroupMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<ServiceGroup>`)
}
