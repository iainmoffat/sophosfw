package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// FQDNHostGroup mutation handler tests. Mirror iphostgroup_mutation_test.go
// exactly, with FQDNHostGroup tag, host_fqdn_* tools, and the sophosfw.v1.
// fqdnHostGroupMutation schema name on apply.

func TestFQDNHostGroupCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFQDNHostGroupCreate(context.Background(), nil, FQDNHostGroupCreateInput{
		Name:    "F1",
		Body:    map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroupCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFQDNHostGroupCreate(context.Background(), nil, FQDNHostGroupCreateInput{
		Name:    "F1",
		Body:    map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroupCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostGroupCreate(context.Background(), nil, FQDNHostGroupCreateInput{
		Name: "F1", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.fqdnHostGroupMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<FQDNHostGroup>`)
}

func TestFQDNHostGroupUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostGroupUpdate(context.Background(), nil, FQDNHostGroupUpdateInput{
		Name: "F1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroupUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, body)},
	})
	out, _, err := s.handleFQDNHostGroupUpdate(context.Background(), nil, FQDNHostGroupUpdateInput{
		Name: "F1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroupUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, live)},
	})
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	out, _, err := s.handleFQDNHostGroupUpdate(context.Background(), nil, FQDNHostGroupUpdateInput{
		Name: "F1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.fqdnHostGroupMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestFQDNHostGroupDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleFQDNHostGroupDelete(context.Background(), nil, FQDNHostGroupDeleteInput{
		Name:    "F1",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroupDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"FQDNHostGroup": {mustJSON(t, live)},
	})
	out, _, err := s.handleFQDNHostGroupDelete(context.Background(), nil, FQDNHostGroupDeleteInput{
		Name:             "F1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.fqdnHostGroupMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<FQDNHostGroup>`)
}
