package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// VPNProfile MCP handler tests. Mirror vpn_ipsec_test.go (T8) for
// list/show, and iphostgroup_mutation_test.go for create/update/delete.

func TestVPNProfileList_Handler_ReturnsRecords(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNProfile": {json.RawMessage(`{"Name":"P1","AuthenticationMode":"PresharedKey"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleVPNProfileList(context.Background(), nil, VPNProfileListInput{})
	require.NoError(t, err)
	text := textOf(out)
	require.Contains(t, text, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, text, `"Name": "P1"`)
}

func TestVPNProfileShow_Handler_InjectsDiffHash(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNProfile": {json.RawMessage(`{"Name":"P1","AuthenticationMode":"PresharedKey"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleVPNProfileShow(context.Background(), nil, VPNProfileShowInput{Name: "P1"})
	require.NoError(t, err)
	text := textOf(out)
	require.Contains(t, text, `"schema": "sophosfw.v1.object"`)
	require.Contains(t, text, `"_diffHash":`)
}

func TestVPNProfileCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleVPNProfileCreate(context.Background(), nil, VPNProfileCreateInput{
		Name:    "P1",
		Body:    map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestVPNProfileCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleVPNProfileCreate(context.Background(), nil, VPNProfileCreateInput{
		Name:    "P1",
		Body:    map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestVPNProfileCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNProfile": {mustJSON(t, body)},
	})
	out, _, err := s.handleVPNProfileCreate(context.Background(), nil, VPNProfileCreateInput{
		Name: "P1", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.vpnProfileMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<VPNProfile>`)
}

func TestVPNProfileUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNProfile": {mustJSON(t, body)},
	})
	out, _, err := s.handleVPNProfileUpdate(context.Background(), nil, VPNProfileUpdateInput{
		Name: "P1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestVPNProfileUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNProfile": {mustJSON(t, body)},
	})
	out, _, err := s.handleVPNProfileUpdate(context.Background(), nil, VPNProfileUpdateInput{
		Name: "P1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestVPNProfileUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNProfile": {mustJSON(t, live)},
	})
	body := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	out, _, err := s.handleVPNProfileUpdate(context.Background(), nil, VPNProfileUpdateInput{
		Name: "P1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.vpnProfileMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestVPNProfileDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleVPNProfileDelete(context.Background(), nil, VPNProfileDeleteInput{
		Name:    "P1",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestVPNProfileDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{"Name": "P1", "AuthenticationMode": "PresharedKey"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNProfile": {mustJSON(t, live)},
	})
	out, _, err := s.handleVPNProfileDelete(context.Background(), nil, VPNProfileDeleteInput{
		Name:             "P1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.vpnProfileMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<VPNProfile>`)
}
