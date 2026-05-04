package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// IPsecPolicy MCP handler tests. Mirror vpn_ipsec_test.go (T8) for
// list/show, and iphostgroup_mutation_test.go for create/update/delete.

func TestIPsecPolicyList_Handler_ReturnsRecords(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPsecPolicy": {json.RawMessage(`{"Name":"P1"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleIPsecPolicyList(context.Background(), nil, IPsecPolicyListInput{})
	require.NoError(t, err)
	text := textOf(out)
	require.Contains(t, text, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, text, `"Name": "P1"`)
}

func TestIPsecPolicyShow_Handler_InjectsDiffHash(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPsecPolicy": {json.RawMessage(`{"Name":"P1"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleIPsecPolicyShow(context.Background(), nil, IPsecPolicyShowInput{Name: "P1"})
	require.NoError(t, err)
	text := textOf(out)
	require.Contains(t, text, `"schema": "sophosfw.v1.object"`)
	require.Contains(t, text, `"_diffHash":`)
}

func TestIPsecPolicyCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleIPsecPolicyCreate(context.Background(), nil, IPsecPolicyCreateInput{
		Name:    "P1",
		Body:    map[string]any{"Name": "P1"},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestIPsecPolicyCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleIPsecPolicyCreate(context.Background(), nil, IPsecPolicyCreateInput{
		Name:    "P1",
		Body:    map[string]any{"Name": "P1"},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestIPsecPolicyCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{"Name": "P1"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPsecPolicy": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPsecPolicyCreate(context.Background(), nil, IPsecPolicyCreateInput{
		Name: "P1", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.ipsecPolicyMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<IPsecPolicy>`)
}

func TestIPsecPolicyUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "P1"}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPsecPolicy": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPsecPolicyUpdate(context.Background(), nil, IPsecPolicyUpdateInput{
		Name: "P1", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestIPsecPolicyUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{"Name": "P1"}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPsecPolicy": {mustJSON(t, body)},
	})
	out, _, err := s.handleIPsecPolicyUpdate(context.Background(), nil, IPsecPolicyUpdateInput{
		Name: "P1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestIPsecPolicyUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPsecPolicy": {mustJSON(t, live)},
	})
	body := map[string]any{"Name": "P1"}
	out, _, err := s.handleIPsecPolicyUpdate(context.Background(), nil, IPsecPolicyUpdateInput{
		Name: "P1", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.ipsecPolicyMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestIPsecPolicyDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleIPsecPolicyDelete(context.Background(), nil, IPsecPolicyDeleteInput{
		Name:    "P1",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestIPsecPolicyDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPsecPolicy": {mustJSON(t, live)},
	})
	out, _, err := s.handleIPsecPolicyDelete(context.Background(), nil, IPsecPolicyDeleteInput{
		Name:             "P1",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.ipsecPolicyMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<IPsecPolicy>`)
}
