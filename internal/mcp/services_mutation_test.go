package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// Services mutation handler tests. Mirror fqdnhost_mutation_test.go
// exactly, with Services tag, service_* tools, and the
// sophosfw.v1.servicesMutation schema name on apply.

func validServicesMcpBody() map[string]any {
	return map[string]any{
		"Name": "ssh",
		"Type": "TCPorUDP",
		"ServiceDetails": map[string]any{
			"ServiceDetail": map[string]any{
				"Protocol":        "TCP",
				"SourcePort":      "1:65535",
				"DestinationPort": "22",
			},
		},
	}
}

func TestServicesCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleServicesCreate(context.Background(), nil, ServicesCreateInput{
		Name:    "ssh",
		Body:    validServicesMcpBody(),
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestServicesCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleServicesCreate(context.Background(), nil, ServicesCreateInput{
		Name:    "ssh",
		Body:    validServicesMcpBody(),
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestServicesCreate_Handler_Apply(t *testing.T) {
	body := validServicesMcpBody()
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, body)},
	})
	out, _, err := s.handleServicesCreate(context.Background(), nil, ServicesCreateInput{
		Name: "ssh", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.servicesMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<Services>`)
}

func TestServicesUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := validServicesMcpBody()
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, body)},
	})
	out, _, err := s.handleServicesUpdate(context.Background(), nil, ServicesUpdateInput{
		Name: "ssh", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestServicesUpdate_Handler_DryRun(t *testing.T) {
	body := validServicesMcpBody()
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, body)},
	})
	out, _, err := s.handleServicesUpdate(context.Background(), nil, ServicesUpdateInput{
		Name: "ssh", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestServicesUpdate_Handler_Apply(t *testing.T) {
	live := validServicesMcpBody()
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, live)},
	})
	body := validServicesMcpBody()
	out, _, err := s.handleServicesUpdate(context.Background(), nil, ServicesUpdateInput{
		Name: "ssh", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.servicesMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestServicesDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleServicesDelete(context.Background(), nil, ServicesDeleteInput{
		Name:    "ssh",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestServicesDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := validServicesMcpBody()
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"Services": {mustJSON(t, live)},
	})
	out, _, err := s.handleServicesDelete(context.Background(), nil, ServicesDeleteInput{
		Name:             "ssh",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.servicesMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<Services>`)
}
