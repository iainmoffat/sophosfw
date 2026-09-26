package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func scheduleBody(name string) map[string]any {
	return map[string]any{"Name": name, "Type": "Recurring", "ScheduleDetails": map[string]any{"ScheduleDetail": map[string]any{"Days": "Monday", "StartTime": "09:00", "StopTime": "17:00"}}}
}

func TestScheduleCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleScheduleCreate(context.Background(), nil, ScheduleCreateInput{Name: "Work", Body: scheduleBody("Work")})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestScheduleCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleScheduleCreate(context.Background(), nil, ScheduleCreateInput{Name: "Work", Body: scheduleBody("Work"), Confirm: true, DryRun: true})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestScheduleCreate_Handler_RejectsBlankBodyName(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	body := scheduleBody("Work")
	body["Name"] = "  "
	out, _, err := s.handleScheduleCreate(context.Background(), nil, ScheduleCreateInput{Name: "Work", Body: body, Confirm: true, DryRun: true})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `body Name must be a non-empty string`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestScheduleDelete_Handler_ReferencedScheduleReturnsErrorEnvelope(t *testing.T) {
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"Schedule":     {json.RawMessage(`{"Name":"Work","Type":"Recurring"}`)},
		"FirewallRule": {json.RawMessage(`{"Name":"Allow-Work","Schedule":"Work"}`)},
	})
	out, _, err := s.handleScheduleDelete(context.Background(), nil, ScheduleDeleteInput{Name: "Work", IgnoreExpectedDiffHash: true, Confirm: true, DryRun: true})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `referenced by firewall rules`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}
