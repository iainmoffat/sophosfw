package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScheduleList_Handler(t *testing.T) {
	s := newServiceTestServer(t, map[string][]json.RawMessage{
		"Schedule": {json.RawMessage(`{"Name":"Work","Type":"Recurring"}`)},
	})
	out, _, err := s.handleScheduleList(context.Background(), nil, ScheduleListInput{})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.scheduleList"`)
	require.Contains(t, textOf(out), `"Name": "Work"`)
}

func TestScheduleShow_Handler_WithReferences(t *testing.T) {
	s := newServiceTestServer(t, map[string][]json.RawMessage{
		"Schedule":     {json.RawMessage(`{"Name":"Work","Type":"Recurring"}`)},
		"FirewallRule": {json.RawMessage(`{"Name":"Allow-Work","Schedule":"Work"}`)},
	})
	out, _, err := s.handleScheduleShow(context.Background(), nil, ScheduleShowInput{Name: "Work", WithReferences: true})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.schedule"`)
	require.Contains(t, textOf(out), `"data"`)
	require.Contains(t, textOf(out), `"references"`)
	require.Contains(t, textOf(out), `Allow-Work`)
}
