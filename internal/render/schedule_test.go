package render

import (
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestScheduleEnvelopes(t *testing.T) {
	list := &svc.ObjectList{Profile: "testvm", Count: 1, Items: []any{map[string]any{"Name": "Night", "Type": "Recurring"}}}
	b, err := ScheduleListEnvelope(list)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))
	require.Equal(t, "sophosfw.v1.scheduleList", got["schema"])
	require.Equal(t, float64(1), got["count"])

	show := &svc.ScheduleShow{Object: &svc.Object{Profile: "testvm", Name: "Night", Data: map[string]any{"Name": "Night", "_diffHash": "hash"}}, References: &svc.References{Refs: map[string][]string{"FirewallRule": {"a"}}}}
	b, err = ScheduleShowEnvelope(show)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &got))
	data, ok := got["data"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, data, "references")
	references, ok := got["references"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []any{"a"}, references["FirewallRule"])
}
