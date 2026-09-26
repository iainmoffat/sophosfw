package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchedulePeriodsCell(t *testing.T) {
	require.Equal(t, "Sunday 00:00-23:59", schedulePeriodsCell(map[string]any{"ScheduleDetails": map[string]any{"ScheduleDetail": map[string]any{"Days": "Sunday", "StartTime": "00:00", "StopTime": "23:59"}}}))
	require.Equal(t, "2 periods: Sunday 00:00-23:59, Saturday 00:00-23:59", schedulePeriodsCell(map[string]any{"ScheduleDetails": map[string]any{"ScheduleDetail": []any{
		map[string]any{"Days": "Sunday", "StartTime": "00:00", "StopTime": "23:59"},
		map[string]any{"Days": "Saturday", "StartTime": "00:00", "StopTime": "23:59"},
	}}}))
	require.Equal(t, "-", schedulePeriodsCell(map[string]any{"Type": "OneTime"}))
	require.Equal(t, "2 periods: a, b", summarizeCell([]any{"a", "b"}, "periods"))
}
