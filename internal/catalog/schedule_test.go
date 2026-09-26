package catalog

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func readScheduleFixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return json.RawMessage(b)
}

func scheduleMap(t *testing.T, value any) map[string]any {
	t.Helper()
	got, ok := value.(map[string]any)
	require.True(t, ok, "got %T", value)
	return got
}

func scheduleSlice(t *testing.T, value any) []any {
	t.Helper()
	got, ok := value.([]any)
	require.True(t, ok, "got %T", value)
	return got
}

func TestScheduleParser_NormalizesSingleDetail(t *testing.T) {
	got, err := ScheduleParser(readScheduleFixture(t, "schedule_single.json"))
	require.NoError(t, err)
	obj := scheduleMap(t, got)
	details := scheduleMap(t, obj["ScheduleDetails"])
	require.Equal(t, []any{map[string]any{"Days": "Sunday", "StartTime": "00:00", "StopTime": "23:59"}}, details["ScheduleDetail"])
}

func TestScheduleParser_PreservesMultipleDetailsInOrder(t *testing.T) {
	got, err := ScheduleParser(readScheduleFixture(t, "schedule_multi.json"))
	require.NoError(t, err)
	details := scheduleMap(t, scheduleMap(t, got)["ScheduleDetails"])
	items := scheduleSlice(t, details["ScheduleDetail"])
	require.Len(t, items, 2)
	require.Equal(t, "Sunday", scheduleMap(t, items[0])["Days"])
	require.Equal(t, "Saturday", scheduleMap(t, items[1])["Days"])
}

func TestScheduleParser_PreservesMissingAndNullShapes(t *testing.T) {
	t.Run("absent details", func(t *testing.T) {
		got, err := ScheduleParser(json.RawMessage(`{"Name":"once","Type":"OneTime"}`))
		require.NoError(t, err)
		require.NotContains(t, scheduleMap(t, got), "ScheduleDetails")
	})
	t.Run("null details", func(t *testing.T) {
		got, err := ScheduleParser(json.RawMessage(`{"ScheduleDetails":null}`))
		require.NoError(t, err)
		require.Nil(t, scheduleMap(t, got)["ScheduleDetails"])
	})
	t.Run("null detail", func(t *testing.T) {
		got, err := ScheduleParser(json.RawMessage(`{"ScheduleDetails":{"ScheduleDetail":null}}`))
		require.NoError(t, err)
		details := scheduleMap(t, scheduleMap(t, got)["ScheduleDetails"])
		require.Nil(t, details["ScheduleDetail"])
	})
}

func TestScheduleParser_PreservesOneTimeUnknownFields(t *testing.T) {
	got, err := ScheduleParser(readScheduleFixture(t, "schedule_onetime_nodetail.json"))
	require.NoError(t, err)
	require.Equal(t, map[string]any{
		"Name": "probe-onetime", "Type": "OneTime", "StartDate": "2026-10-01", "EndDate": "2026-10-02",
	}, got)
}

func TestScheduleParser_RejectsInvalidJSONAndNonObject(t *testing.T) {
	_, err := ScheduleParser(json.RawMessage(`{`))
	require.Error(t, err)
	_, err = ScheduleParser(json.RawMessage(`[]`))
	require.Error(t, err)
}

func TestNewDefault_RegistersScheduleParser(t *testing.T) {
	cat, err := NewDefault()
	require.NoError(t, err)
	for _, tag := range []string{"Schedule", "schedule"} {
		entry, ok := cat.Resolve(tag)
		require.True(t, ok)
		require.True(t, entry.Mutable)
	}
	got, err := cat.Parse("Schedule", readScheduleFixture(t, "schedule_single.json"))
	require.NoError(t, err)
	details := scheduleMap(t, scheduleMap(t, got)["ScheduleDetails"])
	require.IsType(t, []any{}, details["ScheduleDetail"])
}
