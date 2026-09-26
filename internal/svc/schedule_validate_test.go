package svc

import (
	"errors"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func scheduleBody(days, start, stop string) map[string]any {
	return map[string]any{
		"Name": "office", "Type": "Recurring",
		"ScheduleDetails": map[string]any{"ScheduleDetail": map[string]any{
			"Days": days, "StartTime": start, "StopTime": stop,
		}},
	}
}

func schedulePeriods(t *testing.T, body map[string]any) []any {
	t.Helper()
	details, ok := body["ScheduleDetails"].(map[string]any)
	require.True(t, ok)
	periods, ok := details["ScheduleDetail"].([]any)
	require.True(t, ok)
	return periods
}

func TestValidateScheduleBody(t *testing.T) {
	tests := []struct {
		name    string
		body    map[string]any
		wantErr string
		check   func(*testing.T, map[string]any, map[string]any)
	}{
		{name: "testvm valid periods", body: map[string]any{"Name": "ok", "Type": "Recurring", "ScheduleDetails": map[string]any{"ScheduleDetail": []any{
			map[string]any{"Days": "Sunday", "StartTime": "22:00", "StopTime": "23:00"},
			map[string]any{"Days": "All Days of week", "StartTime": "10:00", "StopTime": "11:00"},
			map[string]any{"Days": "Sunday", "StartTime": "10:15", "StopTime": "12:00"},
			map[string]any{"Days": "Sunday", "StartTime": "10:30", "StopTime": "12:00"},
			map[string]any{"Days": "Sunday", "StartTime": "10:00", "StopTime": "11:15"},
			map[string]any{"Days": "Sunday", "StartTime": "10:00", "StopTime": "11:45"},
			map[string]any{"Days": "Sunday", "StartTime": "00:00", "StopTime": "23:45"},
			map[string]any{"Days": "Sunday", "StartTime": "19:45", "StopTime": "23:59"},
		}}}},
		{name: "two periods normalized array", body: map[string]any{"Name": "ok", "Type": "Recurring", "ScheduleDetails": map[string]any{"ScheduleDetail": []any{
			map[string]any{"Days": "Sunday", "StartTime": "19:45", "StopTime": "23:59"},
			map[string]any{"Days": "Monday", "StartTime": "00:00", "StopTime": "06:00"},
		}}}, check: func(t *testing.T, got map[string]any, _ map[string]any) {
			require.Len(t, schedulePeriods(t, got), 2)
		}},
		{name: "single object normalized array", body: scheduleBody("Sunday", "10:00", "11:00"), check: func(t *testing.T, got map[string]any, _ map[string]any) {
			require.Len(t, schedulePeriods(t, got), 1)
		}},
		{name: "off grid start", body: scheduleBody("Sunday", "10:05", "11:00"), wantErr: "StartTime \"10:05\" must be HH:MM"},
		{name: "off grid start ten minutes", body: scheduleBody("Sunday", "10:10", "11:00"), wantErr: "StartTime \"10:10\" must be HH:MM"},
		{name: "off grid stop", body: scheduleBody("Sunday", "10:00", "11:14"), wantErr: "StopTime \"11:14\" must be HH:MM"},
		{name: "off grid stop minute 59", body: scheduleBody("Sunday", "10:00", "11:59"), wantErr: "StopTime \"11:59\" must be HH:MM"},
		{name: "cross midnight", body: scheduleBody("Sunday", "23:00", "01:00"), wantErr: "Split it into Sunday 23:00-23:59 and Monday 00:00-01:00"},
		{name: "equal times", body: scheduleBody("Sunday", "10:00", "10:00"), wantErr: "is empty (StartTime equals StopTime)"},
		{name: "cross to midnight", body: scheduleBody("Friday", "20:00", "00:00"), wantErr: "Use Friday 20:00-23:59 instead"},
		{name: "cross aggregate", body: scheduleBody("Week Days", "19:45", "06:00"), wantErr: "is an aggregate"},
		{name: "saturday wraps", body: scheduleBody("Saturday", "20:00", "06:00"), wantErr: "and Sunday 00:00-06:00"},
		{name: "stop 24 hour", body: scheduleBody("Sunday", "10:00", "24:00"), wantErr: "StopTime \"24:00\" must be HH:MM"},
		{name: "stop 23:59 valid", body: scheduleBody("Sunday", "23:45", "23:59")},
		{name: "start 23:59 invalid", body: scheduleBody("Sunday", "23:59", "23:59"), wantErr: "StartTime \"23:59\" must be HH:MM"},
		{name: "bad day", body: scheduleBody("Weekend", "10:00", "11:00"), wantErr: "valid values:"},
		{name: "day case suggestion", body: scheduleBody("sunday", "10:00", "11:00"), wantErr: "did you mean \"Sunday\""},
		{name: "bad type", body: func() map[string]any { b := scheduleBody("Sunday", "10:00", "11:00"); b["Type"] = "OneTime"; return b }(), wantErr: "only Recurring schedules are writable (got \"OneTime\")"},
		{name: "missing type", body: func() map[string]any { b := scheduleBody("Sunday", "10:00", "11:00"); delete(b, "Type"); return b }(), wantErr: "only Recurring schedules are writable (got \"\")"},
		{name: "blank name", body: func() map[string]any { b := scheduleBody("Sunday", "10:00", "11:00"); b["Name"] = "   "; return b }(), wantErr: "Name must be a non-empty string"},
		{name: "non string name", body: func() map[string]any { b := scheduleBody("Sunday", "10:00", "11:00"); b["Name"] = 42; return b }(), wantErr: "Name must be a non-empty string"},
		{name: "details wrong shape", body: func() map[string]any {
			b := scheduleBody("Sunday", "10:00", "11:00")
			b["ScheduleDetails"] = "bad"
			return b
		}(), wantErr: "ScheduleDetails must be an object containing ScheduleDetail"},
		{name: "detail null", body: func() map[string]any {
			b := scheduleBody("Sunday", "10:00", "11:00")
			b["ScheduleDetails"] = map[string]any{"ScheduleDetail": nil}
			return b
		}(), wantErr: "ScheduleDetail must be an object or a non-empty array of objects"},
		{name: "detail empty", body: func() map[string]any {
			b := scheduleBody("Sunday", "10:00", "11:00")
			b["ScheduleDetails"] = map[string]any{"ScheduleDetail": []any{}}
			return b
		}(), wantErr: "ScheduleDetail must be an object or a non-empty array of objects"},
		{name: "detail bad element", body: func() map[string]any {
			b := scheduleBody("Sunday", "10:00", "11:00")
			b["ScheduleDetails"] = map[string]any{"ScheduleDetail": []any{"x"}}
			return b
		}(), wantErr: "ScheduleDetail must be an object or a non-empty array of objects"},
		{name: "missing stop period two", body: map[string]any{"Name": "ok", "Type": "Recurring", "ScheduleDetails": map[string]any{"ScheduleDetail": []any{
			map[string]any{"Days": "Sunday", "StartTime": "10:00", "StopTime": "11:00"}, map[string]any{"Days": "Monday", "StartTime": "10:00"},
		}}}, wantErr: "period 2: StopTime must be a string"},
		{name: "first failure wins", body: map[string]any{"Name": "ok", "Type": "Recurring", "ScheduleDetails": map[string]any{"ScheduleDetail": []any{
			map[string]any{"Days": "Weekend", "StartTime": "bad", "StopTime": "bad"}, map[string]any{"Days": "Sunday", "StartTime": "bad", "StopTime": "bad"},
		}}}, wantErr: "period 1: Days"},
		{name: "copy unknown keys and remove diff hash", body: func() map[string]any {
			b := scheduleBody("Sunday", "10:00", "11:00")
			b["_diffHash"] = "secret"
			b["Foo"] = "bar"
			b = map[string]any{"Name": "office", "Type": "Recurring", "Foo": "bar", "_diffHash": "secret", "ScheduleDetails": map[string]any{"ScheduleDetail": map[string]any{"Days": "Sunday", "StartTime": "10:00", "StopTime": "11:00", "Bar": "baz"}}}
			return b
		}(), check: func(t *testing.T, got map[string]any, _ map[string]any) {
			require.NotContains(t, got, "_diffHash")
			require.Equal(t, "bar", got["Foo"])
			detail, ok := schedulePeriods(t, got)[0].(map[string]any)
			require.True(t, ok)
			require.Equal(t, "baz", detail["Bar"])
		}},
		{name: "input is not mutated", body: func() map[string]any {
			b := scheduleBody("Sunday", "10:00", "11:00")
			b["_diffHash"] = "keep"
			return b
		}(), check: func(t *testing.T, got map[string]any, input map[string]any) {
			require.NotContains(t, got, "_diffHash")
			require.Equal(t, "keep", input["_diffHash"])
			details, ok := input["ScheduleDetails"].(map[string]any)
			require.True(t, ok)
			_, ok = details["ScheduleDetail"].(map[string]any)
			require.True(t, ok)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateScheduleBody(tt.body)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.ErrorIs(t, err, sophos.ErrInvalidRequest)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, got, tt.body)
			}
		})
	}

	t.Run("supported schedule days have pinned order", func(t *testing.T) {
		require.Equal(t, []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Week Days", "Weekdays Including Saturday", "All Days of week"}, scheduleDays)
	})
	t.Run("missing top-level fields are invalid requests", func(t *testing.T) {
		for _, key := range []string{"Name", "ScheduleDetails"} {
			body := scheduleBody("Sunday", "10:00", "11:00")
			delete(body, key)
			_, err := validateScheduleBody(body)
			require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
		}
	})
	t.Run("valid day vocabulary", func(t *testing.T) {
		for _, day := range scheduleDays {
			_, err := validateScheduleBody(scheduleBody(day, "10:00", "11:00"))
			require.NoError(t, err, day)
		}
	})
	t.Run("valid full error list", func(t *testing.T) {
		_, err := validateScheduleBody(scheduleBody("Weekend", "10:00", "11:00"))
		require.Contains(t, err.Error(), strings.Join(scheduleDays, ", "))
	})
}
