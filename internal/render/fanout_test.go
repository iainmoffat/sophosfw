package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

func fanoutFixtureAllOK() *svc.FanoutResult {
	start := time.Date(2026, 5, 3, 21, 0, 0, 0, time.UTC)
	return &svc.FanoutResult{
		Operation:   "ipHostGroup.add",
		Profiles:    []string{"home", "office"},
		Mutating:    true,
		PreflightOK: true,
		Aborted:     false,
		StartedAt:   start,
		EndedAt:     start.Add(2 * time.Second),
		Results: []svc.FanoutProfileResult{
			{
				Profile:     "home",
				Phase:       "apply",
				Status:      "ok",
				DurationMs:  120,
				StartedAt:   start,
				ApplyResult: map[string]any{"name": "Group-A"},
			},
			{
				Profile:     "office",
				Phase:       "apply",
				Status:      "ok",
				DurationMs:  150,
				StartedAt:   start.Add(200 * time.Millisecond),
				ApplyResult: map[string]any{"name": "Group-A"},
			},
		},
	}
}

func TestFanoutEnvelope_Shape(t *testing.T) {
	r := fanoutFixtureAllOK()
	got, err := FanoutEnvelope(r)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))

	require.Equal(t, "sophosfw.v1.fanoutResult", env["schema"])
	require.Equal(t, "ipHostGroup.add", env["operation"])
	require.Equal(t, true, env["mutating"])
	require.Equal(t, true, env["preflightOK"])
	require.Equal(t, false, env["aborted"])
	require.Equal(t, "2026-05-03T21:00:00Z", env["startedAt"])
	require.Equal(t, "2026-05-03T21:00:02Z", env["endedAt"])

	profiles, ok := env["profiles"].([]any)
	require.True(t, ok)
	require.Equal(t, []any{"home", "office"}, profiles)

	results, ok := env["results"].([]any)
	require.True(t, ok)
	require.Len(t, results, 2)

	first, ok := results[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "home", first["profile"])
	require.Equal(t, "apply", first["phase"])
	require.Equal(t, "ok", first["status"])
	require.EqualValues(t, 120, first["durationMs"])
	require.Equal(t, "2026-05-03T21:00:00Z", first["startedAt"])
	require.Contains(t, first, "applyResult")
	require.NotContains(t, first, "error")
}

func TestFanoutEnvelope_OmitsEmptyError(t *testing.T) {
	r := fanoutFixtureAllOK()
	got, err := FanoutEnvelope(r)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	results, ok := env["results"].([]any)
	require.True(t, ok)
	for _, raw := range results {
		entry, ok := raw.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "ok", entry["status"])
		_, hasError := entry["error"]
		require.False(t, hasError, "ok entries must not include error key")
	}
}

func TestFanoutHumanText_AllOK(t *testing.T) {
	r := fanoutFixtureAllOK()
	var buf bytes.Buffer
	require.NoError(t, FanoutHumanText(&buf, r))

	out := buf.String()
	require.Contains(t, out, "Operation: ipHostGroup.add")
	require.Contains(t, out, "Profiles: 2")
	require.Contains(t, out, "[home] apply OK (120ms)")
	require.Contains(t, out, "[office] apply OK (150ms)")
	require.Contains(t, out, "2 succeeded, 0 failed, 0 skipped.")
}

func TestFanoutHumanText_PreflightFailure(t *testing.T) {
	start := time.Date(2026, 5, 3, 21, 0, 0, 0, time.UTC)
	r := &svc.FanoutResult{
		Operation:   "ipHostGroup.add",
		Profiles:    []string{"home", "office"},
		Mutating:    true,
		PreflightOK: false,
		Aborted:     true,
		StartedAt:   start,
		EndedAt:     start.Add(time.Second),
		Results: []svc.FanoutProfileResult{
			{
				Profile:    "home",
				Phase:      "preflight",
				Status:     "ok",
				DurationMs: 50,
				StartedAt:  start,
			},
			{
				Profile:    "office",
				Phase:      "preflight",
				Status:     "error",
				Error:      "auth failed: invalid credentials",
				DurationMs: 80,
				StartedAt:  start,
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, FanoutHumanText(&buf, r))
	out := buf.String()

	require.Contains(t, out, "[home] preflight OK (50ms)")
	require.Contains(t, out, "[office] preflight ERR (80ms): auth failed: invalid credentials")
	require.Contains(t, out, "1 succeeded, 1 failed, 0 skipped.")

	// Envelope reflects the abort flag too.
	env, err := FanoutEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(env), `"aborted": true`)
	require.Contains(t, string(env), `"preflightOK": false`)

	// Error entry includes the error key; ok entry does not.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(env, &parsed))
	results, ok := parsed["results"].([]any)
	require.True(t, ok)
	okEntry, ok := results[0].(map[string]any)
	require.True(t, ok)
	errEntry, ok := results[1].(map[string]any)
	require.True(t, ok)
	_, hasError := okEntry["error"]
	require.False(t, hasError)
	require.Equal(t, "auth failed: invalid credentials", errEntry["error"])
}

func TestFanoutHumanText_ApplyFailureWithSkipped(t *testing.T) {
	start := time.Date(2026, 5, 3, 21, 0, 0, 0, time.UTC)
	r := &svc.FanoutResult{
		Operation:   "ipHostGroup.add",
		Profiles:    []string{"home", "office", "dc1"},
		Mutating:    true,
		PreflightOK: true,
		Aborted:     false,
		StartedAt:   start,
		EndedAt:     start.Add(2 * time.Second),
		Results: []svc.FanoutProfileResult{
			{
				Profile:     "home",
				Phase:       "apply",
				Status:      "ok",
				DurationMs:  100,
				StartedAt:   start,
				ApplyResult: map[string]any{"name": "Group-A"},
			},
			{
				Profile:    "office",
				Phase:      "apply",
				Status:     "error",
				Error:      "boom: rejected by firewall",
				DurationMs: 200,
				StartedAt:  start.Add(100 * time.Millisecond),
			},
			{
				Profile: "dc1",
				Phase:   "skipped",
				Status:  "skipped",
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, FanoutHumanText(&buf, r))
	out := buf.String()

	require.Contains(t, out, "[home] apply OK (100ms)")
	require.Contains(t, out, "[office] apply ERR (200ms): boom: rejected by firewall")
	require.Contains(t, out, "[dc1] skipped")
	require.Contains(t, out, "1 succeeded, 1 failed, 1 skipped.")

	// dc1 line is "skipped" without phase/duration noise.
	var dc1Line string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "[dc1]") {
			dc1Line = line
			break
		}
	}
	require.Equal(t, "  [dc1] skipped", dc1Line)
}
