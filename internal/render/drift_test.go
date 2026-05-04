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

func driftFixture(changes []svc.DriftChange) *svc.DriftResult {
	return &svc.DriftResult{
		SnapshotPath:      "/tmp/snap/2026-05-03T20-30-00Z",
		Profile:           "home",
		SnapshotCreatedAt: time.Date(2026, 5, 3, 20, 30, 0, 0, time.UTC),
		CheckedAt:         time.Date(2026, 5, 3, 21, 0, 0, 0, time.UTC),
		Summary: svc.DriftSummary{
			Added: 1, Modified: 1, Removed: 1, Unchanged: 2,
			PerType: map[string]svc.DriftSummaryPerType{
				"IPHost":       {Added: 1, Modified: 0, Removed: 0, Unchanged: 1},
				"FirewallRule": {Added: 0, Modified: 1, Removed: 1, Unchanged: 1},
			},
		},
		Changes: changes,
	}
}

func TestDriftEnvelope_Shape(t *testing.T) {
	r := driftFixture([]svc.DriftChange{
		{Type: "IPHost", Name: "Box-A", Change: "added", Body: map[string]any{"Name": "Box-A", "IPAddress": "10.0.0.1"}},
		{Type: "FirewallRule", Name: "Rule-1", Change: "modified", Diff: "@@ ... @@\n-a\n+b\n"},
		{Type: "FirewallRule", Name: "Rule-Old", Change: "removed"},
	})
	got, err := DriftEnvelope(r)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	require.Equal(t, "sophosfw.v1.drift", env["schema"])
	require.Equal(t, "home", env["profile"])
	require.Equal(t, r.SnapshotPath, env["snapshot"])
	require.Equal(t, "2026-05-03T20:30:00Z", env["snapshotCreatedAt"])
	require.Equal(t, "2026-05-03T21:00:00Z", env["checkedAt"])

	summary, ok := env["summary"].(map[string]any)
	require.True(t, ok)
	require.EqualValues(t, 1, summary["added"])
	require.EqualValues(t, 1, summary["modified"])
	require.EqualValues(t, 1, summary["removed"])
	require.EqualValues(t, 2, summary["unchanged"])

	perType, ok := summary["perType"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, perType, "IPHost")
	require.Contains(t, perType, "FirewallRule")

	changes, ok := env["changes"].([]any)
	require.True(t, ok)
	require.Len(t, changes, 3)
}

func TestDriftEnvelope_SortsChanges(t *testing.T) {
	// Provide changes deliberately out of order; expect sort by
	// (Type, Name, Change).
	r := driftFixture([]svc.DriftChange{
		{Type: "IPHost", Name: "z-host", Change: "added", Body: map[string]any{"Name": "z-host"}},
		{Type: "FirewallRule", Name: "Rule-Z", Change: "removed"},
		{Type: "IPHost", Name: "a-host", Change: "modified", Diff: "@@ ... @@\n"},
		{Type: "FirewallRule", Name: "Rule-A", Change: "modified", Diff: "@@ ... @@\n"},
		// Same Type+Name, different Change — Change tiebreaker.
		{Type: "IPHost", Name: "a-host", Change: "added", Body: map[string]any{"Name": "a-host"}},
	})
	got, err := DriftEnvelope(r)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	changes, ok := env["changes"].([]any)
	require.True(t, ok)
	require.Len(t, changes, 5)

	type triple struct{ typ, name, change string }
	want := []triple{
		{"FirewallRule", "Rule-A", "modified"},
		{"FirewallRule", "Rule-Z", "removed"},
		{"IPHost", "a-host", "added"},
		{"IPHost", "a-host", "modified"},
		{"IPHost", "z-host", "added"},
	}
	for i, c := range changes {
		m, ok := c.(map[string]any)
		require.True(t, ok)
		require.Equal(t, want[i].typ, m["type"], "row %d type", i)
		require.Equal(t, want[i].name, m["name"], "row %d name", i)
		require.Equal(t, want[i].change, m["change"], "row %d change", i)
	}
}

func TestDriftEnvelope_OmitsEmptyDiff(t *testing.T) {
	r := driftFixture([]svc.DriftChange{
		{Type: "IPHost", Name: "Box-A", Change: "modified", Diff: ""},
	})
	got, err := DriftEnvelope(r)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	changes, ok := env["changes"].([]any)
	require.True(t, ok)
	require.Len(t, changes, 1)
	row, ok := changes[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "modified", row["change"])
	_, hasDiff := row["diff"]
	require.False(t, hasDiff, "empty Diff should not emit a diff key")
}

func TestDriftHumanText_TableHeaders(t *testing.T) {
	r := driftFixture([]svc.DriftChange{
		{Type: "IPHost", Name: "Box-A", Change: "added", Body: map[string]any{"Name": "Box-A"}},
	})
	var buf bytes.Buffer
	require.NoError(t, DriftHumanText(&buf, r))
	out := buf.String()

	require.Contains(t, out, "Type")
	require.Contains(t, out, "Added")
	require.Contains(t, out, "Modified")
	require.Contains(t, out, "Removed")
	require.Contains(t, out, "Unchanged")
	require.Contains(t, out, "Profile: home")
	require.Contains(t, out, "Total: 1 added, 1 modified, 1 removed (unchanged: 2)")

	// Per-type rows alphabetised by tag.
	fwIdx := strings.Index(out, "FirewallRule")
	ipIdx := strings.Index(out, "IPHost")
	require.GreaterOrEqual(t, fwIdx, 0)
	require.GreaterOrEqual(t, ipIdx, 0)
	require.Less(t, fwIdx, ipIdx, "FirewallRule must precede IPHost in the table")
}

func TestDriftHumanText_PerRecordSection(t *testing.T) {
	r := driftFixture([]svc.DriftChange{
		{Type: "IPHost", Name: "Box-A", Change: "added", Body: map[string]any{"Name": "Box-A", "IPAddress": "10.0.0.1"}},
		{Type: "FirewallRule", Name: "Rule-1", Change: "modified", Diff: "@@ -1 +1 @@\n-a\n+b\n"},
		{Type: "FirewallRule", Name: "Rule-Old", Change: "removed"},
	})
	var buf bytes.Buffer
	require.NoError(t, DriftHumanText(&buf, r))
	out := buf.String()

	require.Contains(t, out, "--- Modified: FirewallRule/Rule-1.yaml")
	require.Contains(t, out, "+++ Modified: FirewallRule/Rule-1 (live)")
	require.Contains(t, out, "@@ -1 +1 @@")
	require.Contains(t, out, "--- Removed: FirewallRule/Rule-Old")
	require.Contains(t, out, "+++ Added: IPHost/Box-A")
	require.Contains(t, out, "IPAddress: 10.0.0.1")
}

func TestDriftHumanText_ModifiedEmptyDiff_NoBody(t *testing.T) {
	r := driftFixture([]svc.DriftChange{
		{Type: "IPHost", Name: "Box-A", Change: "modified", Diff: ""},
	})
	var buf bytes.Buffer
	require.NoError(t, DriftHumanText(&buf, r))
	out := buf.String()

	require.Contains(t, out, "--- Modified: IPHost/Box-A.yaml")
	require.Contains(t, out, "+++ Modified: IPHost/Box-A (live)")
}
