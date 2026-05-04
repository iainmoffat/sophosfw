package render

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

func TestBackupCreateEnvelope_Shape(t *testing.T) {
	r := &svc.BackupCreateResult{
		Profile:       "home",
		Path:          "/tmp/snap/2026-05-03T20-30-00Z",
		CreatedAt:     time.Date(2026, 5, 3, 20, 30, 0, 0, time.UTC),
		TypesIncluded: []string{"FirewallRule", "IPHost"},
		RecordCounts:  map[string]int{"FirewallRule": 4, "IPHost": 7},
		TotalRecords:  11,
	}
	got, err := BackupCreateEnvelope(r)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	require.Equal(t, "sophosfw.v1.backupCreate", env["schema"])
	require.Equal(t, "home", env["profile"])
	require.Equal(t, "/tmp/snap/2026-05-03T20-30-00Z", env["path"])
	require.Equal(t, "2026-05-03T20:30:00Z", env["createdAt"])
	require.EqualValues(t, 11, env["totalRecords"])

	counts, ok := env["recordCounts"].(map[string]any)
	require.True(t, ok)
	require.EqualValues(t, 4, counts["FirewallRule"])
	require.EqualValues(t, 7, counts["IPHost"])

	types, ok := env["typesIncluded"].([]any)
	require.True(t, ok)
	require.Len(t, types, 2)
}

func TestBackupListEnvelope_Empty(t *testing.T) {
	got, err := BackupListEnvelope("home", nil)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	require.Equal(t, "sophosfw.v1.backupList", env["schema"])
	require.Equal(t, "home", env["profile"])

	snaps, ok := env["snapshots"].([]any)
	require.True(t, ok, "snapshots key must marshal as a JSON array even when empty")
	require.Len(t, snaps, 0)
}

func TestBackupListEnvelope_Multiple(t *testing.T) {
	t1 := time.Date(2026, 5, 3, 20, 30, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 4, 9, 15, 0, 0, time.UTC)
	entries := []svc.BackupListEntry{
		{Path: "/tmp/snap/a", CreatedAt: t2, RecordCounts: map[string]int{"IPHost": 2}},
		{Path: "/tmp/snap/b", CreatedAt: t1, RecordCounts: map[string]int{"IPHost": 1}},
	}
	got, err := BackupListEnvelope("home", entries)
	require.NoError(t, err)

	var env map[string]any
	require.NoError(t, json.Unmarshal(got, &env))
	require.Equal(t, "sophosfw.v1.backupList", env["schema"])

	snaps, ok := env["snapshots"].([]any)
	require.True(t, ok)
	require.Len(t, snaps, 2)

	first, ok := snaps[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "/tmp/snap/a", first["path"])
	require.Equal(t, "2026-05-04T09:15:00Z", first["createdAt"])

	second, ok := snaps[1].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "/tmp/snap/b", second["path"])
	require.Equal(t, "2026-05-03T20:30:00Z", second["createdAt"])
}
