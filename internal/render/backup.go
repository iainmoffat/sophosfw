// Package render backup.go: envelopes for `sophosfw backup` and
// `sophosfw backup list`.
package render

import (
	"time"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// BackupCreateEnvelope renders sophosfw.v1.backupCreate from the result
// returned by BackupSvc.Create. CreatedAt is normalised to UTC RFC 3339
// so machine consumers see a single canonical timestamp shape.
func BackupCreateEnvelope(r *svc.BackupCreateResult) ([]byte, error) {
	payload := map[string]any{
		"profile":       r.Profile,
		"path":          r.Path,
		"createdAt":     r.CreatedAt.UTC().Format(time.RFC3339),
		"typesIncluded": r.TypesIncluded,
		"recordCounts":  r.RecordCounts,
		"totalRecords":  r.TotalRecords,
	}
	return marshalEnvelope("sophosfw.v1.backupCreate", payload)
}

// BackupListEnvelope renders sophosfw.v1.backupList from the entries
// returned by BackupSvc.List. The snapshots array preserves the
// caller's ordering (BackupSvc.List sorts newest-first).
func BackupListEnvelope(profile string, entries []svc.BackupListEntry) ([]byte, error) {
	snapshots := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		snapshots = append(snapshots, map[string]any{
			"path":         e.Path,
			"createdAt":    e.CreatedAt.UTC().Format(time.RFC3339),
			"recordCounts": e.RecordCounts,
		})
	}
	return marshalEnvelope("sophosfw.v1.backupList", map[string]any{
		"profile":   profile,
		"snapshots": snapshots,
	})
}
