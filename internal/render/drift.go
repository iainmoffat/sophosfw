// Package render drift.go: envelope + human-text renderer for
// `sophosfw drift`.
package render

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// sortDriftChanges returns a copy of in sorted by (Type, Name, Change).
// Both DriftEnvelope and DriftHumanText apply the same ordering so JSON
// consumers and human readers see identical sequences.
func sortDriftChanges(in []svc.DriftChange) []svc.DriftChange {
	out := append([]svc.DriftChange(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Change < out[j].Change
	})
	return out
}

// DriftEnvelope renders sophosfw.v1.drift. Changes are sorted by
// (Type, Name, Change) before serialization for deterministic output.
// Diff and Body are emitted only when populated so the JSON shape stays
// minimal for "removed" entries and for "modified" entries that
// produced an empty diff (defensive — should not happen in practice).
func DriftEnvelope(r *svc.DriftResult) ([]byte, error) {
	perType := map[string]map[string]int{}
	for tag, s := range r.Summary.PerType {
		perType[tag] = map[string]int{
			"added":     s.Added,
			"modified":  s.Modified,
			"removed":   s.Removed,
			"unchanged": s.Unchanged,
		}
	}

	sorted := sortDriftChanges(r.Changes)
	changes := make([]map[string]any, 0, len(sorted))
	for _, c := range sorted {
		m := map[string]any{
			"type":   c.Type,
			"name":   c.Name,
			"change": c.Change,
		}
		if c.Diff != "" {
			m["diff"] = c.Diff
		}
		if c.Body != nil {
			m["body"] = c.Body
		}
		changes = append(changes, m)
	}

	payload := map[string]any{
		"snapshot":          r.SnapshotPath,
		"profile":           r.Profile,
		"snapshotCreatedAt": r.SnapshotCreatedAt.UTC().Format(time.RFC3339),
		"checkedAt":         r.CheckedAt.UTC().Format(time.RFC3339),
		"summary": map[string]any{
			"added":     r.Summary.Added,
			"modified":  r.Summary.Modified,
			"removed":   r.Summary.Removed,
			"unchanged": r.Summary.Unchanged,
			"perType":   perType,
		},
		"changes": changes,
	}
	return marshalEnvelope("sophosfw.v1.drift", payload)
}

// DriftHumanText writes the default human-readable drift output:
// a per-type summary table followed by per-record diff / body / name
// sections. Per-type rows are alphabetised by tag and per-record
// sections by (Type, Name, Change) for stable output across runs.
//
// "modified" with an empty Diff (defensive — should not happen in
// practice since the svc layer only classifies a record as modified
// after the diff returned a non-empty result) emits the header lines
// only and skips the diff body.
func DriftHumanText(w io.Writer, r *svc.DriftResult) error {
	if _, err := fmt.Fprintf(w, "Profile: %s  Snapshot: %s  Now: %s\n\n",
		r.Profile,
		r.SnapshotCreatedAt.UTC().Format(time.RFC3339),
		r.CheckedAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "Type\tAdded\tModified\tRemoved\tUnchanged"); err != nil {
		return err
	}

	tags := make([]string, 0, len(r.Summary.PerType))
	for tag := range r.Summary.PerType {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		s := r.Summary.PerType[tag]
		if _, err := fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n",
			tag, s.Added, s.Modified, s.Removed, s.Unchanged); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(w, "\nTotal: %d added, %d modified, %d removed (unchanged: %d)\n\n",
		r.Summary.Added, r.Summary.Modified, r.Summary.Removed, r.Summary.Unchanged); err != nil {
		return err
	}

	for _, c := range sortDriftChanges(r.Changes) {
		switch c.Change {
		case "modified":
			if _, err := fmt.Fprintf(w, "--- Modified: %s/%s.yaml\n", c.Type, c.Name); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "+++ Modified: %s/%s (live)\n", c.Type, c.Name); err != nil {
				return err
			}
			if c.Diff != "" {
				if _, err := fmt.Fprintln(w, c.Diff); err != nil {
					return err
				}
			}
		case "added":
			if _, err := fmt.Fprintf(w, "+++ Added: %s/%s\n", c.Type, c.Name); err != nil {
				return err
			}
			yamlBytes, err := yaml.Marshal(c.Body)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w, string(yamlBytes)); err != nil {
				return err
			}
		case "removed":
			if _, err := fmt.Fprintf(w, "--- Removed: %s/%s\n", c.Type, c.Name); err != nil {
				return err
			}
		}
	}
	return nil
}
