// Package render fanout.go: envelope + human-text renderer for the
// multi-profile fan-out result emitted by svc.Run.
package render

import (
	"fmt"
	"io"
	"time"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// FanoutEnvelope produces the sophosfw.v1.fanoutResult JSON envelope.
// Per-profile entries omit the "error" key when Status == "ok"/"skipped"
// and only include the preflightResult / applyResult slots that actually
// ran for that profile.
func FanoutEnvelope(r *svc.FanoutResult) ([]byte, error) {
	results := make([]map[string]any, 0, len(r.Results))
	for _, p := range r.Results {
		m := map[string]any{
			"profile":    p.Profile,
			"phase":      p.Phase,
			"status":     p.Status,
			"durationMs": p.DurationMs,
			"startedAt":  p.StartedAt.UTC().Format(time.RFC3339Nano),
		}
		if p.Error != "" {
			m["error"] = p.Error
		}
		if p.PreflightResult != nil {
			m["preflightResult"] = p.PreflightResult
		}
		if p.ApplyResult != nil {
			m["applyResult"] = p.ApplyResult
		}
		results = append(results, m)
	}
	payload := map[string]any{
		"operation":   r.Operation,
		"profiles":    r.Profiles,
		"mutating":    r.Mutating,
		"preflightOK": r.PreflightOK,
		"aborted":     r.Aborted,
		"startedAt":   r.StartedAt.UTC().Format(time.RFC3339Nano),
		"endedAt":     r.EndedAt.UTC().Format(time.RFC3339Nano),
		"results":     results,
	}
	return marshalEnvelope("sophosfw.v1.fanoutResult", payload)
}

// FanoutHumanText writes the per-profile pre-flight + apply status
// table plus a final summary line (succeeded/failed/skipped counts).
// One line per profile per phase: "OK (Nms)" for ok, "ERR (Nms): msg"
// for error, "skipped" for trailing profiles short-circuited by an
// earlier apply failure.
func FanoutHumanText(w io.Writer, r *svc.FanoutResult) error {
	if _, err := fmt.Fprintf(w, "Operation: %s\n", r.Operation); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Profiles: %d\n\n", len(r.Profiles)); err != nil {
		return err
	}
	var ok, errc, skipped int
	for _, p := range r.Results {
		switch p.Status {
		case "ok":
			ok++
			if _, err := fmt.Fprintf(w, "  [%s] %s OK (%dms)\n", p.Profile, p.Phase, p.DurationMs); err != nil {
				return err
			}
		case "skipped":
			skipped++
			if _, err := fmt.Fprintf(w, "  [%s] skipped\n", p.Profile); err != nil {
				return err
			}
		case "error":
			errc++
			if _, err := fmt.Fprintf(w, "  [%s] %s ERR (%dms): %s\n", p.Profile, p.Phase, p.DurationMs, p.Error); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w, "\n%d succeeded, %d failed, %d skipped.\n", ok, errc, skipped); err != nil {
		return err
	}
	return nil
}
