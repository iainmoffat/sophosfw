// Package render owns user-facing output: JSON envelopes and lipgloss tables.
package render

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON wraps payload in a {schema, ...payload} envelope and pretty-prints
// it with a trailing newline. Use this for every successful JSON output.
func WriteJSON(w io.Writer, schema string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("render: marshal payload: %w", err)
	}

	// Merge {schema: ...} into the payload object. We re-encode through a map
	// so callers can pass either a struct (json-tagged) or map[string]any.
	var merged map[string]any
	if err := json.Unmarshal(b, &merged); err != nil {
		// Payload wasn't a JSON object — wrap it under "data".
		merged = map[string]any{"data": json.RawMessage(b)}
	}
	merged["schema"] = schema

	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("render: marshal envelope: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// WriteError writes a sophosfw.v1.error envelope.
func WriteError(w io.Writer, kind, message, profile string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	return WriteJSON(w, "sophosfw.v1.error", map[string]any{
		"kind":    kind,
		"message": message,
		"profile": profile,
		"details": details,
	})
}
