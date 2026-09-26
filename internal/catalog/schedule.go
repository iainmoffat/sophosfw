package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ScheduleParser is the typed-parser callback for the "schedule"
// identifier in objects.yaml. It returns map[string]any (not a struct) so
// unknown and OneTime fields survive the round trip.
func ScheduleParser(raw json.RawMessage) (any, error) {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("catalog: parse schedule: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("catalog: parse schedule: expected JSON object")
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return nil, fmt.Errorf("catalog: parse schedule: unexpected trailing JSON value")
	} else if err != io.EOF {
		return nil, fmt.Errorf("catalog: parse schedule: %w", err)
	}

	if rawDetails, ok := obj["ScheduleDetails"]; ok && rawDetails != nil {
		if details, ok := rawDetails.(map[string]any); ok {
			if detail, ok := details["ScheduleDetail"].(map[string]any); ok {
				details["ScheduleDetail"] = []any{detail}
			}
		}
	}
	return obj, nil
}
