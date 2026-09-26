package render

import (
	"encoding/json"
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ScheduleListEnvelope renders the schedule list payload.
func ScheduleListEnvelope(l *svc.ObjectList) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.scheduleList", map[string]any{
		"profile": l.Profile,
		"count":   l.Count,
		"items":   l.Items,
	})
}

// ScheduleShowEnvelope renders a schedule record and optional references.
func ScheduleShowEnvelope(s *svc.ScheduleShow) ([]byte, error) {
	data, err := scheduleData(s.Object.Data)
	if err != nil {
		return nil, err
	}
	hash, err := svc.DiffHash(data)
	if err != nil {
		return nil, err
	}
	data["_diffHash"] = hash
	payload := map[string]any{"profile": s.Object.Profile, "name": s.Object.Name, "data": data}
	if s.References != nil {
		payload["references"] = s.References.Refs
		if len(s.References.Errors) > 0 {
			payload["referenceErrors"] = s.References.Errors
		}
		if len(s.References.Skipped) > 0 {
			payload["referenceSkipped"] = s.References.Skipped
		}
	}
	return marshalEnvelope("sophosfw.v1.schedule", payload)
}

func scheduleData(value any) (map[string]any, error) {
	if m, ok := value.(map[string]any); ok {
		out := make(map[string]any, len(m)+1)
		for k, v := range m {
			out[k] = v
		}
		return out, nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("schedule data must be an object")
	}
	return m, nil
}
