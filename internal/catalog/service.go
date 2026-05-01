package catalog

import "encoding/json"

// Service is the typed view of a Sophos Services record. The detail shape
// varies by protocol so we keep the raw fragment alongside the common header.
type Service struct {
	Name       string          `json:"Name"`
	Type       string          `json:"Type"`
	RawDetails json.RawMessage `json:"ServiceDetails,omitempty"`
}

// ServicesParser is the typed-parser callback for the "service" identifier
// in objects.yaml.
func ServicesParser(raw json.RawMessage) (any, error) {
	var s Service
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return s, nil
}
