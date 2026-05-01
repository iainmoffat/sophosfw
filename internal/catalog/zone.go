package catalog

import "encoding/json"

// Zone is the typed view of a Sophos Zone record (LAN, WAN, DMZ, custom).
type Zone struct {
	Name        string `json:"Name"`
	Type        string `json:"Type,omitempty"`
	Description string `json:"Description,omitempty"`
}

// ZoneParser is the typed-parser callback for the "zone" identifier in
// objects.yaml.
func ZoneParser(raw json.RawMessage) (any, error) {
	var v Zone
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
