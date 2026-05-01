package catalog

import "encoding/json"

// MACHost is the typed view of a Sophos MACHost record. Sophos allows
// either a single MACAddress or a list (MACAddressList) per record.
type MACHost struct {
	Name           string   `json:"Name"`
	Type           string   `json:"Type,omitempty"`
	MACAddress     string   `json:"MACAddress,omitempty"`
	MACAddressList []string `json:"MACAddressList,omitempty"`
}

// MACHostParser is the typed-parser callback for the "machost" identifier
// in objects.yaml.
func MACHostParser(raw json.RawMessage) (any, error) {
	var v MACHost
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
