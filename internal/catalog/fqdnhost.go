package catalog

import "encoding/json"

// FQDNHost is the typed view of a Sophos FQDNHost record.
type FQDNHost struct {
	Name     string `json:"Name"`
	FQDN     string `json:"FQDN"`
	IPFamily string `json:"IPFamily,omitempty"`
}

// FQDNHostParser is the typed-parser callback for the "fqdnhost" identifier
// in objects.yaml.
func FQDNHostParser(raw json.RawMessage) (any, error) {
	var v FQDNHost
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
