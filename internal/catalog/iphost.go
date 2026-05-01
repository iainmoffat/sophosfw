package catalog

import "encoding/json"

// IPHost is the typed view of a Sophos IPHost record.
type IPHost struct {
	Name           string `json:"Name"`
	IPFamily       string `json:"IPFamily"`
	HostType       string `json:"HostType"`
	IPAddress      string `json:"IPAddress,omitempty"`
	Subnet         string `json:"Subnet,omitempty"`
	StartIPAddress string `json:"StartIPAddress,omitempty"`
	EndIPAddress   string `json:"EndIPAddress,omitempty"`
	IPAddressList  string `json:"IPAddressList,omitempty"`
}

// IPHostParser is the typed-parser callback for the "iphost" identifier in
// objects.yaml.
func IPHostParser(raw json.RawMessage) (any, error) {
	var h IPHost
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return h, nil
}
