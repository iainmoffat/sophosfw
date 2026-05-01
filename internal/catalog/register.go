package catalog

import _ "embed"

//go:embed objects.yaml
var defaultYAML []byte

// NewDefault loads the embedded production catalog and registers the
// typed parsers shipped in this package (IPHost, Services).
func NewDefault() (*Catalog, error) {
	c, err := loadFromBytes(defaultYAML)
	if err != nil {
		return nil, err
	}
	c.RegisterParser("iphost", IPHostParser)
	c.RegisterParser("service", ServicesParser)
	c.RegisterParser("fqdnhost", FQDNHostParser)
	c.RegisterParser("machost", MACHostParser)
	return c, nil
}
