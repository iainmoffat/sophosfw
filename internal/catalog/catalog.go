// Package catalog is the hybrid metadata + typed-parser registry for Sophos
// XML tags. The bulk of the catalog is YAML; first-class objects also have
// Go-typed unmarshallers registered programmatically.
package catalog

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Entry describes a single Sophos XML tag.
type Entry struct {
	Tag         string   `yaml:"tag"`
	Aliases     []string `yaml:"aliases"`
	Description string   `yaml:"description"`
	Columns     []string `yaml:"columns"`
	Filterable  []string `yaml:"filterable"`
	UsageTag    string   `yaml:"usageTag"`
	TypedParser string   `yaml:"typedParser"`
}

// Catalog holds all known XML tags.
type Catalog struct {
	entries []Entry
	byTag   map[string]*Entry
	byAlias map[string]*Entry
	parsers map[string]TypedParser
}

// TypedParser converts a single record's JSON fragment (produced by the
// generic response parser) into a typed Go struct.
type TypedParser func(json.RawMessage) (any, error)

type yamlDoc struct {
	Objects []Entry `yaml:"objects"`
}

// Load reads the catalog YAML from path.
func Load(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: read %s: %w", path, err)
	}
	return loadFromBytes(b)
}

func loadFromBytes(b []byte) (*Catalog, error) {
	var doc yamlDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("catalog: parse: %w", err)
	}
	c := &Catalog{
		entries: doc.Objects,
		byTag:   map[string]*Entry{},
		byAlias: map[string]*Entry{},
		parsers: map[string]TypedParser{},
	}
	for i := range c.entries {
		e := &c.entries[i]
		if _, dup := c.byTag[e.Tag]; dup {
			return nil, fmt.Errorf("catalog: duplicate tag %q", e.Tag)
		}
		c.byTag[e.Tag] = e
		for _, a := range e.Aliases {
			if _, dup := c.byAlias[a]; dup {
				return nil, fmt.Errorf("catalog: duplicate alias %q", a)
			}
			c.byAlias[a] = e
		}
	}
	return c, nil
}

// Tags returns all canonical tag names.
func (c *Catalog) Tags() []string {
	out := make([]string, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.Tag)
	}
	return out
}

// Resolve returns the entry for either a canonical tag or an alias.
func (c *Catalog) Resolve(nameOrAlias string) (*Entry, bool) {
	if e, ok := c.byTag[nameOrAlias]; ok {
		return e, true
	}
	if e, ok := c.byAlias[nameOrAlias]; ok {
		return e, true
	}
	return nil, false
}

// RegisterParser associates a typed parser with the typedParser identifier in
// the catalog YAML (e.g. "iphost"). Idiomatic call site: in package init().
func (c *Catalog) RegisterParser(name string, p TypedParser) {
	c.parsers[name] = p
}

// Parse dispatches a record to its typed parser if registered, else returns
// the raw fragment unmarshalled as map[string]any.
func (c *Catalog) Parse(tag string, raw json.RawMessage) (any, error) {
	e, ok := c.byTag[tag]
	if !ok {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	if e.TypedParser == "" {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	parser, ok := c.parsers[e.TypedParser]
	if !ok {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	return parser(raw)
}
