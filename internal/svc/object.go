package svc

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// ErrCatalogUnknownTag is returned when a given tag/alias is not in the catalog.
var ErrCatalogUnknownTag = errors.New("catalog: unknown tag")

// ObjectList is the render-friendly result of a list operation.
type ObjectList struct {
	Profile string
	Tag     string
	Filter  *sophos.FilterClause
	Count   int
	Items   []any // typed if catalog has parser, else map[string]any
}

// Object is the render-friendly result of a single-record get.
type Object struct {
	Profile string
	Tag     string
	Name    string
	Typed   bool
	Data    any
}

// ObjectUsage is the render-friendly result of a usage query.
type ObjectUsage struct {
	Profile  string
	Tag      string
	UsageTag string
	Name     string
	Records  []map[string]any
}

// ObjectSvc serves `object list/get/usage/schema`.
type ObjectSvc struct {
	Config    *config.Config
	Creds     creds.Store
	Catalog   *catalog.Catalog
	NewClient ClientFactory
}

func (s *ObjectSvc) clientFor(profileName string) (Client, *catalog.Catalog, string, error) {
	p, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, nil, "", err
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return nil, nil, "", err
	}
	return s.NewClient(p, c), s.Catalog, name, nil
}

// List returns all records of the given XML tag, optionally filtered.
func (s *ObjectSvc) List(ctx context.Context, profileName, tagOrAlias string, filter *sophos.FilterClause) (*ObjectList, error) {
	cl, cat, name, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	entry, ok := cat.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}

	if filter != nil {
		if err := filter.ValidateForGet(); err != nil {
			return nil, err
		}
	}

	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{
		XMLTag: entry.Tag,
		Filter: filter,
	}}})
	if err != nil {
		return nil, err
	}

	out := &ObjectList{Profile: name, Tag: entry.Tag, Filter: filter}
	for _, raw := range resp.Body[entry.Tag] {
		v, err := cat.Parse(entry.Tag, raw)
		if err != nil {
			return nil, err
		}
		// Sophos sometimes returns a stub record (Name="" with all
		// fields blank) when the result set is empty. Drop it so
		// callers see a real Count.
		if isEmptyStubRecord(v) {
			continue
		}
		out.Items = append(out.Items, v)
	}
	out.Count = len(out.Items)
	return out, nil
}

// isEmptyStubRecord returns true if v is a record whose Name field is
// empty. Works for both typed structs (via reflection) and untyped
// map[string]any values. Records without a Name field are never
// considered stubs.
func isEmptyStubRecord(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		s, _ := x["Name"].(string)
		return s == ""
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Ptr {
			rv = rv.Elem()
		}
		if rv.Kind() != reflect.Struct {
			return false
		}
		f := rv.FieldByName("Name")
		if !f.IsValid() || f.Kind() != reflect.String {
			return false
		}
		return f.String() == ""
	}
}

// Get fetches a single record by name.
func (s *ObjectSvc) Get(ctx context.Context, profileName, tagOrAlias, name string) (*Object, error) {
	cl, cat, profName, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	entry, ok := cat.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}

	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{
		XMLTag: entry.Tag,
		Name:   name,
	}}})
	if err != nil {
		return nil, err
	}
	records := resp.Body[entry.Tag]
	if len(records) == 0 {
		return nil, fmt.Errorf("%s %q: %w", entry.Tag, name, sophos.ErrNotFound)
	}
	v, err := cat.Parse(entry.Tag, records[0])
	if err != nil {
		return nil, err
	}
	// Phase 12: inject _diffHash for catalog-mutable types so update/delete
	// callers can use it as expectedDiffHash without a separate query.
	// We coerce typed values to map[string]any here so the field round-trips
	// cleanly through the object envelope; typed downstream services
	// (HostIPSvc, ServiceSvc) re-marshal the map back into their native
	// struct.
	if entry.Mutable {
		m, mErr := toMap(v)
		if mErr != nil {
			return nil, mErr
		}
		if m != nil {
			if hash, hashErr := DiffHash(m); hashErr == nil {
				m["_diffHash"] = hash
			}
			v = m
		}
	}
	return &Object{
		Profile: profName,
		Tag:     entry.Tag,
		Name:    name,
		Typed:   entry.TypedParser != "",
		Data:    v,
	}, nil
}

// Usage runs the *Statistics query for the catalog entry.
func (s *ObjectSvc) Usage(ctx context.Context, profileName, tagOrAlias, name string) (*ObjectUsage, error) {
	cl, cat, profName, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	entry, ok := cat.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}
	if entry.UsageTag == "" {
		return nil, fmt.Errorf("object %q does not support usage queries (no Statistics tag)", entry.Tag)
	}

	var filter *sophos.FilterClause
	if name != "" {
		filter = &sophos.FilterClause{Field: "Name", Criteria: "=", Value: name}
		if err := filter.ValidateForStatistics(); err != nil {
			return nil, err
		}
	}

	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.StatisticsOp{
		XMLTag: entry.UsageTag,
		Filter: filter,
	}}})
	if err != nil {
		return nil, err
	}

	out := &ObjectUsage{Profile: profName, Tag: entry.Tag, UsageTag: entry.UsageTag, Name: name}
	for _, raw := range resp.Body[entry.UsageTag] {
		var m map[string]any
		if err := jsonUnmarshal(raw, &m); err != nil {
			return nil, err
		}
		out.Records = append(out.Records, m)
	}
	return out, nil
}

// Schema returns the catalog entry for tag or alias.
func (s *ObjectSvc) Schema(tagOrAlias string) (*catalog.Entry, error) {
	e, ok := s.Catalog.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}
	return e, nil
}

// Local helper to keep the encoding/json import alongside the call site.
func jsonUnmarshal(raw []byte, v any) error {
	return jsonUnmarshalImpl(raw, v)
}

// decodeObjectDataInto decodes an Object.Data value (which may be a typed
// catalog struct OR a map[string]any with an injected `_diffHash` key) into
// the supplied destination via JSON round-trip. Used by typed downstream
// services (HostIPSvc, ServiceSvc) to recover the catalog struct after
// ObjectSvc.Get has converted to a map for diff-hash injection.
func decodeObjectDataInto(data any, dst any) error {
	if m, ok := data.(map[string]any); ok {
		// Avoid leaking the synthetic field into the typed struct.
		if _, has := m["_diffHash"]; has {
			cleaned := make(map[string]any, len(m))
			for k, v := range m {
				if k == "_diffHash" {
					continue
				}
				cleaned[k] = v
			}
			data = cleaned
		}
	}
	raw, err := jsonMarshalImpl(data)
	if err != nil {
		return err
	}
	return jsonUnmarshalImpl(raw, dst)
}
