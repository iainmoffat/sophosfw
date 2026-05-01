package svc

import (
	"context"
	"errors"
	"fmt"

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
		out.Items = append(out.Items, v)
	}
	out.Count = len(out.Items)
	return out, nil
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
