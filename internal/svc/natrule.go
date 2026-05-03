package svc

import (
	"context"
	"time"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// NATRuleList is the render-friendly result of a NAT rule list. Items are
// untyped maps; NATRule has no typed parser in Phase 3.
type NATRuleList struct {
	Profile string
	Filter  *sophos.FilterClause
	Count   int
	Items   []map[string]any
}

// NATRuleSvc serves the typed `nat rule` first-class command surface.
// Audit, BaseDir, and Now are required for Pull (Phase 8).
type NATRuleSvc struct {
	Inner   *ObjectSvc
	Audit   *AuditLog
	BaseDir string
	Now     func() time.Time // injectable for tests; defaults to time.Now()
}

// List returns NATRule records as plain maps.
func (s *NATRuleSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*NATRuleList, error) {
	inner, err := s.Inner.List(ctx, profileName, "NATRule", filter)
	if err != nil {
		return nil, err
	}
	out := &NATRuleList{Profile: inner.Profile, Filter: inner.Filter}
	for _, item := range inner.Items {
		m, err := toMap(item)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, m)
	}
	out.Count = len(out.Items)
	if out.Items == nil {
		out.Items = []map[string]any{}
	}
	return out, nil
}

// Get fetches one NATRule by name.
func (s *NATRuleSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
	inner, err := s.Inner.Get(ctx, profileName, "NATRule", name)
	if err != nil {
		return nil, err
	}
	return toMap(inner.Data)
}
