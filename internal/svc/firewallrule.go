package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// FirewallRuleList is the render-friendly result of a firewall rule list.
// Items are untyped maps; FirewallRule has no typed parser in Phase 3
// because the rule shape is non-trivial and Phase 6 will define it
// alongside mutating workflows.
type FirewallRuleList struct {
	Profile string
	Filter  *sophos.FilterClause
	Count   int
	Items   []map[string]any
}

// FirewallRuleSvc serves the typed `firewall rule` first-class command
// surface. It calls Inner.List/Get and converts each `any` item to
// `map[string]any` for caller convenience.
type FirewallRuleSvc struct {
	Inner   *ObjectSvc
	Audit   *AuditLog
	BaseDir string
	Now     func() time.Time // injectable for tests; defaults to time.Now()
}

// List returns FirewallRule records as plain maps.
func (s *FirewallRuleSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*FirewallRuleList, error) {
	inner, err := s.Inner.List(ctx, profileName, "FirewallRule", filter)
	if err != nil {
		return nil, err
	}
	out := &FirewallRuleList{Profile: inner.Profile, Filter: inner.Filter}
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

// Get fetches one FirewallRule by name.
func (s *FirewallRuleSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
	inner, err := s.Inner.Get(ctx, profileName, "FirewallRule", name)
	if err != nil {
		return nil, err
	}
	return toMap(inner.Data)
}

// toMap converts a parser output to map[string]any. For generic catalog
// entries the parser yields map[string]any directly; the round-trip via
// JSON is a defensive fallback for any future typed entry that gets
// asked for through a generic-rule lens.
func toMap(item any) (map[string]any, error) {
	if m, ok := item.(map[string]any); ok {
		return m, nil
	}
	b, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("firewallrule: marshal: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("firewallrule: unmarshal: %w", err)
	}
	return m, nil
}
