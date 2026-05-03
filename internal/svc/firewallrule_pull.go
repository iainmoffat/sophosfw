package svc

import (
	"context"
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// FirewallRulePullResult is what Pull returns to the caller.
type FirewallRulePullResult struct {
	Profile      string
	Rule         string
	DraftPath    string
	SnapshotPath string
	DiffHash     string
	References   []ReferenceSummary
}

// ReferenceSummary groups names of objects referenced by a rule.
type ReferenceSummary struct {
	Type  string
	Names []string
}

// Pull fetches the live FirewallRule, writes a snapshot + draft to
// disk under s.BaseDir, rotates old snapshots, and returns paths +
// hash + references.
func (s *FirewallRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*FirewallRulePullResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	body, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("firewall rule %q: %w", ruleName, sophos.ErrNotFound)
	}

	hash, err := DiffHash(body)
	if err != nil {
		return nil, err
	}

	yamlBytes, err := marshalCanonicalYAML(body)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	snapPath, err := draft.SnapshotPath(s.BaseDir, name, ruleName, now)
	if err != nil {
		return nil, err
	}

	d := &draft.Draft{
		Profile:  name,
		Rule:     ruleName,
		PulledAt: now,
		DiffHash: hash,
		Body:     yamlBytes,
	}

	if err := draft.WriteDraft(snapPath, d); err != nil {
		return nil, err
	}
	if err := draft.WriteDraft(draftPath, d); err != nil {
		return nil, err
	}

	if err := draft.RotateSnapshots(s.BaseDir, name, ruleName, 10); err != nil {
		return nil, err
	}

	if s.Audit != nil {
		_ = s.Audit.Write(AuditEntry{
			Profile:    name,
			Operation:  "firewall_rule_pull",
			ObjectType: "FirewallRule",
			ObjectName: ruleName,
			Result:     "ok",
		})
	}

	return &FirewallRulePullResult{
		Profile:      name,
		Rule:         ruleName,
		DraftPath:    draftPath,
		SnapshotPath: snapPath,
		DiffHash:     hash,
		References:   extractReferences(body),
	}, nil
}

func (s *FirewallRuleSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// marshalCanonicalYAML marshals a value to YAML with alphabetically-
// sorted keys at every map level.
func marshalCanonicalYAML(v any) ([]byte, error) {
	node, err := buildSortedYAMLNode(v)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(node)
}

// buildSortedYAMLNode returns a *yaml.Node for v with map keys sorted.
func buildSortedYAMLNode(v any) (*yaml.Node, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		node := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range keys {
			keyN := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
			valN, err := buildSortedYAMLNode(t[k])
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, keyN, valN)
		}
		return node, nil
	case []any:
		node := &yaml.Node{Kind: yaml.SequenceNode}
		for _, item := range t {
			n, err := buildSortedYAMLNode(item)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, n)
		}
		return node, nil
	default:
		n := &yaml.Node{}
		if err := n.Encode(v); err != nil {
			return nil, err
		}
		return n, nil
	}
}

// extractReferences walks a FirewallRule body looking for known
// reference-bearing fields and returns a deduplicated summary.
func extractReferences(body map[string]any) []ReferenceSummary {
	ipHosts := map[string]struct{}{}
	zones := map[string]struct{}{}
	services := map[string]struct{}{}

	if np, ok := body["NetworkPolicy"].(map[string]any); ok {
		collectNames(np, "SourceNetworks", "Network", ipHosts)
		collectNames(np, "DestinationNetworks", "Network", ipHosts)
		collectNames(np, "Services", "Service", services)
		collectNames(np, "SourceZones", "Zone", zones)
		collectNames(np, "DestinationZones", "Zone", zones)
	}

	out := []ReferenceSummary{}
	if len(ipHosts) > 0 {
		out = append(out, ReferenceSummary{Type: "IPHost", Names: sortedKeys(ipHosts)})
	}
	if len(zones) > 0 {
		out = append(out, ReferenceSummary{Type: "Zone", Names: sortedKeys(zones)})
	}
	if len(services) > 0 {
		out = append(out, ReferenceSummary{Type: "Service", Names: sortedKeys(services)})
	}
	return out
}

func collectNames(policy map[string]any, parent, child string, sink map[string]struct{}) {
	pv, ok := policy[parent].(map[string]any)
	if !ok {
		return
	}
	v, ok := pv[child]
	if !ok {
		return
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			sink[t] = struct{}{}
		}
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				sink[s] = struct{}{}
			}
		}
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
