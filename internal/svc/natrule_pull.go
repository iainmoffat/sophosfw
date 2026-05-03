package svc

import (
	"context"
	"fmt"
	"time"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// NATRulePullResult is what Pull returns.
type NATRulePullResult struct {
	Profile      string
	Rule         string
	DraftPath    string
	SnapshotPath string
	DiffHash     string
	References   []ReferenceSummary
}

// Pull fetches the live NATRule, writes a snapshot + draft to disk under
// s.BaseDir, rotates old snapshots, audits, and returns paths + hash +
// references.
func (s *NATRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*NATRulePullResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	body, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("NAT rule %q: %w", ruleName, sophos.ErrNotFound)
	}

	hash, err := DiffHash(body)
	if err != nil {
		return nil, err
	}

	yamlBytes, err := marshalCanonicalYAML(body)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	snapPath, err := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
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

	if err := draft.WriteDraft(draftPath, d); err != nil {
		return nil, err
	}
	if err := draft.WriteDraft(snapPath, d); err != nil {
		return nil, err
	}
	if err := draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10); err != nil {
		return nil, err
	}

	if s.Audit != nil {
		_ = s.Audit.Write(AuditEntry{
			Profile:    name,
			Operation:  "nat_rule_pull",
			ObjectType: "NATRule",
			ObjectName: ruleName,
			Result:     "ok",
		})
	}

	return &NATRulePullResult{
		Profile:      name,
		Rule:         ruleName,
		DraftPath:    draftPath,
		SnapshotPath: snapPath,
		DiffHash:     hash,
		References:   extractNATReferences(body),
	}, nil
}

func (s *NATRuleSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// extractNATReferences walks a NATRule body for known reference-bearing
// fields and returns a deduplicated summary. Sentinel values "Original"
// (translation no-op) and "None" (no link) are filtered.
func extractNATReferences(body map[string]any) []ReferenceSummary {
	ipHosts := map[string]struct{}{}
	services := map[string]struct{}{}
	rules := map[string]struct{}{}
	ifaces := map[string]struct{}{}

	collectNames(body, "OriginalSourceNetworks", "Network", ipHosts)
	collectNames(body, "OriginalDestinationNetworks", "Network", ipHosts)
	collectNames(body, "OriginalServices", "Service", services)
	collectNames(body, "InboundInterfaces", "Interface", ifaces)

	addStringIfNot := func(sink map[string]struct{}, key, sentinel string) {
		v, ok := body[key].(string)
		if !ok || v == "" || v == sentinel {
			return
		}
		sink[v] = struct{}{}
	}

	addStringIfNot(ipHosts, "TranslatedSource", "Original")
	addStringIfNot(ipHosts, "TranslatedDestination", "Original")
	addStringIfNot(services, "TranslatedService", "Original")
	addStringIfNot(rules, "LinkedFirewallrule", "None")

	out := []ReferenceSummary{}
	if len(ipHosts) > 0 {
		out = append(out, ReferenceSummary{Type: "IPHost", Names: sortedKeys(ipHosts)})
	}
	if len(services) > 0 {
		out = append(out, ReferenceSummary{Type: "Service", Names: sortedKeys(services)})
	}
	if len(rules) > 0 {
		out = append(out, ReferenceSummary{Type: "FirewallRule", Names: sortedKeys(rules)})
	}
	if len(ifaces) > 0 {
		out = append(out, ReferenceSummary{Type: "Interface", Names: sortedKeys(ifaces)})
	}
	return out
}
