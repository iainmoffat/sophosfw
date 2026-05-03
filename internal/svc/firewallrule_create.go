package svc

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// firewallRuleTemplate is the structurally-valid skeleton emitted by
// `new` when no --from is supplied. Defaults are deliberately
// fail-safe: Status=Disable so the rule is inert until the user
// reviews and re-enables; Action=Drop so an enabled-but-misconfigured
// rule denies rather than allows.
//
// NOTE: this template is intentionally minimal. Sophos rejects rules
// that lack real SourceNetworks/DestinationNetworks references with
// "Operation could not be performed on Entity" — the user is expected
// to edit the draft and add references that exist on their firewall
// before pushing. For most users `firewall rule new <name> --from
// <existing-rule>` is the more practical starting point.
const firewallRuleTemplate = `Name: __NAME__
Description: ""
Status: Disable
IPFamily: IPv4
PolicyType: Network
Position: Bottom
NetworkPolicy:
  Action: Drop
  LogTraffic: Enable
  Schedule: All The Time
  SkipLocalDestined: Disable
`

// FirewallRuleNewResult mirrors FirewallRulePullResult — same fields,
// reused render envelope. SnapshotPath and DiffHash are empty on a
// fresh new.
type FirewallRuleNewResult = FirewallRulePullResult

// New writes a new draft for ruleName at drafts/firewall/<slug>.yaml.
// If fromRule is non-empty, the existing rule's body is pulled and
// used as the starting template; otherwise firewallRuleTemplate is
// used. Errors:
//   - draft already exists at the resolved path → ErrInvalidRequest.
//   - --from rule doesn't exist → ErrNotFound.
//
// Audit: writes "firewall_rule_new" entry on success.
func (s *FirewallRuleSvc) New(ctx context.Context, profileName, ruleName, fromRule string) (out *FirewallRuleNewResult, err error) {
	_, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "firewall_rule_new",
		ObjectType: "FirewallRule",
		ObjectName: ruleName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	// 1. Compose body.
	var bodyMap map[string]any
	if fromRule == "" {
		if perr := yaml.Unmarshal([]byte(firewallRuleTemplate), &bodyMap); perr != nil {
			return nil, fmt.Errorf("template parse: %w", perr)
		}
		// Overwrite the placeholder Name with the actual rule name. yaml.Marshal
		// will escape special chars (newlines, colons, quotes) safely.
		bodyMap["Name"] = ruleName
	} else {
		live, perr := s.Get(ctx, profileName, fromRule)
		if perr != nil {
			return nil, perr
		}
		if live == nil {
			return nil, fmt.Errorf("firewall rule %q: %w", fromRule, sophos.ErrNotFound)
		}
		// Shallow copy to avoid mutating the map returned by Get.
		bodyMap = make(map[string]any, len(live))
		for k, v := range live {
			bodyMap[k] = v
		}
		bodyMap["Name"] = ruleName
		delete(bodyMap, "After")
		delete(bodyMap, "Before")
	}

	yamlBytes, perr := marshalCanonicalYAML(bodyMap)
	if perr != nil {
		return nil, perr
	}

	// 2. Resolve draft path; reject if file exists.
	draftPath, perr := draft.DraftPath(s.BaseDir, name, "firewall", ruleName)
	if perr != nil {
		return nil, perr
	}
	if _, statErr := os.Stat(draftPath); statErr == nil {
		return nil, fmt.Errorf("%w: draft already exists at %s; delete it first or use a different name", sophos.ErrInvalidRequest, draftPath)
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	// 3. Build and write the draft (no snapshot — there's no live state yet).
	now := s.now()
	d := &draft.Draft{
		Profile:   name,
		Rule:      ruleName,
		Operation: "create",
		PulledAt:  now,
		DiffHash:  "",
		Body:      yamlBytes,
	}
	if perr := draft.WriteDraft(draftPath, d); perr != nil {
		return nil, perr
	}

	// 4. Audit success.
	entryAudit.Result = "ok"
	if s.Audit != nil {
		_ = s.Audit.Write(entryAudit)
	}

	return &FirewallRuleNewResult{
		Profile:   name,
		Rule:      ruleName,
		DraftPath: draftPath,
		// SnapshotPath: "" — no snapshot yet
		// DiffHash: "" — no live state
		References: extractReferences(bodyMap),
	}, nil
}

// CreateInline creates a new FirewallRule from an in-memory body (no
// draft file). Mirrors `Push` for the create path but skips the draft-
// read step. On apply success, writes the FIRST snapshot under
// snapshots/firewall/<slug>-<utc>.yaml so subsequent cli pull/diff on
// this rule have a starting point.
//
// Errors:
//   - read-only profile → ErrReadOnlyViolation
//   - catalog Mutable=false → ErrInvalidRequest
//   - body fails required-field validation → ErrInvalidRequest
//   - Sophos rejects → propagated
//
// Audit op: firewall_rule_create.
func (s *FirewallRuleSvc) CreateInline(ctx context.Context, profileName, ruleName string, body map[string]any, dryRun bool) (out *FirewallRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "firewall_rule_create",
		ObjectType: "FirewallRule",
		ObjectName: ruleName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	for _, k := range requiredFirewallRuleFields {
		v, ok := body[k]
		if !ok {
			return nil, fmt.Errorf("%w: body missing required field %q", sophos.ErrInvalidRequest, k)
		}
		if str, isStr := v.(string); isStr && str == "" {
			return nil, fmt.Errorf("%w: body field %q is empty", sophos.ErrInvalidRequest, k)
		}
	}

	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("FirewallRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: FirewallRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	inner, perr := marshalFirewallRule(body)
	if perr != nil {
		return nil, perr
	}
	full, perr := sophos.BuildSetEnvelope("add", inner, c.Username, c.Password)
	if perr != nil {
		return nil, perr
	}
	entryAudit.RedactedXML = string(safety.RedactXML(full))

	if dryRun {
		mutating, verbs := safety.IsMutating(full)
		pv := &Preview{
			Profile:        name,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    entryAudit.RedactedXML,
			WouldSendBytes: len(full),
		}
		entryAudit.Result = "ok (dry-run)"
		_ = s.Audit.Write(entryAudit)
		return &FirewallRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "create",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	refetched, _ := s.Get(ctx, profileName, ruleName)
	newHash := ""
	if refetched != nil {
		nh, hashErr := DiffHash(refetched)
		if hashErr == nil {
			newHash = nh
		}
	}
	if refetched != nil && newHash != "" {
		now := s.now()
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "firewall", ruleName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile:   name,
					Rule:      ruleName,
					Operation: "update",
					PulledAt:  now,
					DiffHash:  newHash,
					Body:      yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "firewall", ruleName, 10)
			}
		}
	}

	return &FirewallRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "create",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}
