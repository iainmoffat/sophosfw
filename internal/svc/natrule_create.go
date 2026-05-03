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

// natRuleTemplate is the minimal-valid skeleton emitted by `nat rule
// new` when no --from is supplied. Defaults to all "Original"
// translation sentinels (no-op rule).
const natRuleTemplate = `Name: __NAME__
Status: Enable
IPFamily: IPv4
Position: Bottom
OriginalSourceNetworks:
  Network: Any
OriginalDestinationNetworks:
  Network: Any
OriginalServices:
  Service: Any
TranslatedSource: Original
TranslatedDestination: Original
TranslatedService: Original
`

// NATRuleNewResult mirrors NATRulePullResult — same fields, reused
// render envelope. SnapshotPath and DiffHash are empty on a fresh new.
type NATRuleNewResult = NATRulePullResult

// New writes a new draft for ruleName at drafts/nat/<slug>.yaml. If
// fromRule is non-empty, the existing rule's body is pulled and used
// as the starting template; otherwise natRuleTemplate is used.
//
// Errors:
//   - draft already exists at the resolved path → ErrInvalidRequest.
//   - --from rule doesn't exist → ErrNotFound.
//
// Audit: writes "nat_rule_new" entry on success.
func (s *NATRuleSvc) New(ctx context.Context, profileName, ruleName, fromRule string) (out *NATRuleNewResult, err error) {
	_, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_new",
		ObjectType: "NATRule",
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
		// Parse the template as-is; overwrite Name after unmarshal so
		// special chars in ruleName are escaped by yaml.Marshal on write.
		if perr := yaml.Unmarshal([]byte(natRuleTemplate), &bodyMap); perr != nil {
			return nil, fmt.Errorf("template parse: %w", perr)
		}
		bodyMap["Name"] = ruleName
	} else {
		live, perr := s.Get(ctx, profileName, fromRule)
		if perr != nil {
			return nil, perr
		}
		if live == nil {
			return nil, fmt.Errorf("NAT rule %q: %w", fromRule, sophos.ErrNotFound)
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
	draftPath, perr := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if perr != nil {
		return nil, perr
	}
	if _, statErr := os.Stat(draftPath); statErr == nil {
		return nil, fmt.Errorf("%w: draft already exists at %s; delete it first or use a different name", sophos.ErrInvalidRequest, draftPath)
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	// 3. Build and write the draft (no snapshot — no live state yet).
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

	return &NATRuleNewResult{
		Profile:    name,
		Rule:       ruleName,
		DraftPath:  draftPath,
		References: extractNATReferences(bodyMap),
	}, nil
}

// CreateInline creates a new NATRule from an in-memory body. See
// FirewallRuleSvc.CreateInline for shape; this is the NAT mirror.
// Audit op: nat_rule_create.
func (s *NATRuleSvc) CreateInline(ctx context.Context, profileName, ruleName string, body map[string]any, dryRun bool) (out *NATRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_create",
		ObjectType: "NATRule",
		ObjectName: ruleName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	for _, k := range requiredNATRuleFields {
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

	catEntry, ok := s.Inner.Catalog.Resolve("NATRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: NATRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	inner, perr := marshalNATRule(body)
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
		return &NATRulePushResult{
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
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
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
				_ = draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10)
			}
		}
	}

	return &NATRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "create",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}
