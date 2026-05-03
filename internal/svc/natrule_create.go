package svc

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
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
