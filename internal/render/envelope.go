// Package render envelope.go: construct sophosfw.v1.* JSON envelopes as
// byte slices. The cli layer writes these directly; the mcp layer wraps
// them as TextContent. Keeping construction in one place ensures that
// changing an envelope shape changes both surfaces in lockstep.
package render

import (
	"bytes"
	"encoding/json"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// AuthStatusEnvelope renders sophosfw.v1.authStatus.
func AuthStatusEnvelope(st svc.AuthStatus) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.authStatus", map[string]any{
		"profile":            st.Profile,
		"url":                st.URL,
		"loggedIn":           st.LoggedIn,
		"credentialsBackend": st.CredentialsBackend,
	})
}

// ConnectionTestEnvelope renders sophosfw.v1.connectionTest.
func ConnectionTestEnvelope(r svc.ConnectionResult) ([]byte, error) {
	payload := map[string]any{
		"profile":      r.Profile,
		"ok":           r.OK,
		"latencyMs":    r.LatencyMs,
		"apiReachable": r.APIReachable,
		"authOk":       r.AuthOK,
	}
	if r.Error != "" {
		payload["error"] = r.Error
	}
	return marshalEnvelope("sophosfw.v1.connectionTest", payload)
}

// ProfileListEnvelope renders sophosfw.v1.profileList.
func ProfileListEnvelope(currentProfile string, list []svc.ProfileInfo) ([]byte, error) {
	profiles := make([]map[string]any, 0, len(list))
	for _, p := range list {
		profiles = append(profiles, map[string]any{
			"name":     p.Name,
			"url":      p.URL,
			"readOnly": p.ReadOnly,
			"current":  p.Current,
		})
	}
	return marshalEnvelope("sophosfw.v1.profileList", map[string]any{
		"current":  currentProfile,
		"profiles": profiles,
	})
}

// ObjectListEnvelope renders sophosfw.v1.objectList.
func ObjectListEnvelope(out *svc.ObjectList) ([]byte, error) {
	payload := map[string]any{
		"profile": out.Profile,
		"xmlTag":  out.Tag,
		"count":   out.Count,
		"items":   out.Items,
	}
	if out.Filter != nil {
		payload["filter"] = map[string]any{
			"field":    out.Filter.Field,
			"criteria": out.Filter.Criteria,
			"value":    out.Filter.Value,
		}
	}
	return marshalEnvelope("sophosfw.v1.objectList", payload)
}

// ObjectEnvelope renders sophosfw.v1.object.
func ObjectEnvelope(obj *svc.Object) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.object", map[string]any{
		"profile": obj.Profile,
		"xmlTag":  obj.Tag,
		"name":    obj.Name,
		"typed":   obj.Typed,
		"data":    obj.Data,
	})
}

// ObjectUsageEnvelope renders sophosfw.v1.objectUsage.
func ObjectUsageEnvelope(u *svc.ObjectUsage) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.objectUsage", map[string]any{
		"profile":  u.Profile,
		"xmlTag":   u.Tag,
		"usageTag": u.UsageTag,
		"name":     u.Name,
		"records":  u.Records,
	})
}

// ObjectSchemaEnvelope renders sophosfw.v1.objectSchema.
func ObjectSchemaEnvelope(e *catalog.Entry) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.objectSchema", map[string]any{
		"tag":         e.Tag,
		"aliases":     e.Aliases,
		"description": e.Description,
		"columns":     e.Columns,
		"filterable":  e.Filterable,
		"usageTag":    e.UsageTag,
		"typedParser": e.TypedParser,
		"mutable":     e.Mutable,
	})
}

// RawResponseEnvelope renders sophosfw.v1.rawResponse. Body is the
// re-encoded XML fragment map keyed by tag.
func RawResponseEnvelope(r *svc.RawResponse) ([]byte, error) {
	body := map[string]any{}
	for tag, recs := range r.Body {
		items := make([]string, 0, len(recs))
		for _, rec := range recs {
			items = append(items, string(rec))
		}
		body[tag] = items
	}
	return marshalEnvelope("sophosfw.v1.rawResponse", map[string]any{
		"profile": r.Profile,
		"xmlTag":  r.Tag,
		"body":    body,
	})
}

// PreviewEnvelope renders sophosfw.v1.preview (raw_request --dry-run).
func PreviewEnvelope(p *svc.Preview) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.preview", map[string]any{
		"profile":        p.Profile,
		"mutating":       p.Mutating,
		"verbs":          p.Verbs,
		"redactedXml":    p.RedactedXML,
		"wouldSendBytes": p.WouldSendBytes,
		"warning":        p.Warning,
	})
}

// HostIPListEnvelope renders sophosfw.v1.hostIpList. The schema name is
// passed in by the caller because list and search reuse the same payload
// shape under different schemas (sophosfw.v1.hostIpList vs hostIpSearch).
func HostIPListEnvelope(schema string, list *svc.HostIPList) ([]byte, error) {
	return marshalEnvelope(schema, map[string]any{
		"profile": list.Profile,
		"xmlTag":  "IPHost",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// HostIPEnvelope renders sophosfw.v1.hostIp.
func HostIPEnvelope(h *svc.HostIP) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.hostIp", h)
}

// HostIPEnvelopeWithDiffHash renders sophosfw.v1.hostIp with _diffHash field.
func HostIPEnvelopeWithDiffHash(h *svc.HostIP, hash string) ([]byte, error) {
	payload := map[string]any{
		"_diffHash": hash,
	}
	hbytes, _ := json.Marshal(h)
	var hmap map[string]any
	// h is a struct we just marshalled, so the round-trip Unmarshal cannot fail.
	_ = json.Unmarshal(hbytes, &hmap)
	for k, v := range hmap {
		payload[k] = v
	}
	return marshalEnvelope("sophosfw.v1.hostIp", payload)
}

// HostIPUsageEnvelope renders sophosfw.v1.hostIpUsage.
func HostIPUsageEnvelope(u *svc.HostIPUsage) ([]byte, error) {
	payload := map[string]any{
		"profile": u.Profile,
		"name":    u.Name,
		"records": u.Records,
	}
	if u.References != nil {
		payload["references"] = u.References.Refs
		if len(u.References.Errors) > 0 {
			payload["referenceErrors"] = u.References.Errors
		}
	}
	return marshalEnvelope("sophosfw.v1.hostIpUsage", payload)
}

// HostIpMutationEnvelope renders sophosfw.v1.hostIpMutation.
func HostIpMutationEnvelope(r *svc.HostIPMutationResult) ([]byte, error) {
	payload := map[string]any{
		"profile":   r.Profile,
		"operation": r.Operation,
		"name":      r.Name,
		"applied":   !r.DryRun,
	}
	if r.Item != nil {
		hash, _ := svc.DiffHash(r.Item.IPHost)
		raw, err := json.Marshal(r.Item)
		if err == nil {
			var itemMap map[string]any
			if err := json.Unmarshal(raw, &itemMap); err == nil {
				itemMap["_diffHash"] = hash
				payload["item"] = itemMap
			}
		}
	}
	return marshalEnvelope("sophosfw.v1.hostIpMutation", payload)
}

// ServiceListEnvelope renders sophosfw.v1.serviceList or sophosfw.v1.serviceSearch.
func ServiceListEnvelope(schema string, list *svc.ServiceList) ([]byte, error) {
	return marshalEnvelope(schema, map[string]any{
		"profile": list.Profile,
		"xmlTag":  "Services",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// ServiceEnvelope renders sophosfw.v1.service.
func ServiceEnvelope(v *svc.Service) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.service", v)
}

// ServiceUsageEnvelope renders sophosfw.v1.serviceUsage.
func ServiceUsageEnvelope(u *svc.ServiceUsage) ([]byte, error) {
	payload := map[string]any{
		"profile": u.Profile,
		"name":    u.Name,
		"records": u.Records,
	}
	if u.References != nil {
		payload["references"] = u.References.Refs
		if len(u.References.Errors) > 0 {
			payload["referenceErrors"] = u.References.Errors
		}
	}
	return marshalEnvelope("sophosfw.v1.serviceUsage", payload)
}

// FirewallRuleListEnvelope renders sophosfw.v1.firewallRuleList.
func FirewallRuleListEnvelope(list *svc.FirewallRuleList) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.firewallRuleList", map[string]any{
		"profile": list.Profile,
		"xmlTag":  "FirewallRule",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// FirewallRuleEnvelope renders sophosfw.v1.firewallRule.
func FirewallRuleEnvelope(rule map[string]any) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.firewallRule", rule)
}

// NATRuleListEnvelope renders sophosfw.v1.natRuleList.
func NATRuleListEnvelope(list *svc.NATRuleList) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.natRuleList", map[string]any{
		"profile": list.Profile,
		"xmlTag":  "NATRule",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// NATRuleEnvelope renders sophosfw.v1.natRule.
func NATRuleEnvelope(rule map[string]any) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.natRule", rule)
}

// ErrorEnvelope renders sophosfw.v1.error.
func ErrorEnvelope(kind, message, profile string) ([]byte, error) {
	payload := map[string]any{
		"kind":    kind,
		"message": message,
	}
	if profile != "" {
		payload["profile"] = profile
	}
	return marshalEnvelope("sophosfw.v1.error", payload)
}

// FirewallRulePullEnvelope renders sophosfw.v1.firewallRulePull.
func FirewallRulePullEnvelope(r *svc.FirewallRulePullResult) ([]byte, error) {
	refs := make([]map[string]any, 0, len(r.References))
	for _, rs := range r.References {
		refs = append(refs, map[string]any{
			"type":  rs.Type,
			"names": rs.Names,
		})
	}
	payload := map[string]any{
		"profile":      r.Profile,
		"rule":         r.Rule,
		"draftPath":    r.DraftPath,
		"snapshotPath": r.SnapshotPath,
		"diffHash":     r.DiffHash,
		"references":   refs,
	}
	return marshalEnvelope("sophosfw.v1.firewallRulePull", payload)
}

// FirewallRuleDiffEnvelope renders sophosfw.v1.firewallRuleDiff.
func FirewallRuleDiffEnvelope(r *svc.FirewallRuleDiffResult) ([]byte, error) {
	entries := make([]map[string]any, 0, len(r.StructuredDiff))
	for _, e := range r.StructuredDiff {
		entries = append(entries, map[string]any{
			"path":     e.Path,
			"op":       e.Op,
			"oldValue": e.OldValue,
			"newValue": e.NewValue,
		})
	}
	payload := map[string]any{
		"profile":     r.Profile,
		"rule":        r.Rule,
		"hasChanges":  r.HasChanges,
		"unifiedDiff": r.UnifiedDiff,
		"diffEntries": entries,
	}
	return marshalEnvelope("sophosfw.v1.firewallRuleDiff", payload)
}

// FirewallRulePushEnvelope renders sophosfw.v1.firewallRulePush.
func FirewallRulePushEnvelope(r *svc.FirewallRulePushResult) ([]byte, error) {
	payload := map[string]any{
		"profile":   r.Profile,
		"rule":      r.Rule,
		"operation": r.Operation,
		"applied":   !r.DryRun,
		"dryRun":    r.DryRun,
	}
	if r.DryRun && r.Preview != nil {
		payload["preview"] = map[string]any{
			"mutating":       r.Preview.Mutating,
			"verbs":          r.Preview.Verbs,
			"redactedXml":    r.Preview.RedactedXML,
			"wouldSendBytes": r.Preview.WouldSendBytes,
		}
	}
	if !r.DryRun {
		payload["newDiffHash"] = r.NewDiffHash
		if r.Item != nil {
			payload["item"] = r.Item
		}
	}
	return marshalEnvelope("sophosfw.v1.firewallRulePush", payload)
}

// NATRulePullEnvelope renders sophosfw.v1.natRulePull.
func NATRulePullEnvelope(r *svc.NATRulePullResult) ([]byte, error) {
	refs := make([]map[string]any, 0, len(r.References))
	for _, rs := range r.References {
		refs = append(refs, map[string]any{"type": rs.Type, "names": rs.Names})
	}
	payload := map[string]any{
		"profile":      r.Profile,
		"rule":         r.Rule,
		"draftPath":    r.DraftPath,
		"snapshotPath": r.SnapshotPath,
		"diffHash":     r.DiffHash,
		"references":   refs,
	}
	return marshalEnvelope("sophosfw.v1.natRulePull", payload)
}

// NATRuleDiffEnvelope renders sophosfw.v1.natRuleDiff.
func NATRuleDiffEnvelope(r *svc.NATRuleDiffResult) ([]byte, error) {
	entries := make([]map[string]any, 0, len(r.StructuredDiff))
	for _, e := range r.StructuredDiff {
		entries = append(entries, map[string]any{
			"path":     e.Path,
			"op":       e.Op,
			"oldValue": e.OldValue,
			"newValue": e.NewValue,
		})
	}
	payload := map[string]any{
		"profile":     r.Profile,
		"rule":        r.Rule,
		"hasChanges":  r.HasChanges,
		"unifiedDiff": r.UnifiedDiff,
		"diffEntries": entries,
	}
	return marshalEnvelope("sophosfw.v1.natRuleDiff", payload)
}

// NATRulePushEnvelope renders sophosfw.v1.natRulePush.
func NATRulePushEnvelope(r *svc.NATRulePushResult) ([]byte, error) {
	payload := map[string]any{
		"profile":   r.Profile,
		"rule":      r.Rule,
		"operation": r.Operation,
		"applied":   !r.DryRun,
		"dryRun":    r.DryRun,
	}
	if r.DryRun && r.Preview != nil {
		payload["preview"] = map[string]any{
			"mutating":       r.Preview.Mutating,
			"verbs":          r.Preview.Verbs,
			"redactedXml":    r.Preview.RedactedXML,
			"wouldSendBytes": r.Preview.WouldSendBytes,
		}
	}
	if !r.DryRun {
		payload["newDiffHash"] = r.NewDiffHash
		if r.Item != nil {
			payload["item"] = r.Item
		}
	}
	return marshalEnvelope("sophosfw.v1.natRulePush", payload)
}

// marshalEnvelope is the shared writer used by all envelope helpers. It
// produces the same indent-2 JSON that WriteJSON does, with the schema
// embedded as the first field.
func marshalEnvelope(schema string, payload any) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, schema, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
