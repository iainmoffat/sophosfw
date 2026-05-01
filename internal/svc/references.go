package svc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// referenceTargets maps a primary catalog tag to the catalog tags that may
// reference it. Order is the order results appear in JSON output. Adding a
// new referrer type later is a one-line change.
var referenceTargets = map[string][]string{
	"IPHost":   {"IPHostGroup", "FirewallRule", "NATRule"},
	"FQDNHost": {"FQDNHostGroup", "FirewallRule"},
	"MACHost":  {"FirewallRule"},
	"Service":  {"ServiceGroup", "FirewallRule", "NATRule"},
	"Zone":     {"FirewallRule"},
}

// References is the result of a reference-graph scan. Refs is the per-
// referrer name list; Errors is the per-referrer error message captured
// when a sub-query failed. A successful query that found no references
// yields an empty slice in Refs (NOT a missing key); a failed query yields
// no Refs entry and an Errors entry.
type References struct {
	Refs   map[string][]string `json:"refs"`
	Errors map[string]string   `json:"errors,omitempty"`
}

// ErrUnknownPrimaryTag is returned by FindReferences when the caller asks
// for a primary tag that's not in the static referenceTargets map.
var ErrUnknownPrimaryTag = errors.New("references: primary tag has no referrer map entry")

// FindReferences scans the catalog tags listed for `primaryTag` and returns
// a References value listing every record (by Name) whose JSON contains
// `name` as an exact string value somewhere in its body. Per-referrer query
// failures (auth, network, permission) are captured in References.Errors;
// they do NOT cause this function to return an error. Only a missing entry
// in referenceTargets yields a Go error.
func FindReferences(ctx context.Context, inner *ObjectSvc, profileName, primaryTag, name string) (*References, error) {
	referrers, ok := referenceTargets[primaryTag]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPrimaryTag, primaryTag)
	}
	out := &References{
		Refs:   make(map[string][]string, len(referrers)),
		Errors: make(map[string]string),
	}
	for _, ref := range referrers {
		out.Refs[ref] = []string{}
		list, err := inner.List(ctx, profileName, ref, nil)
		if err != nil {
			out.Errors[ref] = errorTag(err) + ": " + err.Error()
			continue
		}
		for _, item := range list.Items {
			b, mErr := json.Marshal(item)
			if mErr != nil {
				continue
			}
			var record map[string]any
			if uErr := json.Unmarshal(b, &record); uErr != nil {
				continue
			}
			if recordContains(record, name) {
				if rn, ok := record["Name"].(string); ok && rn != "" {
					out.Refs[ref] = append(out.Refs[ref], rn)
				}
			}
		}
	}
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	return out, nil
}

// recordContains walks a parsed JSON record and returns true if any leaf
// string value (scalar or array element) equals `name` exactly.
func recordContains(v any, name string) bool {
	switch t := v.(type) {
	case string:
		return t == name
	case []any:
		for _, e := range t {
			if recordContains(e, name) {
				return true
			}
		}
	case map[string]any:
		for _, e := range t {
			if recordContains(e, name) {
				return true
			}
		}
	}
	return false
}

// errorTag returns a short error-kind tag matching the cli vocabulary so
// per-referrer error strings in JSON output stay readable.
func errorTag(err error) string {
	switch {
	case errors.Is(err, sophosErrPermissionDenied()):
		return "permission_denied"
	case errors.Is(err, sophosErrAuthFailed()):
		return "auth_failed"
	case errors.Is(err, sophosErrNotFound()):
		return "not_found"
	case errors.Is(err, sophosErrInvalidRequest()):
		return "invalid_request"
	case errors.Is(err, sophosErrServerError()):
		return "server_error"
	case errors.Is(err, sophosErrReadOnlyViolation()):
		return "read_only_violation"
	default:
		return "generic"
	}
}
