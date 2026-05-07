// Package svc — IPsecPolicy mutating surface (Phase 15, Task 4).
//
// Body-as-map create/update/delete for IPsecPolicy objects. Pure mirror
// of the Phase 12 IPHostGroupSvc template with IPsecPolicy substitutions;
// see docs/plans/2026-05-03-sophosfw-phase15.md.
//
// Dormant in v0.13.1 — Sophos 22.x XML API does not recognize the
// "IPsecPolicy" tag (probe returned "Input request module is Invalid").
// This file is excluded from default builds behind the
// `ipsecpolicy_dormant` build tag and retained for future re-wiring
// once the correct tag name is discovered. See Phase 15.x roadmap.

//go:build ipsecpolicy_dormant

package svc

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// IPsecPolicySvc owns the create/update/delete surface for IPsecPolicy.
// It composes ObjectSvc for catalog/profile/client wiring and the audit
// log for write-side observability. Now is an injectable clock; nil
// means time.Now().UTC(). Reserved for future timestamping (snapshot
// suffixes, audit deduplication) — currently unused but retained for
// symmetry with FirewallRuleSvc and the other per-type services.
type IPsecPolicySvc struct {
	Inner *ObjectSvc
	Audit *AuditLog
	Now   func() time.Time
}

//nolint:unused // reserved for future timestamping; kept for cross-type symmetry.
func (s *IPsecPolicySvc) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// requiredIPsecPolicyFields are the keys a create/update body must
// supply. Sophos rejects partial bodies with unhelpful "Operation could
// not be performed on Entity" errors, so we gate client-side. Other
// IPsecPolicy fields (encryption algorithm, hash, DH group, key lifetime
// etc.) have Sophos defaults — minimal bodies should work for create.
var requiredIPsecPolicyFields = []string{"Name"}

// Create adds a new IPsecPolicy. The body must include all keys listed
// in requiredIPsecPolicyFields. dryRun=true returns a Preview without
// sending the envelope.
func (s *IPsecPolicySvc) Create(ctx context.Context, profileName, name string, body map[string]any, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, body, "create", "", false, dryRun)
}

// Update replaces an existing IPsecPolicy body. expectedHash is required
// (unless ignoreHash is true) and must match the live record's
// DiffHash; otherwise ErrDiffHashMismatch is returned.
func (s *IPsecPolicySvc) Update(ctx context.Context, profileName, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, body, "update", expectedHash, ignoreHash, dryRun)
}

// Delete removes an IPsecPolicy by name. expectedHash is required
// (unless ignoreHash is true) and must match the live record's
// DiffHash; otherwise ErrDiffHashMismatch is returned.
func (s *IPsecPolicySvc) Delete(ctx context.Context, profileName, name, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, nil, "delete", expectedHash, ignoreHash, dryRun)
}

// mutate is the shared create/update/delete pipeline. The op string is
// one of "create" | "update" | "delete" and selects which envelope verb
// to build and which validation gates to apply:
//
//	create  → required-field check; <Set operation="add">
//	update  → required-field check + hash gate; <Set operation="update">
//	delete  → hash gate; <Remove>
//
// Pre-flight order is intentional: profile lookup → audit skeleton →
// read-only check → catalog Mutable check → required-field check (skip
// for delete) → live fetch + hash gate (skip for create) → envelope
// build → dry-run short-circuit → apply → refetch + new-hash on success.
func (s *IPsecPolicySvc) mutate(ctx context.Context, profileName, name string, body map[string]any, op, expectedHash string, ignoreHash, dryRun bool) (out *ObjectMutationResult, err error) {
	profile, resolvedName, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    resolvedName,
		Operation:  "ipsec_policy_" + op,
		ObjectType: "IPsecPolicy",
		ObjectName: name,
	}
	if expectedHash != "" {
		entryAudit.ExpectedDiffHash = expectedHash
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}
	// Catch-all error audit; explicit Result writes below short-circuit
	// this defer.
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, resolvedName)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("IPsecPolicy")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: IPsecPolicy is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	// Strip the _diffHash that ObjectSvc.Get injects into mutable
	// records — otherwise the natural object_get → edit → update
	// workflow leaks <_diffHash>...</_diffHash> into the XML envelope.
	// Delete passes body=nil, so this is a safe no-op there.
	//
	// We clone into a fresh map rather than mutate the caller's map.
	// CLI/MCP fan-out runs preflight goroutines in parallel against
	// the same body; concurrent delete on a shared map would trip
	// Go's "concurrent map writes" runtime panic. The clone is cheap
	// (small maps, shallow copy) and protects every fan-out caller.
	if body != nil {
		cloned := make(map[string]any, len(body))
		for k, v := range body {
			if k == "_diffHash" {
				continue
			}
			cloned[k] = v
		}
		body = cloned
	}

	if op != "delete" {
		for _, k := range requiredIPsecPolicyFields {
			v, present := body[k]
			if !present {
				return nil, fmt.Errorf("%w: body missing required field %q", sophos.ErrInvalidRequest, k)
			}
			if str, isStr := v.(string); isStr && str == "" {
				return nil, fmt.Errorf("%w: body field %q is empty", sophos.ErrInvalidRequest, k)
			}
		}
	}

	if op != "create" {
		live, gerr := s.fetchLive(ctx, profileName, name)
		if gerr != nil {
			return nil, gerr
		}
		if !ignoreHash {
			if expectedHash == "" {
				return nil, fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest)
			}
			// DiffHash internally strips _diffHash; safe to pass the
			// map ObjectSvc.Get returned (which has it injected).
			currentHash, herr := DiffHash(live)
			if herr != nil {
				return nil, herr
			}
			if currentHash != expectedHash {
				return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, currentHash, expectedHash)
			}
		}
	}

	c, perr := s.Inner.Creds.Load(resolvedName)
	if perr != nil {
		return nil, perr
	}

	var full []byte
	switch op {
	case "create":
		inner, merr := marshalObjectBody("IPsecPolicy", body)
		if merr != nil {
			return nil, merr
		}
		full, perr = sophos.BuildSetEnvelope("add", inner, c.Username, c.Password)
	case "update":
		inner, merr := marshalObjectBody("IPsecPolicy", body)
		if merr != nil {
			return nil, merr
		}
		full, perr = sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
	case "delete":
		var inner bytes.Buffer
		inner.WriteString("<IPsecPolicy><Name>")
		if perr = xml.EscapeText(&inner, []byte(name)); perr != nil {
			return nil, perr
		}
		inner.WriteString("</Name></IPsecPolicy>")
		full, perr = sophos.BuildRemoveEnvelope(inner.Bytes(), c.Username, c.Password)
	default:
		return nil, fmt.Errorf("%w: unknown op %q", sophos.ErrInvalidRequest, op)
	}
	if perr != nil {
		return nil, perr
	}
	entryAudit.RedactedXML = string(safety.RedactXML(full))

	if dryRun {
		mutating, verbs := safety.IsMutating(full)
		pv := &Preview{
			Profile:        resolvedName,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    entryAudit.RedactedXML,
			WouldSendBytes: len(full),
		}
		entryAudit.Result = "ok (dry-run)"
		if s.Audit != nil {
			_ = s.Audit.Write(entryAudit)
		}
		return &ObjectMutationResult{
			Profile:    resolvedName,
			ObjectType: "IPsecPolicy",
			Name:       name,
			Operation:  op,
			DryRun:     true,
			Preview:    pv,
		}, nil
	}

	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		if s.Audit != nil {
			_ = s.Audit.Write(entryAudit)
		}
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	if s.Audit != nil {
		_ = s.Audit.Write(entryAudit)
	}

	result := &ObjectMutationResult{
		Profile:    resolvedName,
		ObjectType: "IPsecPolicy",
		Name:       name,
		Operation:  op,
		DryRun:     false,
	}
	if op != "delete" {
		// Best-effort refetch so the caller can echo a fresh
		// _diffHash and the new live state. Refetch failure does not
		// rollback the apply we just did — surface the un-enriched
		// success.
		if refetched, rerr := s.fetchLive(ctx, profileName, name); rerr == nil {
			if newHash, herr := DiffHash(refetched); herr == nil {
				result.NewDiffHash = newHash
				result.Item = refetched
			}
		}
	}
	return result, nil
}

// fetchLive loads the live IPsecPolicy body as a map[string]any. The
// _diffHash field that ObjectSvc.Get injects for catalog-mutable types
// is left intact; DiffHash strips it before hashing, and downstream
// callers expect to see it in the returned Item.
func (s *IPsecPolicySvc) fetchLive(ctx context.Context, profileName, name string) (map[string]any, error) {
	obj, err := s.Inner.Get(ctx, profileName, "IPsecPolicy", name)
	if err != nil {
		return nil, err
	}
	m, ok := obj.Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("IPsecPolicySvc: catalog returned non-map IPsecPolicy payload: %T", obj.Data)
	}
	if liveName, _ := m["Name"].(string); liveName == "" {
		// Sophos sometimes returns a stub record with all fields
		// blank instead of an empty result set.
		return nil, fmt.Errorf("IPsecPolicy %q: %w", name, sophos.ErrNotFound)
	}
	return m, nil
}
