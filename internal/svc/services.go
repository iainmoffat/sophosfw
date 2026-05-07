// Package svc — Services mutating surface (Phase 12, Task 10).
//
// Body-as-map create/update/delete for Services objects. Mechanical
// mirror of FQDNHostSvc; see internal/svc/fqdnhost.go for the canonical
// template and docs/plans/2026-05-03-sophosfw-phase12.md
// for the per-type substitution table.
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

// ServicesSvc owns the create/update/delete surface for Services.
// It composes ObjectSvc for catalog/profile/client wiring and the audit
// log for write-side observability. Now is an injectable clock; nil
// means time.Now().UTC(). Reserved for future timestamping (snapshot
// suffixes, audit deduplication) — currently unused but retained for
// symmetry with IPHostGroupSvc and FirewallRuleSvc.
type ServicesSvc struct {
	Inner *ObjectSvc
	Audit *AuditLog
	Now   func() time.Time
}

//nolint:unused // reserved for future timestamping; kept for cross-type symmetry.
func (s *ServicesSvc) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// requiredServicesFields are the keys a create/update body must
// supply. Sophos rejects partial bodies with unhelpful "Operation could
// not be performed on Entity" errors, so we gate client-side.
var requiredServicesFields = []string{"Name", "Type", "ServiceDetails"}

// Create adds a new Services. The body must include all keys listed
// in requiredServicesFields. dryRun=true returns a Preview without
// sending the envelope.
func (s *ServicesSvc) Create(ctx context.Context, profileName, name string, body map[string]any, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, body, "create", "", false, dryRun)
}

// Update replaces an existing Services body. expectedHash is required
// (unless ignoreHash is true) and must match the live record's
// DiffHash; otherwise ErrDiffHashMismatch is returned.
func (s *ServicesSvc) Update(ctx context.Context, profileName, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, body, "update", expectedHash, ignoreHash, dryRun)
}

// Delete removes a Services by name. expectedHash is required
// (unless ignoreHash is true) and must match the live record's
// DiffHash; otherwise ErrDiffHashMismatch is returned.
func (s *ServicesSvc) Delete(ctx context.Context, profileName, name, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error) {
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
func (s *ServicesSvc) mutate(ctx context.Context, profileName, name string, body map[string]any, op, expectedHash string, ignoreHash, dryRun bool) (out *ObjectMutationResult, err error) {
	profile, resolvedName, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    resolvedName,
		Operation:  "services_" + op,
		ObjectType: "Services",
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

	catEntry, ok := s.Inner.Catalog.Resolve("Services")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: Services is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
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
		for _, k := range requiredServicesFields {
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
		inner, merr := marshalObjectBody("Services", body)
		if merr != nil {
			return nil, merr
		}
		full, perr = sophos.BuildSetEnvelope("add", inner, c.Username, c.Password)
	case "update":
		inner, merr := marshalObjectBody("Services", body)
		if merr != nil {
			return nil, merr
		}
		full, perr = sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
	case "delete":
		var inner bytes.Buffer
		inner.WriteString("<Services><Name>")
		if perr = xml.EscapeText(&inner, []byte(name)); perr != nil {
			return nil, perr
		}
		inner.WriteString("</Name></Services>")
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
			ObjectType: "Services",
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
		ObjectType: "Services",
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

// fetchLive loads the live Services body as a map[string]any. The
// _diffHash field that ObjectSvc.Get injects for catalog-mutable types
// is left intact; DiffHash strips it before hashing, and downstream
// callers expect to see it in the returned Item.
func (s *ServicesSvc) fetchLive(ctx context.Context, profileName, name string) (map[string]any, error) {
	obj, err := s.Inner.Get(ctx, profileName, "Services", name)
	if err != nil {
		return nil, err
	}
	m, ok := obj.Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("ServicesSvc: catalog returned non-map Services payload: %T", obj.Data)
	}
	if liveName, _ := m["Name"].(string); liveName == "" {
		// Sophos sometimes returns a stub record with all fields
		// blank instead of an empty result set.
		return nil, fmt.Errorf("services %q: %w", name, sophos.ErrNotFound)
	}
	return m, nil
}
