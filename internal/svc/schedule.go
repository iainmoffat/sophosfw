package svc

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// ScheduleSvc owns the schedule read and write surface.
type ScheduleSvc struct {
	Inner *ObjectSvc
	Audit *AuditLog
	Now   func() time.Time
}

//nolint:unused // retained for symmetry with the other object services.
func (s *ScheduleSvc) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// ScheduleShow is the show result. References is non-nil only when the
// caller asked for them; it lives beside the record, never inside it.
type ScheduleShow struct {
	Object     *Object
	References *References
}

func (s *ScheduleSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*ObjectList, error) {
	return s.Inner.List(ctx, profileName, "Schedule", filter)
}

func (s *ScheduleSvc) Show(ctx context.Context, profileName, name string, withReferences bool) (*ScheduleShow, error) {
	object, err := s.Inner.Get(ctx, profileName, "Schedule", name)
	if err != nil {
		return nil, err
	}
	out := &ScheduleShow{Object: object}
	if withReferences {
		refs, refErr := FindReferences(ctx, s.Inner, profileName, "Schedule", name)
		if refErr == nil {
			out.References = refs
		}
		// The known Schedule reference map cannot fail today, but preserve
		// the object if a future scan returns a Go error as well.
		if refErr != nil {
			out.References = &References{Refs: map[string][]string{}, Errors: map[string]string{"FirewallRule": refErr.Error()}}
		}
	}
	return out, nil
}

func (s *ScheduleSvc) Create(ctx context.Context, profileName, name string, body map[string]any, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, body, "create", "", false, dryRun)
}

func (s *ScheduleSvc) Update(ctx context.Context, profileName, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, body, "update", expectedHash, ignoreHash, dryRun)
}

func (s *ScheduleSvc) Delete(ctx context.Context, profileName, name, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error) {
	return s.mutate(ctx, profileName, name, nil, "delete", expectedHash, ignoreHash, dryRun)
}

func (s *ScheduleSvc) mutate(ctx context.Context, profileName, name string, body map[string]any, op, expectedHash string, ignoreHash, dryRun bool) (out *ObjectMutationResult, err error) {
	profile, resolvedName, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	entryAudit := AuditEntry{Profile: resolvedName, Operation: "schedule_" + op, ObjectType: "Schedule", ObjectName: name}
	if expectedHash != "" {
		entryAudit.ExpectedDiffHash = expectedHash
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}
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
	catEntry, ok := s.Inner.Catalog.Resolve("Schedule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: Schedule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}
	if op != "delete" {
		body, err = validateScheduleBody(body)
		if err != nil {
			return nil, err
		}
	}

	if op != "create" {
		live, getErr := s.fetchLive(ctx, profileName, name)
		if getErr != nil {
			return nil, getErr
		}
		if !ignoreHash {
			if expectedHash == "" {
				return nil, fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest)
			}
			currentHash, hashErr := DiffHash(live)
			if hashErr != nil {
				return nil, hashErr
			}
			if currentHash != expectedHash {
				return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, currentHash, expectedHash)
			}
		}
	}

	if op == "delete" {
		refs, refErr := FindReferences(ctx, s.Inner, profileName, "Schedule", name)
		if refErr != nil {
			return nil, refErr
		}
		if message, incomplete := scheduleReferenceScanError(refs); incomplete {
			return nil, fmt.Errorf("%w: schedule %q: reference scan could not complete (%s); refusing to delete", sophos.ErrInvalidRequest, name, message)
		}
		if names := refs.Refs["FirewallRule"]; len(names) > 0 {
			return nil, fmt.Errorf("%w: schedule %q is referenced by firewall rules: %s", sophos.ErrInvalidRequest, name, strings.Join(names, ", "))
		}
	}

	c, err := s.Inner.Creds.Load(resolvedName)
	if err != nil {
		return nil, err
	}
	var full []byte
	switch op {
	case "create", "update":
		inner, marshalErr := marshalObjectBody("Schedule", body)
		if marshalErr != nil {
			return nil, marshalErr
		}
		verb := "add"
		if op == "update" {
			verb = "update"
		}
		full, err = sophos.BuildSetEnvelope(verb, inner, c.Username, c.Password)
	case "delete":
		var inner bytes.Buffer
		inner.WriteString("<Schedule><Name>")
		if err = xml.EscapeText(&inner, []byte(name)); err != nil {
			return nil, err
		}
		inner.WriteString("</Name></Schedule>")
		full, err = sophos.BuildRemoveEnvelope(inner.Bytes(), c.Username, c.Password)
	default:
		return nil, fmt.Errorf("%w: unknown op %q", sophos.ErrInvalidRequest, op)
	}
	if err != nil {
		return nil, err
	}
	entryAudit.RedactedXML = string(safety.RedactXML(full))

	if dryRun {
		mutating, verbs := safety.IsMutating(full)
		preview := &Preview{Profile: resolvedName, Mutating: mutating, Verbs: verbs, RedactedXML: entryAudit.RedactedXML, WouldSendBytes: len(full)}
		entryAudit.Result = "ok (dry-run)"
		if s.Audit != nil {
			_ = s.Audit.Write(entryAudit)
		}
		return &ObjectMutationResult{Profile: resolvedName, ObjectType: "Schedule", Name: name, Operation: op, DryRun: true, Preview: preview}, nil
	}

	client := s.Inner.NewClient(profile, c)
	if _, err = client.DoRaw(ctx, full); err != nil {
		entryAudit.Result = "error:" + ErrorKind(err)
		entryAudit.ErrorMessage = err.Error()
		if s.Audit != nil {
			_ = s.Audit.Write(entryAudit)
		}
		return nil, err
	}
	entryAudit.Result = "ok"
	if s.Audit != nil {
		_ = s.Audit.Write(entryAudit)
	}

	result := &ObjectMutationResult{Profile: resolvedName, ObjectType: "Schedule", Name: name, Operation: op}
	if op != "delete" {
		if refetched, refetchErr := s.fetchLive(ctx, profileName, name); refetchErr == nil {
			if newHash, hashErr := DiffHash(refetched); hashErr == nil {
				result.NewDiffHash = newHash
				result.Item = refetched
			}
		}
	}
	return result, nil
}

func scheduleReferenceScanError(refs *References) (string, bool) {
	if message := refs.Errors["FirewallRule"]; message != "" {
		return message, true
	}
	if skipped := refs.Skipped["FirewallRule"]; skipped > 0 {
		return fmt.Sprintf("%d FirewallRule records could not be examined", skipped), true
	}
	return "", false
}

func (s *ScheduleSvc) fetchLive(ctx context.Context, profileName, name string) (map[string]any, error) {
	object, err := s.Inner.Get(ctx, profileName, "Schedule", name)
	if err != nil {
		return nil, err
	}
	m, ok := object.Data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("ScheduleSvc: catalog returned non-map Schedule payload: %T", object.Data)
	}
	if liveName, _ := m["Name"].(string); liveName == "" {
		return nil, fmt.Errorf("schedule %q: %w", name, sophos.ErrNotFound)
	}
	return m, nil
}
