package svc

import (
	"context"
	"errors"
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// ErrUnsupportedInPhase is returned by foundation-phase code paths that exist
// for forward compatibility but have no implementation yet (e.g. raw apply).
var ErrUnsupportedInPhase = errors.New("operation not supported in foundation phase")

// RawResponse is the render-friendly result of `raw get`.
type RawResponse struct {
	Profile string
	Tag     string
	Status  StatusInfo
	Body    map[string][][]byte // raw XML fragments per tag (re-encoded)
}

// StatusInfo summarizes Sophos status fields.
type StatusInfo struct {
	Code    int
	Message string
}

// Preview is the render-friendly result of `raw request --dry-run`.
type Preview struct {
	Profile        string
	Mutating       bool
	Verbs          []string
	RedactedXML    string
	WouldSendBytes int
	Warning        string
}

// RawSvc serves `raw get` and `raw request --dry-run`.
type RawSvc struct {
	Config    *config.Config
	Creds     creds.Store
	NewClient ClientFactory
	Audit     *AuditLog // optional; nil = no audit
}

func (s *RawSvc) clientFor(profileName string) (Client, string, error) {
	p, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, "", err
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return nil, "", err
	}
	return s.NewClient(p, c), name, nil
}

// Get sends a generic <Get><Tag></Tag></Get>.
func (s *RawSvc) Get(ctx context.Context, profileName, xmlTag string) (*RawResponse, error) {
	cl, name, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{XMLTag: xmlTag}}})
	if err != nil && resp == nil {
		return nil, err
	}

	out := &RawResponse{Profile: name, Tag: xmlTag, Body: map[string][][]byte{}}
	for tag, recs := range resp.Body {
		out.Body[tag] = make([][]byte, 0, len(recs))
		for _, r := range recs {
			out.Body[tag] = append(out.Body[tag], []byte(r))
		}
	}
	return out, err
}

// Preview wraps a user-supplied body with login (so the returned redacted XML
// reflects what would actually be sent), runs IsMutating, and returns the
// summary. NEVER sends the request.
func (s *RawSvc) Preview(ctx context.Context, profileName string, body []byte) (*Preview, error) {
	p, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	_ = p

	full, err := sophos.BuildRawEnvelope(body, c.Username, c.Password)
	if err != nil {
		return nil, err
	}

	mutating, verbs := safety.IsMutating(full)
	pv := &Preview{
		Profile:        name,
		Mutating:       mutating,
		Verbs:          verbs,
		RedactedXML:    string(safety.RedactXML(full)),
		WouldSendBytes: len(full),
	}
	if mutating {
		pv.Warning = "Mutating XML detected. Apply path is not implemented in this phase."
	}
	return pv, nil
}

// Apply sends a user-supplied raw envelope. Body is wrapped in a Sophos
// <Request><Login>...</Login>BODY</Request> wrapper, sent, and audit-logged.
// Pre-flight: read-only-profile rejection. The cli is expected to enforce
// the --confirm-mutating intent gate before calling this method when the
// envelope contains mutating verbs.
func (s *RawSvc) Apply(ctx context.Context, profileName string, body []byte) error {
	profile, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return err
	}
	if profile.ReadOnly {
		return fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return err
	}
	full, err := sophos.BuildRawEnvelope(body, c.Username, c.Password)
	if err != nil {
		return err
	}

	cl := s.NewClient(profile, c)
	_, sendErr := cl.DoRaw(ctx, full)

	mutating, _ := safety.IsMutating(full)
	op := "raw_apply"
	if mutating {
		op = "raw_apply_mutating"
	}
	entry := AuditEntry{
		Profile:     name,
		Operation:   op,
		ObjectType:  "raw",
		RedactedXML: string(safety.RedactXML(full)),
	}
	if sendErr != nil {
		entry.Result = "error:" + ErrorKind(sendErr)
		entry.ErrorMessage = sendErr.Error()
	} else {
		entry.Result = "ok"
	}
	if s.Audit != nil {
		_ = s.Audit.Write(entry)
	}

	return sendErr
}
