package svc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// fakeServicesClient is the test double for ServicesSvc. It answers
// Get with a single canned record (when set) and records the raw
// envelopes sent via DoRaw so apply tests can assert the exact verb
// shape.
type fakeServicesClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeServicesClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "Services" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["Services"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeServicesClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

// newServicesSvc constructs a ServicesSvc backed by a fake client
// primed with `body` (the live Services record returned to Get calls).
// Returns the svc, the fake client (for sent-envelope assertions), and
// the audit dir for log assertions.
func newServicesSvc(t *testing.T, body map[string]any) (*ServicesSvc, *fakeServicesClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	fc := &fakeServicesClient{body: body}
	s := &ServicesSvc{
		Inner: &ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		},
		Audit: audit,
	}
	return s, fc, auditDir
}

// validServicesBody returns a body that satisfies the required-field
// check. ServiceDetails is a nested map; marshalObjectBody handles the
// recursion automatically.
func validServicesBody() map[string]any {
	return map[string]any{
		"Name": "ssh",
		"Type": "TCPorUDP",
		"ServiceDetails": map[string]any{
			"ServiceDetail": map[string]any{
				"Protocol":        "TCP",
				"SourcePort":      "1:65535",
				"DestinationPort": "22",
			},
		},
	}
}

func TestServices_Create_RejectsMissingRequiredField(t *testing.T) {
	s, fc, _ := newServicesSvc(t, nil)
	body := map[string]any{"Name": "ssh", "Type": "TCPorUDP"} // ServiceDetails missing
	_, err := s.Create(context.Background(), "home", "ssh", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "ServiceDetails")
	require.Empty(t, fc.sent)
}

func TestServices_Create_RejectsReadOnlyProfile(t *testing.T) {
	s, fc, _ := newServicesSvc(t, nil)
	p := s.Inner.Config.Profiles["home"]
	p.ReadOnly = true
	s.Inner.Config.Profiles["home"] = p

	body := validServicesBody()
	_, err := s.Create(context.Background(), "home", "ssh", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestServices_Create_DryRun_EmitsPreview(t *testing.T) {
	s, fc, _ := newServicesSvc(t, nil)
	body := validServicesBody()
	out, err := s.Create(context.Background(), "home", "ssh", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Equal(t, "Services", out.ObjectType)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestServices_Create_Apply_SendsAddEnvelope(t *testing.T) {
	body := validServicesBody()
	s, fc, _ := newServicesSvc(t, body)
	out, err := s.Create(context.Background(), "home", "ssh", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<Services>`)
	require.Contains(t, string(fc.sent[0]), `<Name>ssh</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestServices_Update_RejectsMissingExpectedDiffHash(t *testing.T) {
	body := validServicesBody()
	s, fc, _ := newServicesSvc(t, body)
	_, err := s.Update(context.Background(), "home", "ssh", body, "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestServices_Update_RejectsHashMismatch(t *testing.T) {
	body := validServicesBody()
	s, fc, _ := newServicesSvc(t, body)
	_, err := s.Update(context.Background(), "home", "ssh", body, "definitely-not-the-real-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestServices_Update_DryRun_EmitsPreview(t *testing.T) {
	live := validServicesBody()
	hash, _ := DiffHash(live)
	s, fc, _ := newServicesSvc(t, live)
	out, err := s.Update(context.Background(), "home", "ssh", live, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.NotNil(t, out.Preview)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestServices_Update_Apply_SendsUpdateEnvelope(t *testing.T) {
	live := validServicesBody()
	hash, _ := DiffHash(live)
	s, fc, _ := newServicesSvc(t, live)
	out, err := s.Update(context.Background(), "home", "ssh", live, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<Services>`)
	require.Contains(t, string(fc.sent[0]), `<Name>ssh</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestServices_Delete_RejectsMissingExpectedDiffHash(t *testing.T) {
	live := validServicesBody()
	s, fc, _ := newServicesSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "ssh", "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestServices_Delete_RejectsHashMismatch(t *testing.T) {
	live := validServicesBody()
	s, fc, _ := newServicesSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "ssh", "wrong-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestServices_Delete_Apply_SendsRemoveEnvelope(t *testing.T) {
	live := validServicesBody()
	hash, _ := DiffHash(live)
	s, fc, auditDir := newServicesSvc(t, live)
	out, err := s.Delete(context.Background(), "home", "ssh", hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "delete", out.Operation)
	require.False(t, out.DryRun)
	require.Empty(t, out.NewDiffHash, "delete must not return a NewDiffHash")
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<Services>`)
	require.Contains(t, string(fc.sent[0]), `<Name>ssh</Name>`)

	// Audit captured the delete with the canonical op name.
	logBody, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"services_delete"`)
	require.Contains(t, string(logBody), `"objectName":"ssh"`)
}

func TestServices_Delete_OnMissing_ReturnsNotFound(t *testing.T) {
	s, fc, _ := newServicesSvc(t, nil) // nil body → Get returns not_found
	_, err := s.Delete(context.Background(), "home", "Missing", "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Empty(t, fc.sent)
}

// TestServices_Update_OnStubRecord_ReturnsNotFoundWithName ensures the
// stub-record branch in fetchLive surfaces the requested name in the
// error string. Regression: a previous version shadowed the outer
// `name` arg with the live record's empty Name, producing
// `Services "": not_found`.
func TestServices_Update_OnStubRecord_ReturnsNotFoundWithName(t *testing.T) {
	// Stub record: catalog Get parses it as a map with Name="" and
	// _diffHash injected; fetchLive must reject it as not_found while
	// preserving the requested name in the message.
	stub := map[string]any{"Name": "", "Type": "", "ServiceDetails": ""}
	s, fc, _ := newServicesSvc(t, stub)
	body := validServicesBody()
	body["Name"] = "RequestedName"
	_, err := s.Update(context.Background(), "home", "RequestedName", body, "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Contains(t, err.Error(), `"RequestedName"`,
		"error message must include the requested name, not the empty live Name (shadowing regression)")
	require.NotContains(t, err.Error(), `""`,
		"error message must not show empty quotes")
	require.Empty(t, fc.sent)
}

// TestServices_Update_StripsInjectedDiffHashFromBody verifies that
// when a caller passes a body with `_diffHash` (e.g. the natural
// object_get → edit → update workflow, where ObjectSvc.Get injects it),
// the field is stripped before XML marshalling so it never appears in
// the envelope sent to the appliance.
func TestServices_Update_StripsInjectedDiffHashFromBody(t *testing.T) {
	live := validServicesBody()
	hash, _ := DiffHash(live)
	s, fc, _ := newServicesSvc(t, live)
	// Body mirrors what a user would pass after object_get — includes
	// the _diffHash key the catalog injected.
	body := validServicesBody()
	body["_diffHash"] = "abc123"
	out, err := s.Update(context.Background(), "home", "ssh", body, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash",
		"injected _diffHash must be stripped before XML marshal")
	require.NotContains(t, string(fc.sent[0]), "abc123",
		"diffHash value must not leak into the envelope")
}
