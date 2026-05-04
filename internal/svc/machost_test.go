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

// fakeMacHostClient is the test double for MACHostSvc. It answers
// Get with a single canned record (when set) and records the raw
// envelopes sent via DoRaw so apply tests can assert the exact verb
// shape.
type fakeMacHostClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeMacHostClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "MACHost" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["MACHost"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeMacHostClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

// newMACHostSvc constructs an MACHostSvc backed by a fake client
// primed with `body` (the live MACHost record returned to Get calls).
// Returns the svc, the fake client (for sent-envelope assertions), and
// the audit dir for log assertions.
func newMACHostSvc(t *testing.T, body map[string]any) (*MACHostSvc, *fakeMacHostClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	fc := &fakeMacHostClient{body: body}
	s := &MACHostSvc{
		Inner: &ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		},
		Audit: audit,
	}
	return s, fc, auditDir
}

func TestMACHost_Create_RejectsMissingRequiredField(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil)
	body := map[string]any{"Name": "M1", "MACAddress": "00:11:22:33:44:55"} // Type missing
	_, err := s.Create(context.Background(), "home", "M1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "Type")
	require.Empty(t, fc.sent)
}

func TestMACHost_Create_RejectsReadOnlyProfile(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil)
	p := s.Inner.Config.Profiles["home"]
	p.ReadOnly = true
	s.Inner.Config.Profiles["home"] = p

	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	_, err := s.Create(context.Background(), "home", "M1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestMACHost_Create_DryRun_EmitsPreview(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil)
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	out, err := s.Create(context.Background(), "home", "M1", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Equal(t, "MACHost", out.ObjectType)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestMACHost_Create_Apply_SendsAddEnvelope(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	s, fc, _ := newMACHostSvc(t, body)
	out, err := s.Create(context.Background(), "home", "M1", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<MACHost>`)
	require.Contains(t, string(fc.sent[0]), `<Name>M1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestMACHost_Update_RejectsMissingExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	s, fc, _ := newMACHostSvc(t, body)
	_, err := s.Update(context.Background(), "home", "M1", body, "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestMACHost_Update_RejectsHashMismatch(t *testing.T) {
	body := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	s, fc, _ := newMACHostSvc(t, body)
	_, err := s.Update(context.Background(), "home", "M1", body, "definitely-not-the-real-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestMACHost_Update_DryRun_EmitsPreview(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	hash, _ := DiffHash(live)
	s, fc, _ := newMACHostSvc(t, live)
	out, err := s.Update(context.Background(), "home", "M1", live, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.NotNil(t, out.Preview)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestMACHost_Update_Apply_SendsUpdateEnvelope(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	hash, _ := DiffHash(live)
	s, fc, _ := newMACHostSvc(t, live)
	out, err := s.Update(context.Background(), "home", "M1", live, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<MACHost>`)
	require.Contains(t, string(fc.sent[0]), `<Name>M1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestMACHost_Delete_RejectsMissingExpectedDiffHash(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	s, fc, _ := newMACHostSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "M1", "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestMACHost_Delete_RejectsHashMismatch(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	s, fc, _ := newMACHostSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "M1", "wrong-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestMACHost_Delete_Apply_SendsRemoveEnvelope(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	hash, _ := DiffHash(live)
	s, fc, auditDir := newMACHostSvc(t, live)
	out, err := s.Delete(context.Background(), "home", "M1", hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "delete", out.Operation)
	require.False(t, out.DryRun)
	require.Empty(t, out.NewDiffHash, "delete must not return a NewDiffHash")
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<MACHost>`)
	require.Contains(t, string(fc.sent[0]), `<Name>M1</Name>`)

	// Audit captured the delete with the canonical op name.
	logBody, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"mac_host_delete"`)
	require.Contains(t, string(logBody), `"objectName":"M1"`)
}

func TestMACHost_Delete_OnMissing_ReturnsNotFound(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil) // nil body → Get returns not_found
	_, err := s.Delete(context.Background(), "home", "Missing", "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Empty(t, fc.sent)
}

// TestMACHost_Update_OnStubRecord_ReturnsNotFoundWithName ensures the
// stub-record branch in fetchLive surfaces the requested name in the
// error string. Regression: a previous version shadowed the outer
// `name` arg with the live record's empty Name, producing
// `MACHost "": not_found`.
func TestMACHost_Update_OnStubRecord_ReturnsNotFoundWithName(t *testing.T) {
	// Stub record: catalog Get parses it as a map with Name="" and
	// _diffHash injected; fetchLive must reject it as not_found while
	// preserving the requested name in the message.
	stub := map[string]any{"Name": "", "Type": "", "MACAddress": ""}
	s, fc, _ := newMACHostSvc(t, stub)
	body := map[string]any{"Name": "RequestedName", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	_, err := s.Update(context.Background(), "home", "RequestedName", body, "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Contains(t, err.Error(), `"RequestedName"`,
		"error message must include the requested name, not the empty live Name (shadowing regression)")
	require.NotContains(t, err.Error(), `""`,
		"error message must not show empty quotes")
	require.Empty(t, fc.sent)
}

// TestMACHost_Update_StripsInjectedDiffHashFromBody verifies that
// when a caller passes a body with `_diffHash` (e.g. the natural
// object_get → edit → update workflow, where ObjectSvc.Get injects it),
// the field is stripped before XML marshalling so it never appears in
// the envelope sent to the appliance.
func TestMACHost_Update_StripsInjectedDiffHashFromBody(t *testing.T) {
	live := map[string]any{"Name": "M1", "Type": "MACAddress", "MACAddress": "00:11:22:33:44:55"}
	hash, _ := DiffHash(live)
	s, fc, _ := newMACHostSvc(t, live)
	// Body mirrors what a user would pass after object_get — includes
	// the _diffHash key the catalog injected.
	body := map[string]any{
		"Name":       "M1",
		"Type":       "MACAddress",
		"MACAddress": "00:11:22:33:44:55",
		"_diffHash":  "abc123",
	}
	out, err := s.Update(context.Background(), "home", "M1", body, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash",
		"injected _diffHash must be stripped before XML marshal")
	require.NotContains(t, string(fc.sent[0]), "abc123",
		"diffHash value must not leak into the envelope")
}

// TestMACHost_Create_RejectsBothMACAndList verifies the client-side
// XOR validator rejects a body that sets both MACAddress and a
// non-empty MACAddressList — Sophos returns unhelpful errors here.
func TestMACHost_Create_RejectsBothMACAndList(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil)
	body := map[string]any{
		"Name":           "M1",
		"Type":           "MACAddress",
		"MACAddress":     "00:11:22:33:44:55",
		"MACAddressList": []any{"00:11:22:33:44:66"},
	}
	_, err := s.Create(context.Background(), "home", "M1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "exactly one")
	require.Empty(t, fc.sent)
}

// TestMACHost_Create_RejectsNeitherMACNorList verifies the XOR
// validator rejects a body that sets neither MACAddress nor
// MACAddressList.
func TestMACHost_Create_RejectsNeitherMACNorList(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil)
	body := map[string]any{
		"Name": "M1",
		"Type": "MACAddress",
	}
	_, err := s.Create(context.Background(), "home", "M1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "exactly one")
	require.Empty(t, fc.sent)
}

// TestMACHost_Create_AcceptsSingleMACAddress verifies the XOR
// validator accepts a body that sets only MACAddress (dry-run path
// avoids needing full apply mocking).
func TestMACHost_Create_AcceptsSingleMACAddress(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil)
	body := map[string]any{
		"Name":       "M1",
		"Type":       "MACAddress",
		"MACAddress": "00:11:22:33:44:55",
	}
	out, err := s.Create(context.Background(), "home", "M1", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.NotNil(t, out.Preview)
	require.Empty(t, fc.sent, "dry-run must not send")
}

// TestMACHost_Create_AcceptsMACAddressList verifies the XOR validator
// accepts a body that sets only MACAddressList (dry-run path).
func TestMACHost_Create_AcceptsMACAddressList(t *testing.T) {
	s, fc, _ := newMACHostSvc(t, nil)
	body := map[string]any{
		"Name":           "M1",
		"Type":           "MACList",
		"MACAddressList": []any{"00:11:22:33:44:55", "00:11:22:33:44:66"},
	}
	out, err := s.Create(context.Background(), "home", "M1", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.NotNil(t, out.Preview)
	require.Empty(t, fc.sent, "dry-run must not send")
}
