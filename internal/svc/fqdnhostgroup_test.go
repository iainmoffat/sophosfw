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

// fakeFqdnHostGroupClient is the test double for FQDNHostGroupSvc. It answers
// Get with a single canned record (when set) and records the raw
// envelopes sent via DoRaw so apply tests can assert the exact verb
// shape.
type fakeFqdnHostGroupClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeFqdnHostGroupClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "FQDNHostGroup" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["FQDNHostGroup"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeFqdnHostGroupClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

// newFQDNHostGroupSvc constructs an FQDNHostGroupSvc backed by a fake client
// primed with `body` (the live FQDNHostGroup record returned to Get calls).
// Returns the svc, the fake client (for sent-envelope assertions), and
// the audit dir for log assertions.
func newFQDNHostGroupSvc(t *testing.T, body map[string]any) (*FQDNHostGroupSvc, *fakeFqdnHostGroupClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	fc := &fakeFqdnHostGroupClient{body: body}
	s := &FQDNHostGroupSvc{
		Inner: &ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		},
		Audit: audit,
	}
	return s, fc, auditDir
}

func TestFQDNHostGroup_Create_RejectsMissingRequiredField(t *testing.T) {
	s, fc, _ := newFQDNHostGroupSvc(t, nil)
	body := map[string]any{"Name": "F1", "FQDN": "example.com"} // IPFamily missing
	_, err := s.Create(context.Background(), "home", "F1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroup_Create_RejectsReadOnlyProfile(t *testing.T) {
	s, fc, _ := newFQDNHostGroupSvc(t, nil)
	p := s.Inner.Config.Profiles["home"]
	p.ReadOnly = true
	s.Inner.Config.Profiles["home"] = p

	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	_, err := s.Create(context.Background(), "home", "F1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroup_Create_DryRun_EmitsPreview(t *testing.T) {
	s, fc, _ := newFQDNHostGroupSvc(t, nil)
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	out, err := s.Create(context.Background(), "home", "F1", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Equal(t, "FQDNHostGroup", out.ObjectType)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestFQDNHostGroup_Create_Apply_SendsAddEnvelope(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	s, fc, _ := newFQDNHostGroupSvc(t, body)
	out, err := s.Create(context.Background(), "home", "F1", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<FQDNHostGroup>`)
	require.Contains(t, string(fc.sent[0]), `<Name>F1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestFQDNHostGroup_Update_RejectsMissingExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	s, fc, _ := newFQDNHostGroupSvc(t, body)
	_, err := s.Update(context.Background(), "home", "F1", body, "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroup_Update_RejectsHashMismatch(t *testing.T) {
	body := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	s, fc, _ := newFQDNHostGroupSvc(t, body)
	_, err := s.Update(context.Background(), "home", "F1", body, "definitely-not-the-real-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroup_Update_DryRun_EmitsPreview(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, _ := newFQDNHostGroupSvc(t, live)
	out, err := s.Update(context.Background(), "home", "F1", live, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.NotNil(t, out.Preview)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestFQDNHostGroup_Update_Apply_SendsUpdateEnvelope(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, _ := newFQDNHostGroupSvc(t, live)
	out, err := s.Update(context.Background(), "home", "F1", live, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<FQDNHostGroup>`)
	require.Contains(t, string(fc.sent[0]), `<Name>F1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestFQDNHostGroup_Delete_RejectsMissingExpectedDiffHash(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	s, fc, _ := newFQDNHostGroupSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "F1", "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroup_Delete_RejectsHashMismatch(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	s, fc, _ := newFQDNHostGroupSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "F1", "wrong-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestFQDNHostGroup_Delete_Apply_SendsRemoveEnvelope(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, auditDir := newFQDNHostGroupSvc(t, live)
	out, err := s.Delete(context.Background(), "home", "F1", hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "delete", out.Operation)
	require.False(t, out.DryRun)
	require.Empty(t, out.NewDiffHash, "delete must not return a NewDiffHash")
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<FQDNHostGroup>`)
	require.Contains(t, string(fc.sent[0]), `<Name>F1</Name>`)

	// Audit captured the delete with the canonical op name.
	logBody, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"fqdn_host_group_delete"`)
	require.Contains(t, string(logBody), `"objectName":"F1"`)
}

func TestFQDNHostGroup_Delete_OnMissing_ReturnsNotFound(t *testing.T) {
	s, fc, _ := newFQDNHostGroupSvc(t, nil) // nil body → Get returns not_found
	_, err := s.Delete(context.Background(), "home", "Missing", "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Empty(t, fc.sent)
}

// TestFQDNHostGroup_Update_OnStubRecord_ReturnsNotFoundWithName ensures the
// stub-record branch in fetchLive surfaces the requested name in the
// error string. Regression: a previous version shadowed the outer
// `name` arg with the live record's empty Name, producing
// `FQDNHostGroup "": not_found`.
func TestFQDNHostGroup_Update_OnStubRecord_ReturnsNotFoundWithName(t *testing.T) {
	// Stub record: catalog Get parses it as a map with Name="" and
	// _diffHash injected; fetchLive must reject it as not_found while
	// preserving the requested name in the message.
	stub := map[string]any{"Name": "", "FQDN": "", "IPFamily": ""}
	s, fc, _ := newFQDNHostGroupSvc(t, stub)
	body := map[string]any{"Name": "RequestedName", "FQDN": "example.com", "IPFamily": "IPv4"}
	_, err := s.Update(context.Background(), "home", "RequestedName", body, "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Contains(t, err.Error(), `"RequestedName"`,
		"error message must include the requested name, not the empty live Name (shadowing regression)")
	require.NotContains(t, err.Error(), `""`,
		"error message must not show empty quotes")
	require.Empty(t, fc.sent)
}

// TestFQDNHostGroup_Update_StripsInjectedDiffHashFromBody verifies that
// when a caller passes a body with `_diffHash` (e.g. the natural
// object_get → edit → update workflow, where ObjectSvc.Get injects it),
// the field is stripped before XML marshalling so it never appears in
// the envelope sent to the appliance.
func TestFQDNHostGroup_Update_StripsInjectedDiffHashFromBody(t *testing.T) {
	live := map[string]any{"Name": "F1", "FQDN": "example.com", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, _ := newFQDNHostGroupSvc(t, live)
	// Body mirrors what a user would pass after object_get — includes
	// the _diffHash key the catalog injected.
	body := map[string]any{
		"Name":      "F1",
		"FQDN":      "example.com",
		"IPFamily":  "IPv4",
		"_diffHash": "abc123",
	}
	out, err := s.Update(context.Background(), "home", "F1", body, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash",
		"injected _diffHash must be stripped before XML marshal")
	require.NotContains(t, string(fc.sent[0]), "abc123",
		"diffHash value must not leak into the envelope")
}
