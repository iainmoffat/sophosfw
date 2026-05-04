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

// fakeIpHostGroupClient is the test double for IPHostGroupSvc. It
// answers Get with a single canned record (when set) and records the
// raw envelopes sent via DoRaw so apply tests can assert the exact verb
// shape.
type fakeIpHostGroupClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeIpHostGroupClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "IPHostGroup" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["IPHostGroup"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeIpHostGroupClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

// newIPHostGroupSvc constructs an IPHostGroupSvc backed by a fake
// client primed with `body` (the live IPHostGroup record returned to
// Get calls). Returns the svc, the fake client (for sent-envelope
// assertions), and the audit dir for log assertions.
func newIPHostGroupSvc(t *testing.T, body map[string]any) (*IPHostGroupSvc, *fakeIpHostGroupClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	fc := &fakeIpHostGroupClient{body: body}
	s := &IPHostGroupSvc{
		Inner: &ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		},
		Audit: audit,
	}
	return s, fc, auditDir
}

func TestIPHostGroup_Create_RejectsMissingRequiredField(t *testing.T) {
	s, fc, _ := newIPHostGroupSvc(t, nil)
	body := map[string]any{"Name": "G1"} // IPFamily missing
	_, err := s.Create(context.Background(), "home", "G1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestIPHostGroup_Create_RejectsReadOnlyProfile(t *testing.T) {
	s, fc, _ := newIPHostGroupSvc(t, nil)
	p := s.Inner.Config.Profiles["home"]
	p.ReadOnly = true
	s.Inner.Config.Profiles["home"] = p

	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	_, err := s.Create(context.Background(), "home", "G1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestIPHostGroup_Create_DryRun_EmitsPreview(t *testing.T) {
	s, fc, _ := newIPHostGroupSvc(t, nil)
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	out, err := s.Create(context.Background(), "home", "G1", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Equal(t, "IPHostGroup", out.ObjectType)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestIPHostGroup_Create_Apply_SendsAddEnvelope(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, fc, _ := newIPHostGroupSvc(t, body)
	out, err := s.Create(context.Background(), "home", "G1", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<IPHostGroup>`)
	require.Contains(t, string(fc.sent[0]), `<Name>G1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestIPHostGroup_Update_RejectsMissingExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, fc, _ := newIPHostGroupSvc(t, body)
	_, err := s.Update(context.Background(), "home", "G1", body, "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestIPHostGroup_Update_RejectsHashMismatch(t *testing.T) {
	body := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, fc, _ := newIPHostGroupSvc(t, body)
	_, err := s.Update(context.Background(), "home", "G1", body, "definitely-not-the-real-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestIPHostGroup_Update_DryRun_EmitsPreview(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, _ := newIPHostGroupSvc(t, live)
	out, err := s.Update(context.Background(), "home", "G1", live, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.NotNil(t, out.Preview)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestIPHostGroup_Update_Apply_SendsUpdateEnvelope(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, _ := newIPHostGroupSvc(t, live)
	out, err := s.Update(context.Background(), "home", "G1", live, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<IPHostGroup>`)
	require.Contains(t, string(fc.sent[0]), `<Name>G1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestIPHostGroup_Delete_RejectsMissingExpectedDiffHash(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, fc, _ := newIPHostGroupSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "G1", "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestIPHostGroup_Delete_RejectsHashMismatch(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	s, fc, _ := newIPHostGroupSvc(t, live)
	_, err := s.Delete(context.Background(), "home", "G1", "wrong-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestIPHostGroup_Delete_Apply_SendsRemoveEnvelope(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, auditDir := newIPHostGroupSvc(t, live)
	out, err := s.Delete(context.Background(), "home", "G1", hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "delete", out.Operation)
	require.False(t, out.DryRun)
	require.Empty(t, out.NewDiffHash, "delete must not return a NewDiffHash")
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<IPHostGroup>`)
	require.Contains(t, string(fc.sent[0]), `<Name>G1</Name>`)

	// Audit captured the delete with the canonical op name.
	logBody, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"ip_host_group_delete"`)
	require.Contains(t, string(logBody), `"objectName":"G1"`)
}

func TestIPHostGroup_Delete_OnMissing_ReturnsNotFound(t *testing.T) {
	s, fc, _ := newIPHostGroupSvc(t, nil) // nil body → Get returns not_found
	_, err := s.Delete(context.Background(), "home", "Missing", "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Empty(t, fc.sent)
}

// TestIPHostGroup_Update_OnStubRecord_ReturnsNotFoundWithName ensures
// the stub-record branch in fetchLive surfaces the requested name in
// the error string. Regression: a previous version shadowed the outer
// `name` arg with the live record's empty Name, producing
// `IPHostGroup "": not_found`.
func TestIPHostGroup_Update_OnStubRecord_ReturnsNotFoundWithName(t *testing.T) {
	// Stub record: catalog Get parses it as a map with Name="" and
	// _diffHash injected; fetchLive must reject it as not_found while
	// preserving the requested name in the message.
	stub := map[string]any{"Name": "", "IPFamily": ""}
	s, fc, _ := newIPHostGroupSvc(t, stub)
	body := map[string]any{"Name": "RequestedName", "IPFamily": "IPv4"}
	_, err := s.Update(context.Background(), "home", "RequestedName", body, "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Contains(t, err.Error(), `"RequestedName"`,
		"error message must include the requested name, not the empty live Name (shadowing regression)")
	require.NotContains(t, err.Error(), `""`,
		"error message must not show empty quotes")
	require.Empty(t, fc.sent)
}

// TestIPHostGroup_Create_DoesNotMutateCallerBody is a regression guard
// for a parallel-preflight race. Phase 14 fan-out runs N preflight
// goroutines in parallel against the same body map. The svc-layer
// _diffHash strip used to call delete(body, …) on the caller's map,
// which under N parallel goroutines triggers Go's "concurrent map
// writes" runtime panic. The fix clones the body before the strip;
// this test asserts the caller's map is unchanged after Create.
func TestIPHostGroup_Create_DoesNotMutateCallerBody(t *testing.T) {
	s, _, _ := newIPHostGroupSvc(t, nil)
	body := map[string]any{
		"Name":      "G1",
		"IPFamily":  "IPv4",
		"_diffHash": "abc",
	}
	bodyCopy := map[string]any{}
	for k, v := range body {
		bodyCopy[k] = v
	}

	_, err := s.Create(context.Background(), "home", "G1", body, true /* dryRun */)
	require.NoError(t, err)
	require.Equal(t, bodyCopy, body, "Create must not mutate the caller's body map")
}

// TestIPHostGroup_Update_StripsInjectedDiffHashFromBody verifies that
// when a caller passes a body with `_diffHash` (e.g. the natural
// object_get → edit → update workflow, where ObjectSvc.Get injects it),
// the field is stripped before XML marshalling so it never appears in
// the envelope sent to the appliance.
func TestIPHostGroup_Update_StripsInjectedDiffHashFromBody(t *testing.T) {
	live := map[string]any{"Name": "G1", "IPFamily": "IPv4"}
	hash, _ := DiffHash(live)
	s, fc, _ := newIPHostGroupSvc(t, live)
	// Body mirrors what a user would pass after object_get — includes
	// the _diffHash key the catalog injected.
	body := map[string]any{
		"Name":      "G1",
		"IPFamily":  "IPv4",
		"_diffHash": "abc123",
	}
	out, err := s.Update(context.Background(), "home", "G1", body, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash",
		"injected _diffHash must be stripped before XML marshal")
	require.NotContains(t, string(fc.sent[0]), "abc123",
		"diffHash value must not leak into the envelope")
}
