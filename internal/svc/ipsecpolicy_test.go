// IPsecPolicy is dormant in v0.13.1 — Sophos 22.x XML API does not
// recognize the "IPsecPolicy" tag (probe returned "Input request module
// is Invalid"). The svc/CLI/MCP code is retained for future re-wiring
// once the correct tag name is discovered. These tests require the
// catalog entry to be present, so they are excluded from default builds
// behind the `ipsecpolicy_dormant` build tag. See Phase 15.x roadmap.

//go:build ipsecpolicy_dormant

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

// fakeIpsecPolicyClient is the test double for IPsecPolicySvc. It
// answers Get with a single canned record (when set) and records the
// raw envelopes sent via DoRaw so apply tests can assert the exact verb
// shape.
type fakeIpsecPolicyClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeIpsecPolicyClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "IPsecPolicy" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["IPsecPolicy"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeIpsecPolicyClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

// newIPsecPolicySvc constructs an IPsecPolicySvc backed by a fake
// client primed with `body` (the live IPsecPolicy record returned to
// Get calls). Returns the svc, the fake client (for sent-envelope
// assertions), and the audit dir for log assertions.
func newIPsecPolicySvc(t *testing.T, body map[string]any) (*IPsecPolicySvc, *fakeIpsecPolicyClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	fc := &fakeIpsecPolicyClient{body: body}
	s := &IPsecPolicySvc{
		Inner: &ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		},
		Audit: audit,
	}
	return s, fc, auditDir
}

func TestIPsecPolicy_Create_RejectsMissingRequiredField(t *testing.T) {
	s, fc, _ := newIPsecPolicySvc(t, nil)
	body := map[string]any{} // Name missing
	_, err := s.Create(context.Background(), "home", "P1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "Name")
	require.Empty(t, fc.sent)
}

func TestIPsecPolicy_Create_RejectsReadOnlyProfile(t *testing.T) {
	s, fc, _ := newIPsecPolicySvc(t, nil)
	p := s.Inner.Config.Profiles["home"]
	p.ReadOnly = true
	s.Inner.Config.Profiles["home"] = p

	body := map[string]any{"Name": "P1"}
	_, err := s.Create(context.Background(), "home", "P1", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestIPsecPolicy_Create_DryRun_EmitsPreview(t *testing.T) {
	s, fc, _ := newIPsecPolicySvc(t, nil)
	body := map[string]any{"Name": "P1"}
	out, err := s.Create(context.Background(), "home", "P1", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Equal(t, "IPsecPolicy", out.ObjectType)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestIPsecPolicy_Create_Apply_SendsAddEnvelope(t *testing.T) {
	body := map[string]any{"Name": "P1"}
	s, fc, _ := newIPsecPolicySvc(t, body)
	out, err := s.Create(context.Background(), "home", "P1", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<IPsecPolicy>`)
	require.Contains(t, string(fc.sent[0]), `<Name>P1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestIPsecPolicy_Update_RejectsMissingExpectedDiffHash(t *testing.T) {
	body := map[string]any{"Name": "P1"}
	s, fc, _ := newIPsecPolicySvc(t, body)
	_, err := s.Update(context.Background(), "home", "P1", body, "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestIPsecPolicy_Update_RejectsHashMismatch(t *testing.T) {
	body := map[string]any{"Name": "P1"}
	s, fc, _ := newIPsecPolicySvc(t, body)
	_, err := s.Update(context.Background(), "home", "P1", body, "definitely-not-the-real-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestIPsecPolicy_Update_DryRun_EmitsPreview(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := DiffHash(live)
	s, fc, _ := newIPsecPolicySvc(t, live)
	out, err := s.Update(context.Background(), "home", "P1", live, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.NotNil(t, out.Preview)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestIPsecPolicy_Update_Apply_SendsUpdateEnvelope(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := DiffHash(live)
	s, fc, _ := newIPsecPolicySvc(t, live)
	out, err := s.Update(context.Background(), "home", "P1", live, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<IPsecPolicy>`)
	require.Contains(t, string(fc.sent[0]), `<Name>P1</Name>`)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestIPsecPolicy_Delete_RejectsMissingExpectedDiffHash(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	s, fc, _ := newIPsecPolicySvc(t, live)
	_, err := s.Delete(context.Background(), "home", "P1", "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestIPsecPolicy_Delete_RejectsHashMismatch(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	s, fc, _ := newIPsecPolicySvc(t, live)
	_, err := s.Delete(context.Background(), "home", "P1", "wrong-hash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestIPsecPolicy_Delete_Apply_SendsRemoveEnvelope(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := DiffHash(live)
	s, fc, auditDir := newIPsecPolicySvc(t, live)
	out, err := s.Delete(context.Background(), "home", "P1", hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "delete", out.Operation)
	require.False(t, out.DryRun)
	require.Empty(t, out.NewDiffHash, "delete must not return a NewDiffHash")
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<IPsecPolicy>`)
	require.Contains(t, string(fc.sent[0]), `<Name>P1</Name>`)

	// Audit captured the delete with the canonical op name.
	logBody, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"ipsec_policy_delete"`)
	require.Contains(t, string(logBody), `"objectName":"P1"`)
}

func TestIPsecPolicy_Delete_OnMissing_ReturnsNotFound(t *testing.T) {
	s, fc, _ := newIPsecPolicySvc(t, nil) // nil body → Get returns not_found
	_, err := s.Delete(context.Background(), "home", "Missing", "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Empty(t, fc.sent)
}

// TestIPsecPolicy_Update_OnStubRecord_ReturnsNotFoundWithName ensures
// the stub-record branch in fetchLive surfaces the requested name in
// the error string. Regression: a previous version shadowed the outer
// `name` arg with the live record's empty Name, producing
// `IPsecPolicy "": not_found`.
func TestIPsecPolicy_Update_OnStubRecord_ReturnsNotFoundWithName(t *testing.T) {
	// Stub record: catalog Get parses it as a map with Name="" and
	// _diffHash injected; fetchLive must reject it as not_found while
	// preserving the requested name in the message.
	stub := map[string]any{"Name": ""}
	s, fc, _ := newIPsecPolicySvc(t, stub)
	body := map[string]any{"Name": "RequestedName"}
	_, err := s.Update(context.Background(), "home", "RequestedName", body, "anyhash", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
	require.Contains(t, err.Error(), `"RequestedName"`,
		"error message must include the requested name, not the empty live Name (shadowing regression)")
	require.NotContains(t, err.Error(), `""`,
		"error message must not show empty quotes")
	require.Empty(t, fc.sent)
}

// TestIPsecPolicy_Create_DoesNotMutateCallerBody is a regression guard
// for a parallel-preflight race. Phase 14 fan-out runs N preflight
// goroutines in parallel against the same body map. The svc-layer
// _diffHash strip used to call delete(body, …) on the caller's map,
// which under N parallel goroutines triggers Go's "concurrent map
// writes" runtime panic. The fix clones the body before the strip;
// this test asserts the caller's map is unchanged after Create.
func TestIPsecPolicy_Create_DoesNotMutateCallerBody(t *testing.T) {
	s, _, _ := newIPsecPolicySvc(t, nil)
	body := map[string]any{
		"Name":      "P1",
		"_diffHash": "abc",
	}
	bodyCopy := map[string]any{}
	for k, v := range body {
		bodyCopy[k] = v
	}

	_, err := s.Create(context.Background(), "home", "P1", body, true /* dryRun */)
	require.NoError(t, err)
	require.Equal(t, bodyCopy, body, "Create must not mutate the caller's body map")
}

// TestIPsecPolicy_Update_StripsInjectedDiffHashFromBody verifies that
// when a caller passes a body with `_diffHash` (e.g. the natural
// object_get → edit → update workflow, where ObjectSvc.Get injects it),
// the field is stripped before XML marshalling so it never appears in
// the envelope sent to the appliance.
func TestIPsecPolicy_Update_StripsInjectedDiffHashFromBody(t *testing.T) {
	live := map[string]any{"Name": "P1"}
	hash, _ := DiffHash(live)
	s, fc, _ := newIPsecPolicySvc(t, live)
	// Body mirrors what a user would pass after object_get — includes
	// the _diffHash key the catalog injected.
	body := map[string]any{
		"Name":      "P1",
		"_diffHash": "abc123",
	}
	out, err := s.Update(context.Background(), "home", "P1", body, hash, false, false)
	require.NoError(t, err)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash",
		"injected _diffHash must be stripped before XML marshal")
	require.NotContains(t, string(fc.sent[0]), "abc123",
		"diffHash value must not leak into the envelope")
}
