package svc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeIPsecClient struct {
	body    map[string][]json.RawMessage
	sent    [][]byte
	sendErr error
}

func (f *fakeIPsecClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}

func (f *fakeIPsecClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sophos.Response{LoginOK: true}, nil
}

// newVPNIPsecSvc builds a read-only VPNIPsecSvc fixture (no draft dir,
// no audit log). Used by the original T2 read-side tests.
func newVPNIPsecSvc(t *testing.T, body map[string][]json.RawMessage) *VPNIPsecSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	fc := &fakeIPsecClient{body: body}
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
	}
	return &VPNIPsecSvc{Inner: inner}
}

// newVPNIPsecSvcFull builds a fully-wired VPNIPsecSvc fixture (with
// audit log, draft dir, fixed Now). Mirrors newFwRuleSvc. The fake
// client body is built from a single map[string]any record by JSON-
// marshaling it into the VPNIPsecConnection slot — match the
// fakeRuleClient ergonomics.
func newVPNIPsecSvcFull(t *testing.T, body map[string]any) (*VPNIPsecSvc, *fakeIPsecClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	baseDir := t.TempDir()

	fakeBody := map[string][]json.RawMessage{}
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		fakeBody["VPNIPsecConnection"] = []json.RawMessage{raw}
	}
	fc := &fakeIPsecClient{body: fakeBody}
	svc := &VPNIPsecSvc{
		Inner: &ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		},
		Audit:   audit,
		BaseDir: baseDir,
		Now:     func() time.Time { return time.Date(2026, 5, 2, 15, 30, 0, 0, time.UTC) },
	}
	return svc, fc, baseDir
}

// setIPsecBody updates the live body used by the fake client. Mirrors
// the fc.body[k] = v pattern of fakeRuleClient.
func setIPsecBody(t *testing.T, fc *fakeIPsecClient, body map[string]any) {
	t.Helper()
	if body == nil {
		fc.body = map[string][]json.RawMessage{}
		return
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	fc.body = map[string][]json.RawMessage{
		"VPNIPsecConnection": {raw},
	}
}

// =============================================================================
// T2 read-side tests (existing — kept verbatim).
// =============================================================================

func TestVPNIPsec_Get_ReturnsBody(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {
			json.RawMessage(`{"Name":"site-a","Status":"Enable","ConnectionType":"SiteToSite","AuthenticationType":"PresharedKey","Strategy":"Respond"}`),
		},
	}
	s := newVPNIPsecSvc(t, body)
	got, err := s.Get(context.Background(), "home", "site-a")
	require.NoError(t, err)
	require.Equal(t, "site-a", got["Name"])
	require.Equal(t, "Enable", got["Status"])
	require.Equal(t, "SiteToSite", got["ConnectionType"])
}

func TestVPNIPsec_Get_NotFound_ReturnsErrNotFound(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {},
	}
	s := newVPNIPsecSvc(t, body)
	_, err := s.Get(context.Background(), "home", "missing")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrNotFound)
}

func TestVPNIPsec_Get_InjectsDiffHash(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {
			json.RawMessage(`{"Name":"site-a","Status":"Enable","ConnectionType":"SiteToSite"}`),
		},
	}
	s := newVPNIPsecSvc(t, body)
	got, err := s.Get(context.Background(), "home", "site-a")
	require.NoError(t, err)
	hash, ok := got["_diffHash"]
	require.True(t, ok, "_diffHash should be injected for mutable catalog entries")
	require.NotEmpty(t, hash)
}

// =============================================================================
// T3 — New (template + --from + rejection paths).
// =============================================================================

func TestVPNIPsec_New_FromTemplate(t *testing.T) {
	svc, _, baseDir := newVPNIPsecSvcFull(t, nil)
	out, err := svc.New(context.Background(), "home", "site-a", "")
	require.NoError(t, err)
	require.Equal(t, "site-a", out.Tunnel)
	require.NotEmpty(t, out.DraftPath)
	require.Empty(t, out.SnapshotPath)
	require.Empty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Empty(t, d.DiffHash)
	require.Contains(t, string(d.Body), "Name: site-a")
	require.Contains(t, string(d.Body), "Status: Disable")
	require.Contains(t, string(d.Body), "ConnectionType: SiteToSite")

	snaps, err := draft.ListSnapshots(baseDir, "home", "vpn", "site-a")
	require.NoError(t, err)
	require.Empty(t, snaps)
}

func TestVPNIPsec_New_FromExisting(t *testing.T) {
	body := map[string]any{
		"Name":               "old-tunnel",
		"Status":             "Enable",
		"ConnectionType":     "SiteToSite",
		"AuthenticationType": "PresharedKey",
		"Strategy":           "Respond",
	}
	svc, _, _ := newVPNIPsecSvcFull(t, body)
	out, err := svc.New(context.Background(), "home", "new-tunnel", "old-tunnel")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Contains(t, string(d.Body), "Name: new-tunnel")
	require.NotContains(t, string(d.Body), "Name: old-tunnel")
	require.Contains(t, string(d.Body), "AuthenticationType: PresharedKey")
	require.Contains(t, string(d.Body), "Strategy: Respond")
	// Phase 13.x regression: --from copy must drop _diffHash too.
	require.NotContains(t, string(d.Body), "_diffHash")
}

func TestVPNIPsec_New_RejectsExistingDraft(t *testing.T) {
	svc, _, _ := newVPNIPsecSvcFull(t, nil)
	_, err := svc.New(context.Background(), "home", "site-a", "")
	require.NoError(t, err)
	_, err = svc.New(context.Background(), "home", "site-a", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "draft already exists")
}

func TestVPNIPsec_New_RejectsFromMissing(t *testing.T) {
	svc, _, _ := newVPNIPsecSvcFull(t, nil)
	_, err := svc.New(context.Background(), "home", "new-tunnel", "missing-tunnel")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

// =============================================================================
// T3 — Pull.
// =============================================================================

func TestVPNIPsec_Pull_WritesSnapshotAndDraft(t *testing.T) {
	body := map[string]any{
		"Name":           "site-a",
		"Status":         "Enable",
		"ConnectionType": "SiteToSite",
	}
	svc, _, _ := newVPNIPsecSvcFull(t, body)
	out, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)
	require.Equal(t, "site-a", out.Tunnel)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "home", d.Profile)
	require.Equal(t, "site-a", d.Rule)
	require.Contains(t, string(d.Body), "Name: site-a")
	require.Contains(t, string(d.Body), "ConnectionType: SiteToSite")
}

// TestVPNIPsec_Pull_StripsDiffHashFromDraft is the Phase 13.x regression
// guard: ObjectSvc.Get injects `_diffHash` for catalog-mutable types,
// but the on-disk draft must never carry it.
func TestVPNIPsec_Pull_StripsDiffHashFromDraft(t *testing.T) {
	body := map[string]any{
		"Name":           "site-a",
		"Status":         "Enable",
		"ConnectionType": "SiteToSite",
	}
	svc, _, _ := newVPNIPsecSvcFull(t, body)
	out, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.NotContains(t, string(d.Body), "_diffHash",
		"Pull must strip _diffHash before writing the draft to disk")
}

func TestVPNIPsec_Pull_RejectsMissingTunnel(t *testing.T) {
	svc, _, _ := newVPNIPsecSvcFull(t, nil) // nil body → empty Body map → not_found
	_, err := svc.Pull(context.Background(), "home", "missing-tunnel")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

// =============================================================================
// T3 — Diff.
// =============================================================================

func TestVPNIPsec_Diff_NoDraft_Empty(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, _, _ := newVPNIPsecSvcFull(t, body)
	_, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)

	out, err := svc.Diff(context.Background(), "home", "site-a")
	require.NoError(t, err)
	require.False(t, out.HasChanges)
	require.Empty(t, out.UnifiedDiff)
	require.Empty(t, out.StructuredDiff)
}

func TestVPNIPsec_Diff_DraftDiffersFromSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, _, _ := newVPNIPsecSvcFull(t, body)
	pull, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("Status: Enable"), []byte("Status: Disable"))
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	out, err := svc.Diff(context.Background(), "home", "site-a")
	require.NoError(t, err)
	require.True(t, out.HasChanges)
	require.Contains(t, out.UnifiedDiff, "-Status: Enable")
	require.Contains(t, out.UnifiedDiff, "+Status: Disable")
}

// =============================================================================
// T3 — Push (draft-based).
// =============================================================================

func TestVPNIPsec_Push_RejectsMissingDraft(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, body)
	_, err := svc.Push(context.Background(), "home", "site-a", "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, draft.ErrDraftMissing))
	require.Empty(t, fc.sent)
}

func TestVPNIPsec_Push_RejectsHashMismatch(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, body)
	_, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)

	// Mutate the live body so the hash changes.
	setIPsecBody(t, fc, map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	})

	_, err = svc.Push(context.Background(), "home", "site-a", "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent, "mismatch must reject before send")
}

func TestVPNIPsec_Push_DryRun_EmitsPreview(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, body)
	_, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "site-a", "", false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestVPNIPsec_Push_Apply_RefetchAndArchive(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, baseDir := newVPNIPsecSvcFull(t, body)
	_, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)

	preCount, err := draft.ListSnapshots(baseDir, "home", "vpn", "site-a")
	require.NoError(t, err)
	require.Len(t, preCount, 1, "Pull writes 1 snapshot")

	// Bump Now so the new snapshot has a different timestamp.
	svc.Now = func() time.Time { return time.Date(2026, 5, 2, 16, 0, 0, 0, time.UTC) }

	out, err := svc.Push(context.Background(), "home", "site-a", "", false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<VPNIPsecConnection>`)
	require.Contains(t, string(fc.sent[0]), `<Name>site-a</Name>`)
	// Regression: the sophosfw-internal `_diffHash` field must never
	// appear in the XML body sent to the appliance.
	require.NotContains(t, string(fc.sent[0]), "_diffHash")

	postCount, err := draft.ListSnapshots(baseDir, "home", "vpn", "site-a")
	require.NoError(t, err)
	require.Len(t, postCount, 2, "Push apply must archive a new snapshot")
}

// TestVPNIPsec_Push_StripsDiffHashFromHandEditedDraft is the defense-
// in-depth regression for parseAndValidateVPNIPsecBody: even if a
// draft on disk already has a `_diffHash` entry (e.g. left over from
// before the Pull-side fix, or hand-edited in by a user), the push
// must not include it in the XML envelope.
func TestVPNIPsec_Push_StripsDiffHashFromHandEditedDraft(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, body)
	pull, err := svc.Pull(context.Background(), "home", "site-a")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = append(d.Body, []byte("_diffHash: deadbeef\n")...)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "site-a", "", false, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

// =============================================================================
// T3 — CreateInline.
// =============================================================================

func TestVPNIPsec_CreateInline_RejectsMissingRequiredField(t *testing.T) {
	body := map[string]any{
		"Name":   "site-a",
		"Status": "Disable",
		// ConnectionType missing.
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, nil)
	_, err := svc.CreateInline(context.Background(), "home", "site-a", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "ConnectionType")
	require.Empty(t, fc.sent)
}

func TestVPNIPsec_CreateInline_RejectsReadOnlyProfile(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, nil)
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err := svc.CreateInline(context.Background(), "home", "site-a", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestVPNIPsec_CreateInline_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, nil)
	out, err := svc.CreateInline(context.Background(), "home", "site-a", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestVPNIPsec_CreateInline_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, body)
	out, err := svc.CreateInline(context.Background(), "home", "site-a", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<VPNIPsecConnection>`)
	require.Contains(t, string(fc.sent[0]), `<Name>site-a</Name>`)
}

// =============================================================================
// T3 — UpdateInline.
// =============================================================================

func TestVPNIPsec_UpdateInline_RejectsMissingExpectedDiffHash(t *testing.T) {
	live := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, live)

	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	_, err := svc.UpdateInline(context.Background(), "home", "site-a", body, "", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestVPNIPsec_UpdateInline_DryRun(t *testing.T) {
	live := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "site-a", body, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Empty(t, fc.sent)
}

func TestVPNIPsec_UpdateInline_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "site-a", body, hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<VPNIPsecConnection>`)
}

// TestVPNIPsec_UpdateInline_StripsInjectedDiffHashFromBody is the
// Phase 13.x regression for the body-as-map path: if the caller passes
// a body that still has `_diffHash` (typical of an object_get → edit →
// update flow), the marshaled XML must not contain it.
func TestVPNIPsec_UpdateInline_StripsInjectedDiffHashFromBody(t *testing.T) {
	live := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name":           "site-a",
		"Status":         "Disable",
		"ConnectionType": "SiteToSite",
		"_diffHash":      "deadbeef",
	}
	_, err = svc.UpdateInline(context.Background(), "home", "site-a", body, hash, false, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

// =============================================================================
// T3 — Delete.
// =============================================================================

func TestVPNIPsec_Delete_RejectsMissingExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, _ := newVPNIPsecSvcFull(t, body)
	_, err := svc.Delete(context.Background(), "home", "site-a", "", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestVPNIPsec_Delete_DiffHashMatch_Applies(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, fc, baseDir := newVPNIPsecSvcFull(t, body)
	hash, err := DiffHash(body)
	require.NoError(t, err)

	out, err := svc.Delete(context.Background(), "home", "site-a", hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "delete", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<VPNIPsecConnection>`)
	require.Contains(t, string(fc.sent[0]), `<Name>site-a</Name>`)

	// Verify a -deleted snapshot was archived.
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots", "vpn")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	hasDeleted := false
	for _, e := range entries {
		if strings.Contains(e.Name(), "-deleted") {
			hasDeleted = true
		}
	}
	require.True(t, hasDeleted, "expected a -deleted snapshot")
}

// =============================================================================
// T3 — Phase 14 body-clone regression guards.
// =============================================================================

// TestVPNIPsec_Create_DoesNotMutateCallerBody asserts the caller's
// body map is unchanged after CreateInline. Phase 14 fan-out runs N
// preflight goroutines in parallel against the same body; svc-layer
// `delete(body, "_diffHash")` on the caller's map would trip Go's
// "concurrent map writes" runtime panic. The fix clones the body
// before the strip; this test asserts the body is intact afterward.
func TestVPNIPsec_Create_DoesNotMutateCallerBody(t *testing.T) {
	svc, _, _ := newVPNIPsecSvcFull(t, nil)
	body := map[string]any{
		"Name":           "site-a",
		"Status":         "Disable",
		"ConnectionType": "SiteToSite",
		"_diffHash":      "abc",
	}
	bodyCopy := map[string]any{}
	for k, v := range body {
		bodyCopy[k] = v
	}

	_, err := svc.CreateInline(context.Background(), "home", "site-a", body, true /* dryRun */)
	require.NoError(t, err)
	require.Equal(t, bodyCopy, body, "CreateInline must not mutate the caller's body map")
}

// TestVPNIPsec_Update_DoesNotMutateCallerBody — UpdateInline mirror of
// the body-clone regression.
func TestVPNIPsec_Update_DoesNotMutateCallerBody(t *testing.T) {
	live := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	svc, _, _ := newVPNIPsecSvcFull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name":           "site-a",
		"Status":         "Disable",
		"ConnectionType": "SiteToSite",
		"_diffHash":      "abc",
	}
	bodyCopy := map[string]any{}
	for k, v := range body {
		bodyCopy[k] = v
	}

	_, err = svc.UpdateInline(context.Background(), "home", "site-a", body, hash, false, true /* dryRun */)
	require.NoError(t, err)
	require.Equal(t, bodyCopy, body, "UpdateInline must not mutate the caller's body map")
}
