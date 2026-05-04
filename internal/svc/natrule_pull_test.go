package svc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type fakePullNATClient struct {
	body    map[string]any
	sent    [][]byte
	sendErr error
}

func (f *fakePullNATClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "NATRule" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["NATRule"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakePullNATClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sophos.Response{LoginOK: true}, nil
}

func newNATSvcPull(t *testing.T, body map[string]any) (*NATRuleSvc, *fakePullNATClient, string) {
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
	fc := &fakePullNATClient{body: body}
	svc := &NATRuleSvc{
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

func TestNATRuleSvc_Pull_WritesSnapshotAndDraft(t *testing.T) {
	body := map[string]any{
		"Name":                        "DNAT-X",
		"Status":                      "Enable",
		"IPFamily":                    "IPv4",
		"Position":                    "Top",
		"OriginalSourceNetworks":      map[string]any{"Network": "Any"},
		"OriginalDestinationNetworks": map[string]any{"Network": "#Port4"},
		"OriginalServices":            map[string]any{"Service": "HTTPS"},
		"TranslatedSource":            "Original",
		"TranslatedDestination":       "http-proxy01",
		"TranslatedService":           "Original",
		"LinkedFirewallrule":          "None",
	}
	svc, _, _ := newNATSvcPull(t, body)

	out, err := svc.Pull(context.Background(), "home", "DNAT-X")
	require.NoError(t, err)
	require.Equal(t, "DNAT-X", out.Rule)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)
	require.Contains(t, out.DraftPath, filepath.Join("drafts", "nat"))
	require.Contains(t, out.SnapshotPath, filepath.Join("snapshots", "nat"))

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "DNAT-X", d.Rule)
	require.Contains(t, string(d.Body), "Name: DNAT-X")
	// Regression: `_diffHash` is a sophosfw-internal field injected by
	// ObjectSvc.Get for catalog-mutable types. It must be stripped before
	// the draft is written so the on-disk YAML is hand-editable and never
	// round-trips into the push XML envelope.
	require.NotContains(t, string(d.Body), "_diffHash")

	allRefs := []string{}
	for _, rs := range out.References {
		allRefs = append(allRefs, rs.Type+":"+fmt.Sprint(rs.Names))
	}
	joined := strings.Join(allRefs, ",")
	require.Contains(t, joined, "#Port4")
	require.Contains(t, joined, "http-proxy01")
	require.Contains(t, joined, "HTTPS")
	require.Contains(t, joined, "Any")
	// Sentinels filtered out:
	require.NotContains(t, joined, "Original")
	require.NotContains(t, joined, "[None]")
}

func TestNATRuleSvc_Pull_RuleNotFound(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.Pull(context.Background(), "home", "Missing")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestNATRuleSvc_Pull_AuditLogged(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_pull"`)
	require.Contains(t, string(logBody), `"objectType":"NATRule"`)
}

func TestExtractNATReferences_AllFieldKinds(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
		"OriginalSourceNetworks":      map[string]any{"Network": []any{"A", "B"}},
		"OriginalDestinationNetworks": map[string]any{"Network": "C"},
		"OriginalServices":            map[string]any{"Service": "HTTP"},
		"TranslatedSource":            "src-translated",
		"TranslatedDestination":       "dst-translated",
		"TranslatedService":           "svc-translated",
		"LinkedFirewallrule":          "linked-rule",
		"InboundInterfaces":           map[string]any{"Interface": "Port4"},
	}
	refs := extractNATReferences(body)

	collect := func(kind string) []string {
		for _, r := range refs {
			if r.Type == kind {
				return r.Names
			}
		}
		return nil
	}

	ipHosts := collect("IPHost")
	require.Contains(t, ipHosts, "A")
	require.Contains(t, ipHosts, "B")
	require.Contains(t, ipHosts, "C")
	require.Contains(t, ipHosts, "src-translated")
	require.Contains(t, ipHosts, "dst-translated")

	services := collect("Service")
	require.Contains(t, services, "HTTP")
	require.Contains(t, services, "svc-translated")

	rules := collect("FirewallRule")
	require.Contains(t, rules, "linked-rule")

	ifaces := collect("Interface")
	require.Contains(t, ifaces, "Port4")
}

func TestExtractNATReferences_FiltersSentinels(t *testing.T) {
	body := map[string]any{
		"TranslatedSource":      "Original",
		"TranslatedDestination": "Original",
		"TranslatedService":     "Original",
		"LinkedFirewallrule":    "None",
	}
	refs := extractNATReferences(body)
	require.Empty(t, refs)
}

func TestNATRuleSvc_Push_DryRun_NoSend(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_Apply_RefetchAndArchive(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)
	// Regression: the sophosfw-internal `_diffHash` field must never
	// appear in the XML body sent to the appliance.
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

// TestNATRuleSvc_Push_StripsDiffHashFromHandEditedDraft is the defense-in-
// depth regression for parseAndValidateNATRuleBody: even if a draft on disk
// already has a `_diffHash` entry, the push must not include it in the XML
// envelope.
func TestNATRuleSvc_Push_StripsDiffHashFromHandEditedDraft(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = append(d.Body, []byte("_diffHash: deadbeef\n")...)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
	require.NotContains(t, string(fc.sent[0]), "_diffHash")
}

func TestNATRuleSvc_Push_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_DiffHashMismatch_IgnoreFlag_Applies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", true, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
}

func TestNATRuleSvc_Push_HeaderRuleMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Rule = "Different"
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("IPFamily: IPv4\n"), nil)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_Failure_AuditLogged(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.sendErr = sophos.ErrServerError

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_push"`)
	require.Contains(t, string(logBody), `"result":"error:server_error"`)
}

func TestMarshalNATRule_TagWrapper(t *testing.T) {
	rule := map[string]any{
		"Name": "X", "Status": "Enable",
	}
	out, err := marshalObjectBody("NATRule", rule)
	require.NoError(t, err)
	s := string(out)
	require.True(t, strings.HasPrefix(s, "<NATRule>"))
	require.True(t, strings.HasSuffix(s, "</NATRule>"))
	require.Contains(t, s, "<Name>X</Name>")
	require.Contains(t, s, "<Status>Enable</Status>")
}

func TestNATRuleSvc_Push_DiffHashMismatch_AuditsRejection(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_push"`)
	require.Contains(t, string(logBody), `"result":"error:diff_hash_mismatch"`)
}

func TestNATRuleSvc_Diff_NoChanges(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Diff(context.Background(), "home", "X")
	require.NoError(t, err)
	require.False(t, out.HasChanges)
	require.Empty(t, out.UnifiedDiff)
}

func TestNATRuleSvc_Diff_DetectsFieldChange(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("Status: Enable"), []byte("Status: Disable"))
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	out, err := svc.Diff(context.Background(), "home", "X")
	require.NoError(t, err)
	require.True(t, out.HasChanges)
	require.Contains(t, out.UnifiedDiff, "-Status: Enable")
	require.Contains(t, out.UnifiedDiff, "+Status: Disable")
}

func TestNATRuleSvc_Diff_MissingSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, baseDir := newNATSvcPull(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots", "nat")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		require.NoError(t, os.Remove(filepath.Join(dir, e.Name())))
	}
	_, err = svc.Diff(context.Background(), "home", "X")
	require.Error(t, err)
	require.True(t, errors.Is(err, draft.ErrSnapshotMissing))
}

func TestNATRuleSvc_Push_RejectsMaliciousKeyInBody(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Inject a key with spaces (invalid XML element name).
	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = append(d.Body, []byte(`"name with spaces": "x"`+"\n")...)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Empty(t, fc.sent, "must not send envelope when XML tag is invalid")
}

func TestNATRuleSvc_Delete_RequiresExpectedHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Delete_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, baseDir := newNATSvcPull(t, body)
	hash, err := DiffHash(body)
	require.NoError(t, err)

	out, err := svc.Delete(context.Background(), "home", "X", hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "delete", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)

	dir := filepath.Join(baseDir, "profiles", "home", "snapshots", "nat")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	hasDeleted := false
	for _, e := range entries {
		if strings.Contains(e.Name(), "-deleted") {
			hasDeleted = true
		}
	}
	require.True(t, hasDeleted)
}

func TestNATRuleSvc_Delete_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Delete_DiffHashMismatch_AuditsRejection(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_delete"`)
	require.Contains(t, string(logBody), `"result":"error:diff_hash_mismatch"`)
}

func TestNATRuleSvc_Push_CreateOperation_SendsAdd(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRuleSvc_Push_CreateOperation_SkipsDiffHashCheck(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	fc.body = map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	out, err := svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
}

func TestNATRuleSvc_Push_CreateOperation_FlipsDraftHeader(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	pull, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	d1, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d1.Operation)
	require.Empty(t, d1.DiffHash)

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	d2, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "update", d2.Operation)
	require.NotEmpty(t, d2.DiffHash)
	require.Regexp(t, `^[a-f0-9]{64}$`, d2.DiffHash)
}

func TestNATRuleSvc_Push_CreateOperation_WritesFirstSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, baseDir := newNATSvcPull(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	snaps0, err := draft.ListSnapshots(baseDir, "home", "nat", "X")
	require.NoError(t, err)
	require.Empty(t, snaps0)

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	snaps1, err := draft.ListSnapshots(baseDir, "home", "nat", "X")
	require.NoError(t, err)
	require.Len(t, snaps1, 1)
}

func TestNATRuleSvc_Push_CreateOperation_AuditTagsCreate(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)
	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_create"`)
}

func TestNATRuleSvc_Diff_CreateDraft_Errors(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "X", "")
	require.NoError(t, err)

	_, err = svc.Diff(context.Background(), "home", "X")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "no snapshot")
}

func TestNATRuleSvc_UpdateInline_DryRun(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "X", body, hash, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_UpdateInline_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	out, err := svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRuleSvc_UpdateInline_DiffHashMismatch_Rejects(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	_, err := svc.UpdateInline(context.Background(), "home", "X", body,
		"definitely-wrong-hash-0000000000000000000000000000000000000000",
		false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_UpdateInline_IgnoreHash_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	_, err := svc.UpdateInline(context.Background(), "home", "X", body, "", true, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
}

func TestNATRuleSvc_UpdateInline_RequiredFieldMissing_Rejects(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable",
		// IPFamily missing.
	}
	_, err = svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_UpdateInline_AuditTagsPush(t *testing.T) {
	live := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, live)
	hash, err := DiffHash(live)
	require.NoError(t, err)

	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	_, err = svc.UpdateInline(context.Background(), "home", "X", body, hash, false, false)
	require.NoError(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_push"`)
}
