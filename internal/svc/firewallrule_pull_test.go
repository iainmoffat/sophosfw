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

type fakeRuleClient struct {
	body    map[string]any
	sent    [][]byte
	sendErr error
}

func (f *fakeRuleClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "FirewallRule" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["FirewallRule"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeRuleClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sophos.Response{LoginOK: true}, nil
}

func newFwRuleSvc(t *testing.T, body map[string]any) (*FirewallRuleSvc, *fakeRuleClient, string) {
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
	fc := &fakeRuleClient{body: body}
	svc := &FirewallRuleSvc{
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

func TestFirewallRuleSvc_Pull_WritesSnapshotAndDraft(t *testing.T) {
	body := map[string]any{
		"Name":       "WAN-to-LAN",
		"Status":     "Enable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"NetworkPolicy": map[string]any{
			"Action":           "Accept",
			"SourceNetworks":   map[string]any{"Network": "LAN-network"},
			"DestinationZones": map[string]any{"Zone": "WAN"},
		},
	}
	svc, _, _ := newFwRuleSvc(t, body)

	out, err := svc.Pull(context.Background(), "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, "WAN-to-LAN", out.Rule)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "home", d.Profile)
	require.Equal(t, "WAN-to-LAN", d.Rule)
	require.Contains(t, string(d.Body), "Name: WAN-to-LAN")
	require.Contains(t, string(d.Body), "PolicyType: Network")

	allRefs := []string{}
	for _, rs := range out.References {
		allRefs = append(allRefs, rs.Type+":"+fmt.Sprint(rs.Names))
	}
	joined := strings.Join(allRefs, ",")
	require.Contains(t, joined, "LAN-network")
	require.Contains(t, joined, "WAN")
}

func TestFirewallRuleSvc_Pull_RuleNotFound(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil) // nil body → empty Body map → not_found
	_, err := svc.Pull(context.Background(), "home", "MissingRule")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestFirewallRuleSvc_Pull_OverwritesExistingDraft(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	_, err = svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	// Fixed Now → both pulls write to the same snapshot filename → 1 file.
	snaps, err := draft.ListSnapshots(baseDir, "home", "X")
	require.NoError(t, err)
	require.Len(t, snaps, 1)
}

func TestFirewallRuleSvc_Pull_RotatesOldSnapshots(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	for i := 0; i < 12; i++ {
		stamp := time.Date(2026, 5, 1, i, 0, 0, 0, time.UTC).Format("2006-01-02T15-04-05Z")
		path := filepath.Join(dir, "x-"+stamp+".yaml")
		require.NoError(t, os.WriteFile(path, []byte("# rule: X\n"), 0o600))
	}
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	snaps, err := draft.ListSnapshots(baseDir, "home", "X")
	require.NoError(t, err)
	require.LessOrEqual(t, len(snaps), 10)
}

func TestFirewallRuleSvc_Pull_AuditLogged(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_pull"`)
	require.Contains(t, string(logBody), `"objectType":"FirewallRule"`)
	require.Contains(t, string(logBody), `"objectName":"X"`)
}

func TestFirewallRuleSvc_Diff_NoChanges(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Diff(context.Background(), "home", "X")
	require.NoError(t, err)
	require.False(t, out.HasChanges)
	require.Empty(t, out.UnifiedDiff)
	require.Empty(t, out.StructuredDiff)
}

func TestFirewallRuleSvc_Diff_DetectsFieldChange(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
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

	var found bool
	for _, e := range out.StructuredDiff {
		if e.Path == "Status" {
			found = true
			require.Equal(t, "changed", e.Op)
			require.Equal(t, "Enable", e.OldValue)
			require.Equal(t, "Disable", e.NewValue)
		}
	}
	require.True(t, found, "Status change must appear in structured diff")
}

func TestFirewallRuleSvc_Diff_MissingSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		require.NoError(t, os.Remove(filepath.Join(dir, e.Name())))
	}
	_, err = svc.Diff(context.Background(), "home", "X")
	require.Error(t, err)
	require.True(t, errors.Is(err, draft.ErrSnapshotMissing))
}

func TestFirewallRuleSvc_Push_DryRun_NoSend(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, true) // ignoreHash=false, dryRun=true
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestFirewallRuleSvc_Push_Apply_RefetchAndArchive(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, false) // apply
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<FirewallRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)
}

func TestFirewallRuleSvc_Push_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Mutate the live body so the hash changes.
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent, "mismatch must reject before send")
}

func TestFirewallRuleSvc_Push_DiffHashMismatch_IgnoreFlag_Applies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", true, false) // ignoreHash=true
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
}

func TestFirewallRuleSvc_Push_HeaderRuleMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Rule = "DifferentName"
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_Push_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("PolicyType: Network\n"), nil)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "PolicyType")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_Push_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
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

func TestFirewallRuleSvc_Push_Failure_AuditLogged(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	fc.sendErr = sophos.ErrServerError

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_push"`)
	require.Contains(t, string(logBody), `"result":"error:server_error"`)
}

func TestFirewallRuleSvc_Push_RejectsMaliciousKeyInBody(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Inject a malicious key into the draft body.
	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	// Append a key with spaces (illegal in XML element names).
	d.Body = append(d.Body, []byte("\"name with spaces\": x\n")...)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Empty(t, fc.sent, "must not send envelope when XML tag is invalid")
}

func TestFirewallRuleSvc_Push_Apply_ArchivesNewSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	preCount, err := draft.ListSnapshots(baseDir, "home", "X")
	require.NoError(t, err)
	require.Len(t, preCount, 1, "Pull writes 1 snapshot")

	// Apply (no actual data change, but the apply flow should still archive
	// after refetch). Use injected Now so the new snapshot has a different
	// timestamp.
	svc.Now = func() time.Time {
		// Different time than the pull snapshot.
		return time.Date(2026, 5, 2, 16, 0, 0, 0, time.UTC)
	}
	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)

	postCount, err := draft.ListSnapshots(baseDir, "home", "X")
	require.NoError(t, err)
	require.Len(t, postCount, 2, "Push apply must archive a new snapshot")
}

func TestFirewallRuleSvc_Push_DiffHashMismatch_AuditsRejection(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Mutate the live body so the hash no longer matches the draft's stored hash.
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))

	logBody, readErr := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, readErr)
	// Two entries: one from Pull (ok) and one from Push (error).
	require.Contains(t, string(logBody), `"operation":"firewall_rule_push"`)
	require.Contains(t, string(logBody), `"objectName":"X"`)
	require.Contains(t, string(logBody), `"result":"error:diff_hash_mismatch"`)
}

func TestFirewallRuleSvc_Delete_DiffHashMismatch_AuditsRejection(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))

	logBody, readErr := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, readErr)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_delete"`)
	require.Contains(t, string(logBody), `"objectName":"X"`)
	require.Contains(t, string(logBody), `"result":"error:diff_hash_mismatch"`)
}

func TestFirewallRuleSvc_Delete_RequiresExpectedHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_Delete_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, baseDir := newFwRuleSvc(t, body)
	hash, err := DiffHash(body)
	require.NoError(t, err)

	out, err := svc.Delete(context.Background(), "home", "X", hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "delete", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<FirewallRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)

	// Verify a -deleted snapshot was archived.
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots")
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

func TestFirewallRuleSvc_Delete_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

// TestMarshalFirewallRule_NumericTypes covers the full numeric type
// coverage of writeKeyValue. Sophos rule bodies are normally string-typed
// in JSON, but a future caller could pass typed numeric values and we
// shouldn't error.
func TestMarshalFirewallRule_NumericTypes(t *testing.T) {
	rule := map[string]any{
		"Name":      "X",
		"IntVal":    int(42),
		"Int32Val":  int32(43),
		"Int64Val":  int64(44),
		"UintVal":   uint(45),
		"Uint32Val": uint32(46),
		"Uint64Val": uint64(47),
		"Float32":   float32(4.5),
		"Float64":   float64(5.5),
		"BoolVal":   true,
	}
	out, err := marshalFirewallRule(rule)
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "<IntVal>42</IntVal>")
	require.Contains(t, s, "<Int64Val>44</Int64Val>")
	require.Contains(t, s, "<UintVal>45</UintVal>")
	require.Contains(t, s, "<Uint64Val>47</Uint64Val>")
	require.Contains(t, s, "<Float64>5.5</Float64>")
	require.Contains(t, s, "<BoolVal>true</BoolVal>")
}
