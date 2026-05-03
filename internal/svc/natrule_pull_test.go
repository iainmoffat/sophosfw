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
		"Name":     "DNAT-X",
		"Status":   "Enable",
		"IPFamily": "IPv4",
		"Position": "Top",
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
