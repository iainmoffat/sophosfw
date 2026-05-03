package svc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNATRuleSvc_New_FromTemplate(t *testing.T) {
	svc, _, baseDir := newNATSvcPull(t, nil)
	out, err := svc.New(context.Background(), "home", "MyNAT", "")
	require.NoError(t, err)
	require.Equal(t, "MyNAT", out.Rule)
	require.NotEmpty(t, out.DraftPath)
	require.Empty(t, out.SnapshotPath)
	require.Empty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Empty(t, d.DiffHash)
	require.Contains(t, string(d.Body), "Name: MyNAT")
	require.Contains(t, string(d.Body), "TranslatedSource: Original")

	snaps, err := draft.ListSnapshots(baseDir, "home", "nat", "MyNAT")
	require.NoError(t, err)
	require.Empty(t, snaps)
}

func TestNATRuleSvc_New_FromExisting(t *testing.T) {
	body := map[string]any{
		"Name":                   "OldNAT",
		"Status":                 "Enable",
		"IPFamily":               "IPv4",
		"OriginalSourceNetworks": map[string]any{"Network": "LAN"},
		"TranslatedSource":       "Original",
	}
	svc, _, _ := newNATSvcPull(t, body)
	out, err := svc.New(context.Background(), "home", "NewNAT", "OldNAT")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Contains(t, string(d.Body), "Name: NewNAT")
	require.NotContains(t, string(d.Body), "Name: OldNAT")
	require.Contains(t, string(d.Body), "Network: LAN")
}

func TestNATRuleSvc_New_FromExisting_DropsAfterBefore(t *testing.T) {
	body := map[string]any{
		"Name":     "OldNAT",
		"Status":   "Enable",
		"IPFamily": "IPv4",
		"After":    map[string]any{"Name": "SomeRule"},
		"Before":   map[string]any{"Name": "OtherRule"},
	}
	svc, _, _ := newNATSvcPull(t, body)
	out, err := svc.New(context.Background(), "home", "NewNAT", "OldNAT")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.NotContains(t, string(d.Body), "After:")
	require.NotContains(t, string(d.Body), "Before:")
}

func TestNATRuleSvc_New_RejectsExistingDraft(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "MyNAT", "")
	require.NoError(t, err)
	_, err = svc.New(context.Background(), "home", "MyNAT", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "draft already exists")
}

func TestNATRuleSvc_New_FromExistingNotFound(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "NewNAT", "Missing")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestNATRuleSvc_New_AuditLogged(t *testing.T) {
	svc, _, _ := newNATSvcPull(t, nil)
	_, err := svc.New(context.Background(), "home", "MyNAT", "")
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_new"`)
	require.Contains(t, string(logBody), `"objectName":"MyNAT"`)
}

func TestNATRuleSvc_New_RuleNameWithSpecialChars(t *testing.T) {
	cases := []string{
		"Rule:With:Colons",
		"Rule with spaces",
		"Rule\"With\"Quotes",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _, _ := newNATSvcPull(t, nil)
			out, err := svc.New(context.Background(), "home", name, "")
			require.NoError(t, err)
			d, err := draft.ReadDraft(out.DraftPath)
			require.NoError(t, err)
			var parsed map[string]any
			require.NoError(t, yaml.Unmarshal(d.Body, &parsed))
			require.Equal(t, name, parsed["Name"])
		})
	}
}

func TestNATRuleSvc_CreateInline_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		"OriginalSourceNetworks":      map[string]any{"Network": "Any"},
		"OriginalDestinationNetworks": map[string]any{"Network": "Any"},
		"TranslatedSource":            "Original",
		"TranslatedDestination":       "Original",
	}
	svc, fc, _ := newNATSvcPull(t, nil)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_CreateInline_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, body)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRuleSvc_CreateInline_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable",
		// IPFamily missing.
	}
	svc, fc, _ := newNATSvcPull(t, nil)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_CreateInline_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvcPull(t, nil)
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_CreateInline_AuditTagsCreate(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvcPull(t, body)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_create"`)
}
