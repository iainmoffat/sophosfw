package svc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func TestFirewallRuleSvc_New_FromTemplate(t *testing.T) {
	svc, _, baseDir := newFwRuleSvc(t, nil)
	out, err := svc.New(context.Background(), "home", "MyRule", "")
	require.NoError(t, err)
	require.Equal(t, "MyRule", out.Rule)
	require.NotEmpty(t, out.DraftPath)
	require.Empty(t, out.SnapshotPath)
	require.Empty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Empty(t, d.DiffHash)
	require.Contains(t, string(d.Body), "Name: MyRule")
	require.Contains(t, string(d.Body), "Action: Drop")

	snaps, err := draft.ListSnapshots(baseDir, "home", "firewall", "MyRule")
	require.NoError(t, err)
	require.Empty(t, snaps)
}

func TestFirewallRuleSvc_New_FromExisting(t *testing.T) {
	body := map[string]any{
		"Name":       "OldRule",
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
	out, err := svc.New(context.Background(), "home", "NewRule", "OldRule")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "create", d.Operation)
	require.Contains(t, string(d.Body), "Name: NewRule")
	require.NotContains(t, string(d.Body), "Name: OldRule")
	require.Contains(t, string(d.Body), "Action: Accept")
	require.Contains(t, string(d.Body), "LAN-network")
}

func TestFirewallRuleSvc_New_FromExisting_DropsAfterBefore(t *testing.T) {
	body := map[string]any{
		"Name":       "OldRule",
		"Status":     "Enable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"After":      map[string]any{"Name": "SomeRule"},
		"Before":     map[string]any{"Name": "OtherRule"},
	}
	svc, _, _ := newFwRuleSvc(t, body)
	out, err := svc.New(context.Background(), "home", "NewRule", "OldRule")
	require.NoError(t, err)

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.NotContains(t, string(d.Body), "After:")
	require.NotContains(t, string(d.Body), "Before:")
}

func TestFirewallRuleSvc_New_RejectsExistingDraft(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil)
	_, err := svc.New(context.Background(), "home", "MyRule", "")
	require.NoError(t, err)
	_, err = svc.New(context.Background(), "home", "MyRule", "")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "draft already exists")
}

func TestFirewallRuleSvc_New_FromExistingNotFound(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil)
	_, err := svc.New(context.Background(), "home", "NewRule", "Missing")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestFirewallRuleSvc_New_AuditLogged(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil)
	_, err := svc.New(context.Background(), "home", "MyRule", "")
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_new"`)
	require.Contains(t, string(logBody), `"objectName":"MyRule"`)
}

func TestFirewallRuleSvc_New_RuleNameWithSpecialChars(t *testing.T) {
	cases := []string{
		"Rule:With:Colons",
		"Rule with spaces",
		"Rule\"With\"Quotes",
		"Rule'With'Apostrophes",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _, _ := newFwRuleSvc(t, nil)
			out, err := svc.New(context.Background(), "home", name, "")
			require.NoError(t, err)
			d, err := draft.ReadDraft(out.DraftPath)
			require.NoError(t, err)
			// Body must be parseable YAML and contain the literal rule name
			// somewhere (yaml.Marshal will properly quote/escape).
			require.NotEmpty(t, d.Body)
			// The rule name must round-trip through yaml unmarshal cleanly.
			var parsed map[string]any
			require.NoError(t, yaml.Unmarshal(d.Body, &parsed))
			require.Equal(t, name, parsed["Name"])
		})
	}
}

func TestFirewallRuleSvc_CreateInline_DryRun(t *testing.T) {
	body := map[string]any{
		"Name":       "X",
		"Status":     "Disable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"NetworkPolicy": map[string]any{
			"Action":         "Drop",
			"SourceNetworks": map[string]any{"Network": "Russian Federation"},
		},
	}
	svc, fc, _ := newFwRuleSvc(t, nil)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestFirewallRuleSvc_CreateInline_Apply(t *testing.T) {
	body := map[string]any{
		"Name":       "X",
		"Status":     "Disable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"NetworkPolicy": map[string]any{
			"Action":         "Drop",
			"SourceNetworks": map[string]any{"Network": "Russian Federation"},
		},
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	out, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "create", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
	require.Contains(t, string(fc.sent[0]), `<FirewallRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)
}

func TestFirewallRuleSvc_CreateInline_Apply_WritesFirstSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	snaps0, err := draft.ListSnapshots(baseDir, "home", "firewall", "X")
	require.NoError(t, err)
	require.Empty(t, snaps0)

	_, err = svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)

	snaps1, err := draft.ListSnapshots(baseDir, "home", "firewall", "X")
	require.NoError(t, err)
	require.Len(t, snaps1, 1)
}

func TestFirewallRuleSvc_CreateInline_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4",
		// PolicyType missing.
	}
	svc, fc, _ := newFwRuleSvc(t, nil)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.Contains(t, err.Error(), "PolicyType")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_CreateInline_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, nil)
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_CreateInline_AuditTagsCreate(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Disable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.CreateInline(context.Background(), "home", "X", body, false)
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_create"`)
}
