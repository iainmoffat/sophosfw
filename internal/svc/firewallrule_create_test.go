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
