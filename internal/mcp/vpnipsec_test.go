package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

func TestVPNIPsecList_Handler_ReturnsRecords(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {json.RawMessage(`{"Name":"site-a","Status":"Disable","ConnectionType":"SiteToSite"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleVPNIPsecList(context.Background(), nil, VPNIPsecListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.vpnIPsecList"`)
	require.Contains(t, body2, `"xmlTag": "VPNIPsecConnection"`)
	require.Contains(t, body2, `"Name": "site-a"`)
}

func TestVPNIPsecShow_Handler_InjectsDiffHash(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {json.RawMessage(`{"Name":"site-a","Status":"Disable","ConnectionType":"SiteToSite"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleVPNIPsecShow(context.Background(), nil, VPNIPsecShowInput{Name: "site-a"})
	require.NoError(t, err)
	text := textOf(out)
	require.Contains(t, text, `"schema": "sophosfw.v1.vpnIPsec"`)
	require.Contains(t, text, `"_diffHash":`)
}

func TestVPNIPsecCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleVPNIPsecCreate(context.Background(), nil, VPNIPsecCreateInput{
		Name: "site-a",
		Body: map[string]any{
			"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
		},
		Confirm: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestVPNIPsecCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleVPNIPsecCreate(context.Background(), nil, VPNIPsecCreateInput{
		Name: "site-a",
		Body: map[string]any{
			"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
		},
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestVPNIPsecCreate_Handler_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNIPsecConnection": {mustJSON(t, body)},
	})
	out, _, err := s.handleVPNIPsecCreate(context.Background(), nil, VPNIPsecCreateInput{
		Name: "site-a", Body: body, Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.vpnIPsecPush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
}

func TestVPNIPsecUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNIPsecConnection": {mustJSON(t, body)},
	})
	out, _, err := s.handleVPNIPsecUpdate(context.Background(), nil, VPNIPsecUpdateInput{
		Name: "site-a", Body: body, Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestVPNIPsecUpdate_Handler_DryRun(t *testing.T) {
	body := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	hash, _ := svc.DiffHash(body)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNIPsecConnection": {mustJSON(t, body)},
	})
	out, _, err := s.handleVPNIPsecUpdate(context.Background(), nil, VPNIPsecUpdateInput{
		Name: "site-a", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestVPNIPsecUpdate_Handler_Apply(t *testing.T) {
	live := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNIPsecConnection": {mustJSON(t, live)},
	})
	body := map[string]any{
		"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
	}
	out, _, err := s.handleVPNIPsecUpdate(context.Background(), nil, VPNIPsecUpdateInput{
		Name: "site-a", Body: body,
		ExpectedDiffHash: hash,
		Confirm:          true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.vpnIPsecPush"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestVPNIPsecDelete_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleVPNIPsecDelete(context.Background(), nil, VPNIPsecDeleteInput{
		Name:    "site-a",
		Confirm: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestVPNIPsecDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	live := map[string]any{
		"Name": "site-a", "Status": "Enable", "ConnectionType": "SiteToSite",
	}
	hash, _ := svc.DiffHash(live)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"VPNIPsecConnection": {mustJSON(t, live)},
	})
	out, _, err := s.handleVPNIPsecDelete(context.Background(), nil, VPNIPsecDeleteInput{
		Name:             "site-a",
		ExpectedDiffHash: hash,
		Confirm:          true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.vpnIPsecPush"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
}

func TestVPNIPsecCreate_Handler_FanOut_TwoProfiles(t *testing.T) {
	body := map[string][]json.RawMessage{
		"VPNIPsecConnection": {json.RawMessage(`{"Name":"site-a","Status":"Disable","ConnectionType":"SiteToSite"}`)},
	}
	s, _ := newMutMcpServerFanout(t, body)
	out, _, err := s.handleVPNIPsecCreate(context.Background(), nil, VPNIPsecCreateInput{
		ProfileSet: "home,office",
		Name:       "site-a",
		Body: map[string]any{
			"Name": "site-a", "Status": "Disable", "ConnectionType": "SiteToSite",
		},
		Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	requireFanoutOK(t, textOf(out), "vpn_ipsec_create")
}
