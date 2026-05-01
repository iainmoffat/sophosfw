package svc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/stretchr/testify/require"
)

func TestHostIPSvc_Update_DiffHashMatch_Applies(t *testing.T) {
	current := json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)
	s, fc, auditDir := newCreateTestSvc(t, false, []json.RawMessage{current})

	hash, err := DiffHash(catalog.IPHost{
		Name: "LAN-network", IPFamily: "IPv4", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	})
	require.NoError(t, err)

	out, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.252.0",
	}, hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Len(t, fc.sentEnvelopes, 1)
	require.Contains(t, string(fc.sentEnvelopes[0]), `<Set operation="update">`)

	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"update"`)
	require.Contains(t, string(body), `"expectedDiffHash":"`+hash+`"`)
	require.Contains(t, string(body), `"result":"ok"`)
}

func TestHostIPSvc_Update_DiffHashMismatch(t *testing.T) {
	current := json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)
	s, fc, _ := newCreateTestSvc(t, false, []json.RawMessage{current})
	_, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.252.0",
	}, "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sentEnvelopes, "mismatch must reject before any send")
}

func TestHostIPSvc_Update_RequiresExpectedHash_WhenNotIgnored(t *testing.T) {
	current := json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)
	s, fc, _ := newCreateTestSvc(t, false, []json.RawMessage{current})
	_, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "IP", IPAddress: "1.1.1.1",
	}, "", false, false)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expectedDiffHash"))
	require.Empty(t, fc.sentEnvelopes)
}

func TestHostIPSvc_Update_IgnoreHash_AppliesWithoutFetch(t *testing.T) {
	s, fc, auditDir := newCreateTestSvc(t, false, []json.RawMessage{
		json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`),
	})
	_, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "IP", IPAddress: "9.9.9.9",
	}, "", true, false)
	require.NoError(t, err)
	require.Len(t, fc.sentEnvelopes, 1)

	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"expectedDiffHash":"ignored"`)
}

func TestHostIPSvc_Delete_DiffHashRequired(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, false, []json.RawMessage{
		json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`),
	})
	_, err := s.Delete(context.Background(), "home", "X", "", false, false)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expectedDiffHash"))
	require.Empty(t, fc.sentEnvelopes)
}

func TestHostIPSvc_Delete_Apply(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, err := DiffHash(current)
	require.NoError(t, err)
	s, fc, auditDir := newCreateTestSvc(t, false, []json.RawMessage{
		json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`),
	})
	out, err := s.Delete(context.Background(), "home", "X", hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Len(t, fc.sentEnvelopes, 1)
	require.Contains(t, string(fc.sentEnvelopes[0]), `<Remove>`)

	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"delete"`)
	require.Contains(t, string(body), `"objectName":"X"`)
}
