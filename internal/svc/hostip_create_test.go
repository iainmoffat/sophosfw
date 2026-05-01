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
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// fakeMutClient records sent envelopes and returns a canned response.
type fakeMutClient struct {
	sentEnvelopes [][]byte
	body          map[string][]json.RawMessage
	sendErr       error
}

func (f *fakeMutClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	// Build a placeholder envelope so tests can verify Set/Remove was attempted.
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		// Mutation path uses DoRaw, not Do. Refetch path uses Do.
		// Refetch returns the canned body keyed by "IPHost".
		if recs, ok := f.body["IPHost"]; ok {
			resp.Body["IPHost"] = recs
		}
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (f *fakeMutClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sentEnvelopes = append(f.sentEnvelopes, raw)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sophos.Response{LoginOK: true}, nil
}

func newCreateTestSvc(t *testing.T, readOnly bool, refetched []json.RawMessage) (*HostIPSvc, *fakeMutClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444", ReadOnly: readOnly})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	body := map[string][]json.RawMessage{"IPHost": refetched}
	fc := &fakeMutClient{body: body}
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
	}
	return &HostIPSvc{Inner: inner, Audit: audit}, fc, auditDir
}

func TestHostIPSvc_Create_DryRun(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, false, nil)
	out, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Contains(t, out.Preview.Verbs, "Set:add")
	require.Empty(t, fc.sentEnvelopes, "dry-run must not send the envelope")
}

func TestHostIPSvc_Create_Apply(t *testing.T) {
	refetched := []json.RawMessage{json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)}
	s, fc, auditDir := newCreateTestSvc(t, false, refetched)
	out, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.NotNil(t, out.Item)
	require.Equal(t, "LAN-network", out.Item.Name)
	require.Len(t, fc.sentEnvelopes, 1)
	require.Contains(t, string(fc.sentEnvelopes[0]), `<Set operation="add">`)

	// Audit log entry written
	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"create"`)
	require.Contains(t, string(body), `"objectName":"LAN-network"`)
	require.Contains(t, string(body), `"result":"ok"`)
}

func TestHostIPSvc_Create_RejectedOnReadOnlyProfile(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, true, nil)
	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "IP", IPAddress: "1.1.1.1",
	}, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation), "expected ErrReadOnlyViolation, got %v", err)
	require.Empty(t, fc.sentEnvelopes, "read-only pre-flight must reject before any send")
}

func TestHostIPSvc_Create_ValidationFailure_NetworkMissingSubnet(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, false, nil)
	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "Network", IPAddress: "10.0.0.0",
		// Subnet missing
	}, true)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.True(t, strings.Contains(err.Error(), "Subnet"))
	require.Empty(t, fc.sentEnvelopes)
}

func TestHostIPSvc_Create_ValidationFailure_BadHostType(t *testing.T) {
	s, _, _ := newCreateTestSvc(t, false, nil)
	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "Bogus",
	}, true)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}

func TestHostIPSvc_Create_DryRun_AuditLogged(t *testing.T) {
	s, _, auditDir := newCreateTestSvc(t, false, nil)
	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}, true)
	require.NoError(t, err)

	// Verify audit log contains dry-run result
	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"result":"ok (dry-run)"`)
	require.Contains(t, string(body), `"operation":"create"`)
}

func TestHostIPSvc_Create_Apply_AuditLoggedOnFailure(t *testing.T) {
	refetched := []json.RawMessage{json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)}
	s, fc, auditDir := newCreateTestSvc(t, false, refetched)

	// Configure the fake client to return an error
	testErr := errors.New("network error")
	fc.sendErr = testErr

	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}, false)
	require.Error(t, err)
	require.Equal(t, testErr, err)

	// Verify audit log contains error result
	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"result":"error:`)
	require.Contains(t, string(body), `"errorMessage"`)
}
