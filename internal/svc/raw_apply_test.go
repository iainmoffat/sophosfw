package svc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func newRawApplyTestSvc(t *testing.T, readOnly bool, sendErr error) (*RawSvc, *fakeMutClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	_ = cat

	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444", ReadOnly: readOnly})

	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))

	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)

	fc := &fakeMutClient{}
	if sendErr != nil {
		fc.sendErr = sendErr
	}

	return &RawSvc{
		Config:    cfg,
		Creds:     store,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		Audit:     audit,
	}, fc, auditDir
}

func TestRawSvc_Apply_Success(t *testing.T) {
	s, fc, auditDir := newRawApplyTestSvc(t, false, nil)
	body := []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`)
	require.NoError(t, s.Apply(context.Background(), "home", body))
	require.Len(t, fc.sentEnvelopes, 1)

	logBody, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"raw_apply_mutating"`)
	require.Contains(t, string(logBody), `"result":"ok"`)
}

func TestRawSvc_Apply_NonMutating_LogsRawApply(t *testing.T) {
	s, _, auditDir := newRawApplyTestSvc(t, false, nil)
	body := []byte(`<Get><IPHost></IPHost></Get>`)
	require.NoError(t, s.Apply(context.Background(), "home", body))
	logBody, _ := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.Contains(t, string(logBody), `"operation":"raw_apply"`)
}

func TestRawSvc_Apply_RejectedOnReadOnlyProfile(t *testing.T) {
	s, fc, _ := newRawApplyTestSvc(t, true, nil)
	err := s.Apply(context.Background(), "home", []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`))
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sentEnvelopes)
}

func TestRawSvc_Apply_ReadOnlyProfile_AuditsRejection(t *testing.T) {
	s, fc, auditDir := newRawApplyTestSvc(t, true, nil)
	err := s.Apply(context.Background(), "home", []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`))
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sentEnvelopes)

	logBody, readErr := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, readErr)
	require.Contains(t, string(logBody), `"operation":"raw_apply"`)
	require.Contains(t, string(logBody), `"result":"error:read_only_violation"`)
}

func TestRawSvc_Apply_AuditLoggedOnFailure(t *testing.T) {
	s, _, auditDir := newRawApplyTestSvc(t, false, sophos.ErrServerError)
	body := []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`)
	err := s.Apply(context.Background(), "home", body)
	require.Error(t, err)
	logBody, _ := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.Contains(t, string(logBody), `"result":"error:server_error"`)
}
