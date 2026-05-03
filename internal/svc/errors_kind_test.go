package svc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func TestErrorKind_Sentinels(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{sophos.ErrAuthFailed, "auth_failed"},
		{sophos.ErrNotFound, "not_found"},
		{sophos.ErrPermissionDenied, "permission_denied"},
		{sophos.ErrInvalidRequest, "invalid_request"},
		{sophos.ErrServerError, "server_error"},
		{sophos.ErrReadOnlyViolation, "read_only_violation"},
		{ErrUnsupportedInPhase, "unsupported_in_phase"},
		{ErrCatalogUnknownTag, "invalid_request"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, ErrorKind(c.err), "err=%v", c.err)
	}
}

func TestErrorKind_WrappedSentinel(t *testing.T) {
	wrapped := fmt.Errorf("operation failed: %w", sophos.ErrNotFound)
	require.Equal(t, "not_found", ErrorKind(wrapped))
}

func TestErrorKind_TLS(t *testing.T) {
	err := errors.New("tls: handshake failed")
	require.Equal(t, "tls_error", ErrorKind(err))
}

func TestErrorKind_Generic(t *testing.T) {
	err := errors.New("something weird happened")
	require.Equal(t, "generic", ErrorKind(err))
}

func TestErrorKind_Nil(t *testing.T) {
	require.Equal(t, "", ErrorKind(nil))
}

func TestErrorKind_DraftMissing(t *testing.T) {
	require.Equal(t, "not_found", ErrorKind(ErrDraftMissing))
}

func TestErrorKind_SnapshotMissing(t *testing.T) {
	require.Equal(t, "not_found", ErrorKind(ErrSnapshotMissing))
}
