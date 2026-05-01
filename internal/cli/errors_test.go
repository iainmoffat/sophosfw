package cli

import (
	"errors"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestErrorKind_AuthFailed(t *testing.T) {
	k := ErrorKind(sophos.ErrAuthFailed)
	require.Equal(t, "auth_failed", k)
	require.Equal(t, 3, ExitCodeFor(k))
}

func TestErrorKind_NotFound(t *testing.T) {
	require.Equal(t, "not_found", ErrorKind(sophos.ErrNotFound))
}

func TestErrorKind_PermissionDenied(t *testing.T) {
	require.Equal(t, "permission_denied", ErrorKind(sophos.ErrPermissionDenied))
}

func TestErrorKind_ReadOnlyViolation(t *testing.T) {
	k := ErrorKind(sophos.ErrReadOnlyViolation)
	require.Equal(t, "read_only_violation", k)
	require.Equal(t, 4, ExitCodeFor(k))
}

func TestErrorKind_UnsupportedInPhase(t *testing.T) {
	k := ErrorKind(svc.ErrUnsupportedInPhase)
	require.Equal(t, "unsupported_in_phase", k)
	require.Equal(t, 6, ExitCodeFor(k))
}

func TestErrorKind_CatalogUnknown(t *testing.T) {
	require.Equal(t, "invalid_request", ErrorKind(svc.ErrCatalogUnknownTag))
}

func TestErrorKind_GenericFallback(t *testing.T) {
	require.Equal(t, "generic", ErrorKind(errors.New("anything else")))
	require.Equal(t, 1, ExitCodeFor("generic"))
}
