package cli

import (
	"errors"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ErrorKind classifies an error into a sophosfw.v1.error envelope kind.
func ErrorKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, sophos.ErrAuthFailed):
		return "auth_failed"
	case errors.Is(err, sophos.ErrNotFound):
		return "not_found"
	case errors.Is(err, sophos.ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, sophos.ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, sophos.ErrServerError):
		return "server_error"
	case errors.Is(err, sophos.ErrReadOnlyViolation):
		return "read_only_violation"
	case errors.Is(err, svc.ErrUnsupportedInPhase):
		return "unsupported_in_phase"
	case errors.Is(err, svc.ErrCatalogUnknownTag):
		return "catalog_unknown_tag"
	default:
		return "generic"
	}
}

// ExitCodeFor maps an error kind to a process exit code.
func ExitCodeFor(kind string) int {
	switch kind {
	case "":
		return 0
	case "config_error":
		return 2
	case "auth_failed":
		return 3
	case "read_only_violation":
		return 4
	case "tls_error", "network_error":
		return 5
	case "unsupported_in_phase":
		return 6
	default:
		return 1
	}
}
