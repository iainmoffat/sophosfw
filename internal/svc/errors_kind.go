package svc

import (
	"errors"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// ErrorKind classifies an error into one of the stable kind tags used by
// sophosfw.v1.error envelopes. The mapping is shared between cli.HandleError
// and the MCP layer's errorEnvelopeResult helper.
//
// Stable tags: auth_failed, not_found, permission_denied, invalid_request,
// server_error, read_only_violation, unsupported_in_phase, network_error,
// tls_error, config_error, generic.
func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	switch {
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
	case errors.Is(err, ErrUnsupportedInPhase):
		return "unsupported_in_phase"
	case errors.Is(err, ErrCatalogUnknownTag):
		return "invalid_request"
	}
	if isTLSError(err) {
		return "tls_error"
	}
	return "generic"
}

// isTLSError detects TLS handshake failures by message inspection. The
// foundation's HTTP client wraps these without a sentinel, so a string
// match is the pragmatic call.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "tls:") || strings.Contains(s, "x509:") || strings.Contains(s, "TLS handshake")
}
