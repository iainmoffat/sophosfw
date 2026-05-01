package sophos

import (
	"errors"
	"fmt"
)

// Sentinel errors. Higher layers compare with errors.Is to map to
// sophosfw.v1.error envelope kinds.
var (
	ErrAuthFailed        = errors.New("sophos: authentication failed")
	ErrNotFound          = errors.New("sophos: object not found")
	ErrPermissionDenied  = errors.New("sophos: permission denied")
	ErrInvalidRequest    = errors.New("sophos: invalid request")
	ErrServerError       = errors.New("sophos: server error")
	ErrReadOnlyViolation = errors.New("sophos: read-only profile rejected mutating XML")
)

// StatusError wraps the original numeric code and message so callers can
// surface them while still matching against a sentinel via errors.Is.
type StatusError struct {
	Code     int
	Message  string
	Sentinel error
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("sophos status %d: %s", e.Code, e.Message)
}

func (e *StatusError) Unwrap() error { return e.Sentinel }

// statusToError converts a Sophos status code to a typed error. Returns nil
// for success codes.
func statusToError(code int, message string) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == 534:
		return &StatusError{Code: code, Message: message, Sentinel: ErrAuthFailed}
	case code == 526:
		return &StatusError{Code: code, Message: message, Sentinel: ErrNotFound}
	case code == 535:
		return &StatusError{Code: code, Message: message, Sentinel: ErrPermissionDenied}
	case code >= 500 && code <= 530:
		return &StatusError{Code: code, Message: message, Sentinel: ErrInvalidRequest}
	default:
		return &StatusError{Code: code, Message: message, Sentinel: ErrServerError}
	}
}
