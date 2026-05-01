package svc

import "github.com/iainmoffat/sophosfw/internal/sophos"

// These accessors keep references.go free of a direct import on the sophos
// package's error sentinels.
func sophosErrAuthFailed() error        { return sophos.ErrAuthFailed }
func sophosErrNotFound() error          { return sophos.ErrNotFound }
func sophosErrPermissionDenied() error  { return sophos.ErrPermissionDenied }
func sophosErrInvalidRequest() error    { return sophos.ErrInvalidRequest }
func sophosErrServerError() error       { return sophos.ErrServerError }
func sophosErrReadOnlyViolation() error { return sophos.ErrReadOnlyViolation }
