package sophos

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatusToError_SuccessReturnsNil(t *testing.T) {
	require.NoError(t, statusToError(200, "Operation Successful"))
	require.NoError(t, statusToError(216, "Operation Completed Successfully"))
}

func TestStatusToError_AuthFailed(t *testing.T) {
	err := statusToError(534, "Authentication Failure")
	require.ErrorIs(t, err, ErrAuthFailed)
}

func TestStatusToError_NotFound(t *testing.T) {
	err := statusToError(526, "No matching record found")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestStatusToError_PermissionDenied(t *testing.T) {
	err := statusToError(535, "Permission denied")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestStatusToError_InvalidRequest(t *testing.T) {
	err := statusToError(500, "Bad request")
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestStatusToError_GenericServerError(t *testing.T) {
	err := statusToError(599, "Server error")
	require.ErrorIs(t, err, ErrServerError)
}

func TestStatusToError_PreservesCodeAndMessage(t *testing.T) {
	err := statusToError(534, "Authentication Failure")
	var sErr *StatusError
	require.True(t, errors.As(err, &sErr))
	require.Equal(t, 534, sErr.Code)
	require.Equal(t, "Authentication Failure", sErr.Message)
}
