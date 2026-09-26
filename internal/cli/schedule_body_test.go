package cli

import (
	"bytes"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func TestScheduleCreateNullBodyReturnsInvalidRequest(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"schedule", "create", "X", "--body", "null"})
	err := root.Execute()
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
}
