package creds

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew_PlatformDefault(t *testing.T) {
	s := New(t.TempDir())
	if runtime.GOOS == "darwin" {
		require.Equal(t, BackendKeychain, s.Backend())
	} else {
		require.Equal(t, BackendFile, s.Backend())
	}
}
