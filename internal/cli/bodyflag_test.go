package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

func TestLoadBody_EmptyArg(t *testing.T) {
	_, err := LoadBody("")
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}

func TestLoadBody_InlineJSON(t *testing.T) {
	body, err := LoadBody(`{"Name":"x"}`)
	require.NoError(t, err)
	require.Equal(t, "x", body["Name"])
}

func TestLoadBody_InlineYAML(t *testing.T) {
	body, err := LoadBody(`Name: x
IPFamily: IPv4`)
	require.NoError(t, err)
	require.Equal(t, "x", body["Name"])
	require.Equal(t, "IPv4", body["IPFamily"])
}

func TestLoadBody_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "body.yaml")
	require.NoError(t, os.WriteFile(path, []byte("Name: x\n"), 0o600))
	body, err := LoadBody("@" + path)
	require.NoError(t, err)
	require.Equal(t, "x", body["Name"])
}

func TestLoadBody_MissingFile(t *testing.T) {
	_, err := LoadBody("@/no/such/path")
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}

func TestLoadBody_Garbage(t *testing.T) {
	_, err := LoadBody("not json or yaml: : :")
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}
