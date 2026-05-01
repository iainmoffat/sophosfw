package creds

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileStore_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.Equal(t, BackendFile, s.Backend())

	require.NoError(t, s.Save("home", Credentials{Username: "admin", Password: "hunter2"}))

	got, err := s.Load("home")
	require.NoError(t, err)
	require.Equal(t, "admin", got.Username)
	require.Equal(t, "hunter2", got.Password)
}

func TestFileStore_FileWrittenWith0600(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.NoError(t, s.Save("home", Credentials{Username: "u", Password: "p"}))

	info, err := os.Stat(filepath.Join(dir, "credentials.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFileStore_LoadRefusesLoosePerms(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.NoError(t, s.Save("home", Credentials{Username: "u", Password: "p"}))

	require.NoError(t, os.Chmod(filepath.Join(dir, "credentials.yaml"), 0o644))
	_, err := s.Load("home")
	require.ErrorIs(t, err, ErrInsecurePermissions)
}

func TestFileStore_LoadMissingProfile(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	_, err := s.Load("missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFileStore_Delete(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.NoError(t, s.Save("home", Credentials{Username: "u", Password: "p"}))
	require.NoError(t, s.Delete("home"))
	_, err := s.Load("home")
	require.ErrorIs(t, err, ErrNotFound)
}
