package svc

import (
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/stretchr/testify/require"
)

func newProfileSvc(t *testing.T) (*ProfileSvc, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.New()
	store := creds.NewFileStore(dir)
	return &ProfileSvc{
		Config:  cfg,
		Creds:   store,
		BaseDir: dir,
	}, dir
}

func TestProfileSvc_AddSavesConfig(t *testing.T) {
	s, _ := newProfileSvc(t)
	err := s.Add("home", "https://fw.example.com:4444", false)
	require.NoError(t, err)
	require.Contains(t, s.Config.Profiles, "home")
	require.Equal(t, "home", s.Config.CurrentProfile)
}

func TestProfileSvc_AddRejectsEmptyURL(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.Error(t, s.Add("home", "", false))
}

func TestProfileSvc_AddRejectsDuplicateName(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.Error(t, s.Add("home", "https://y:4444", false))
}

func TestProfileSvc_RemoveDeletesCreds(t *testing.T) {
	s, dir := newProfileSvc(t)
	_ = dir
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.NoError(t, s.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))

	require.NoError(t, s.Remove("home"))
	_, err := s.Creds.Load("home")
	require.ErrorIs(t, err, creds.ErrNotFound)
}

func TestProfileSvc_Use(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.NoError(t, s.Add("work", "https://y:4444", false))
	require.NoError(t, s.Use("work"))
	require.Equal(t, "work", s.Config.CurrentProfile)
}

func TestProfileSvc_List(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.NoError(t, s.Add("work", "https://y:4444", true))
	list := s.List()
	require.Len(t, list, 2)
}
