package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestLoad_EmptyDir_ReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, 1, c.Version)
	require.Equal(t, "table", c.Defaults.Output)
	require.Equal(t, 30*time.Second, c.Defaults.Timeout)
	require.Empty(t, c.Profiles)
	require.Empty(t, c.CurrentProfile)
}

func TestLoad_ParsesProfiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
version: 1
currentProfile: home
defaults:
  output: json
  timeout: 45s
profiles:
  home:
    url: https://fw.example.com:4444
    timeout: 30s
    insecureSkipVerify: false
    readOnly: false
    credentialsBackend: keychain
`)
	c, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, "home", c.CurrentProfile)
	require.Equal(t, "json", c.Defaults.Output)
	require.Len(t, c.Profiles, 1)
	p := c.Profiles["home"]
	require.Equal(t, "https://fw.example.com:4444", p.URL)
	require.Equal(t, "keychain", p.CredentialsBackend)
	require.False(t, p.ReadOnly)
}

func TestSave_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	c := &Config{
		Version:        1,
		CurrentProfile: "home",
		Defaults:       Defaults{Output: "table", Timeout: 30 * time.Second},
		Profiles: map[string]Profile{
			"home": {
				URL:                "https://fw.example.com:4444",
				Timeout:            30 * time.Second,
				ReadOnly:           false,
				CredentialsBackend: "keychain",
			},
		},
	}
	require.NoError(t, c.Save(dir))

	got, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, c.CurrentProfile, got.CurrentProfile)
	require.Equal(t, c.Profiles["home"].URL, got.Profiles["home"].URL)
}

func TestProfile_AddRemoveSelect(t *testing.T) {
	c := New()
	c.AddProfile("home", Profile{URL: "https://h:4444"})
	require.Contains(t, c.Profiles, "home")
	require.Equal(t, "home", c.CurrentProfile, "first profile becomes current automatically")

	c.AddProfile("work", Profile{URL: "https://w:4444"})
	require.Equal(t, "home", c.CurrentProfile, "subsequent additions do not change current")

	require.NoError(t, c.UseProfile("work"))
	require.Equal(t, "work", c.CurrentProfile)

	require.Error(t, c.UseProfile("nope"))

	require.NoError(t, c.RemoveProfile("home"))
	require.NotContains(t, c.Profiles, "home")
}

func TestRemoveProfile_CurrentClearedIfRemoved(t *testing.T) {
	c := New()
	c.AddProfile("home", Profile{URL: "https://h:4444"})
	require.NoError(t, c.RemoveProfile("home"))
	require.Empty(t, c.CurrentProfile)
}

func TestActiveProfile(t *testing.T) {
	c := New()
	c.AddProfile("home", Profile{URL: "https://h:4444"})
	p, name, err := c.ActiveProfile("")
	require.NoError(t, err)
	require.Equal(t, "home", name)
	require.Equal(t, "https://h:4444", p.URL)

	_, _, err = c.ActiveProfile("missing")
	require.Error(t, err)
}
