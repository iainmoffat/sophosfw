package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/sophos"
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

// --- ProfileSet tests (Phase 14 T1) ---------------------------------------

func newConfigWithProfiles(names ...string) *Config {
	c := New()
	for _, n := range names {
		c.AddProfile(n, Profile{URL: "https://" + n + ":4444"})
	}
	return c
}

func TestConfig_AddProfileSet_Persists(t *testing.T) {
	dir := t.TempDir()
	c := newConfigWithProfiles("a", "b")
	require.NoError(t, c.AddProfileSet("staging", []string{"a", "b"}))
	require.NoError(t, c.Save(dir))

	got, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, got.ProfileSets["staging"])

	// Verify the stored slice is independent of the input slice.
	members := []string{"a"}
	c2 := newConfigWithProfiles("a")
	require.NoError(t, c2.AddProfileSet("g", members))
	members[0] = "mutated"
	require.Equal(t, "a", c2.ProfileSets["g"][0])
}

func TestConfig_AddProfileSet_RejectsInvalidName(t *testing.T) {
	c := newConfigWithProfiles("a")
	for _, bad := range []string{"", "has space", "with/slash", "dot.dot", "weird!"} {
		err := c.AddProfileSet(bad, []string{"a"})
		require.Error(t, err, "name %q should be rejected", bad)
		require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	}
}

func TestConfig_AddProfileSet_RejectsCollisionWithProfileName(t *testing.T) {
	c := newConfigWithProfiles("home", "work")
	err := c.AddProfileSet("home", []string{"work"})
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "collides")
}

func TestConfig_AddProfileSet_RejectsMissingMember(t *testing.T) {
	c := newConfigWithProfiles("a")
	err := c.AddProfileSet("g", []string{"a", "ghost"})
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.NotContains(t, c.ProfileSets, "g", "set must not be persisted on validation failure")
}

func TestConfig_RemoveProfileSet(t *testing.T) {
	c := newConfigWithProfiles("a")
	require.NoError(t, c.AddProfileSet("g", []string{"a"}))
	require.NoError(t, c.RemoveProfileSet("g"))
	require.NotContains(t, c.ProfileSets, "g")
}

func TestConfig_RemoveProfileSet_NotFound(t *testing.T) {
	c := newConfigWithProfiles("a")
	err := c.RemoveProfileSet("ghost")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
}

func TestConfig_ResolveProfileSet_BareSetName_ExpandsMembers(t *testing.T) {
	c := newConfigWithProfiles("a", "b", "c")
	require.NoError(t, c.AddProfileSet("staging", []string{"a", "b"}))
	got, err := c.ResolveProfileSet("staging")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, got)

	// Returned slice is a copy.
	got[0] = "mutated"
	require.Equal(t, "a", c.ProfileSets["staging"][0])
}

func TestConfig_ResolveProfileSet_BareProfileName_ReturnsSingle(t *testing.T) {
	c := newConfigWithProfiles("home")
	got, err := c.ResolveProfileSet("home")
	require.NoError(t, err)
	require.Equal(t, []string{"home"}, got)
}

func TestConfig_ResolveProfileSet_CSV_ReturnsList(t *testing.T) {
	c := newConfigWithProfiles("a", "b", "c")
	got, err := c.ResolveProfileSet("a, b ,c")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, got)
}

func TestConfig_ResolveProfileSet_CSV_RejectsSetEntry(t *testing.T) {
	c := newConfigWithProfiles("a", "b")
	require.NoError(t, c.AddProfileSet("staging", []string{"a", "b"}))
	_, err := c.ResolveProfileSet("a,staging")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "profile set")
}

func TestConfig_ResolveProfileSet_UnknownIdentifier(t *testing.T) {
	c := newConfigWithProfiles("a")

	_, err := c.ResolveProfileSet("ghost")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)

	_, err = c.ResolveProfileSet("a,ghost")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)

	_, err = c.ResolveProfileSet("")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)

	_, err = c.ResolveProfileSet("a,,b")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
}

func TestConfig_ResolveProfileSet_DuplicatesDeduped(t *testing.T) {
	c := newConfigWithProfiles("a", "b")
	got, err := c.ResolveProfileSet("a,b,a,b,a")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, got)
}

func TestConfig_Load_ValidatesProfileSets(t *testing.T) {
	dir := t.TempDir()

	// Member that doesn't exist in profiles.
	writeFile(t, filepath.Join(dir, "config.yaml"), `
version: 1
defaults:
  output: table
  timeout: 30s
profiles:
  a:
    url: https://a:4444
    credentialsBackend: keychain
profileSets:
  bad:
    - a
    - ghost
`)
	_, err := Load(dir)
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "ghost")

	// Set name collides with a profile name.
	dir2 := t.TempDir()
	writeFile(t, filepath.Join(dir2, "config.yaml"), `
version: 1
defaults:
  output: table
  timeout: 30s
profiles:
  home:
    url: https://h:4444
    credentialsBackend: keychain
profileSets:
  home:
    - home
`)
	_, err = Load(dir2)
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)
	require.Contains(t, err.Error(), "collides")

	// Invalid set name.
	dir3 := t.TempDir()
	writeFile(t, filepath.Join(dir3, "config.yaml"), `
version: 1
defaults:
  output: table
  timeout: 30s
profiles:
  a:
    url: https://a:4444
    credentialsBackend: keychain
profileSets:
  "has space":
    - a
`)
	_, err = Load(dir3)
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrInvalidRequest)

	// Sanity: a valid file loads without error.
	dir4 := t.TempDir()
	writeFile(t, filepath.Join(dir4, "config.yaml"), `
version: 1
defaults:
  output: table
  timeout: 30s
profiles:
  a:
    url: https://a:4444
    credentialsBackend: keychain
  b:
    url: https://b:4444
    credentialsBackend: keychain
profileSets:
  staging:
    - a
    - b
`)
	cfg, err := Load(dir4)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, cfg.ProfileSets["staging"])
}
