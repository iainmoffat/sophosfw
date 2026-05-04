package cli

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// newProfileSetTestCmd builds a minimal cobra command with the flags
// resolveTargetProfiles reads (--profile + --profile-set) wired up,
// matching the shape used by real commands.
func newProfileSetTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("profile", "", "config profile to use")
	AddProfileSetFlag(cmd)
	return cmd
}

// newProfileSetTestConfig builds a config with three profiles and one
// profile set.
func newProfileSetTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://h:4444"})
	cfg.AddProfile("office", config.Profile{URL: "https://o:4444"})
	cfg.AddProfile("colo", config.Profile{URL: "https://c:4444"})
	require.NoError(t, cfg.UseProfile("home"))
	require.NoError(t, cfg.AddProfileSet("eastcoast", []string{"home", "office"}))
	return cfg
}

func TestResolveTargetProfiles_DefaultsToActive(t *testing.T) {
	cfg := newProfileSetTestConfig(t)
	cmd := newProfileSetTestCmd()

	got, err := resolveTargetProfiles(cmd, cfg)
	require.NoError(t, err)
	require.Equal(t, []string{"home"}, got)
}

func TestResolveTargetProfiles_ProfileFlag(t *testing.T) {
	cfg := newProfileSetTestConfig(t)
	cmd := newProfileSetTestCmd()
	require.NoError(t, cmd.Flags().Set("profile", "office"))

	got, err := resolveTargetProfiles(cmd, cfg)
	require.NoError(t, err)
	require.Equal(t, []string{"office"}, got)
}

func TestResolveTargetProfiles_ProfileSetFlag_BareSetName(t *testing.T) {
	cfg := newProfileSetTestConfig(t)
	cmd := newProfileSetTestCmd()
	require.NoError(t, cmd.Flags().Set("profile-set", "eastcoast"))

	got, err := resolveTargetProfiles(cmd, cfg)
	require.NoError(t, err)
	require.Equal(t, []string{"home", "office"}, got)
}

func TestResolveTargetProfiles_ProfileSetFlag_CSV(t *testing.T) {
	cfg := newProfileSetTestConfig(t)
	cmd := newProfileSetTestCmd()
	require.NoError(t, cmd.Flags().Set("profile-set", "office,colo"))

	got, err := resolveTargetProfiles(cmd, cfg)
	require.NoError(t, err)
	require.Equal(t, []string{"office", "colo"}, got)
}

func TestResolveTargetProfiles_BothFlagsRejected(t *testing.T) {
	cfg := newProfileSetTestConfig(t)
	cmd := newProfileSetTestCmd()
	require.NoError(t, cmd.Flags().Set("profile", "home"))
	require.NoError(t, cmd.Flags().Set("profile-set", "eastcoast"))

	_, err := resolveTargetProfiles(cmd, cfg)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest), "expected ErrInvalidRequest, got: %v", err)
}
