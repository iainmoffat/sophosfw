package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// AddProfileSetFlag wires the --profile-set flag to a command.
// Mutually exclusive with --profile (enforced at runtime in
// resolveTargetProfiles).
func AddProfileSetFlag(cmd *cobra.Command) {
	cmd.Flags().String("profile-set", "", "named profile group OR comma-separated profile list (mutually exclusive with --profile)")
}

// resolveTargetProfiles returns the ordered list of profile names to
// operate against. Reads --profile and --profile-set flags; rejects
// both-set; defaults to the active profile when neither is set.
func resolveTargetProfiles(cmd *cobra.Command, cfg *config.Config) ([]string, error) {
	profile, _ := cmd.Flags().GetString("profile")
	profileSet, _ := cmd.Flags().GetString("profile-set")
	if profile != "" && profileSet != "" {
		return nil, fmt.Errorf("%w: --profile and --profile-set are mutually exclusive", sophos.ErrInvalidRequest)
	}
	if profileSet != "" {
		return cfg.ResolveProfileSet(profileSet)
	}
	if profile != "" {
		return []string{profile}, nil
	}
	_, name, err := cfg.ActiveProfile("")
	if err != nil {
		return nil, err
	}
	return []string{name}, nil
}
