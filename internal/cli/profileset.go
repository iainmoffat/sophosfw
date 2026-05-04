package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
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

// printFanout writes a *svc.FanoutResult to the command's stdout in
// either JSON envelope form (--json) or human text. After writing, it
// returns one of the fan-out sentinel errors so HandleError can map to
// the appropriate exit code WITHOUT printing an additional error line
// (the per-profile output already explains what happened):
//
//   - ErrFanoutPreflightFailed (exit 1): pre-flight aborted before apply.
//   - ErrFanoutApplyFailed (exit 2):     apply ran and stopped on a
//     mid-fleet failure (trailing profiles "skipped").
//
// Returns nil only when every profile reported "ok" (or "skipped" via
// dryRunOnly with no errors — which currently doesn't apply because
// fan-out callers either route through here on success/failure or
// short-circuit earlier).
func printFanout(cmd *cobra.Command, fr *svc.FanoutResult) error {
	jsonOut, _ := cmd.Flags().GetBool("json")
	if jsonOut {
		body, err := render.FanoutEnvelope(fr)
		if err != nil {
			return err
		}
		if _, err := cmd.OutOrStdout().Write(body); err != nil {
			return err
		}
		if _, err := cmd.OutOrStdout().Write([]byte("\n")); err != nil {
			return err
		}
	} else {
		if err := render.FanoutHumanText(cmd.OutOrStdout(), fr); err != nil {
			return err
		}
	}
	if fr.Aborted {
		return ErrFanoutPreflightFailed
	}
	for _, p := range fr.Results {
		if p.Status == "error" {
			return ErrFanoutApplyFailed
		}
	}
	return nil
}
