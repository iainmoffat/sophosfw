// Package cli — `sophosfw drift` command.
//
// Compares an existing snapshot tree (per-record YAML under
// ~/.config/sophosfw/profiles/<name>/backups/<utc>/, or any other path)
// against the firewall's current state and reports added / modified /
// removed records. Drift detection is a query, not a mutation: this
// command is safe to run from cron or CI, and follows the
// `git diff --exit-code` convention so callers can branch on the exit
// code without parsing output:
//
//   - 0 → snapshot matches live state
//   - 1 → drift detected (printed normally; ErrDriftDetected sentinel
//     suppresses the usual error envelope)
//   - 2+ → an actual error (config, network, etc.)
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newDriftCmd is the top-level `drift` command. The user supplies
// either a positional snapshot directory OR `--latest`; supplying
// neither (or both) is rejected with ErrInvalidRequest. This is
// stricter than the underlying svc.BackupSvc.Drift, which silently
// defaults to --latest when neither is set; T7 tightens CLI semantics
// so cron mistakes ("forgot the path") fail loudly.
func newDriftCmd(d RootDeps) *cobra.Command {
	var latest, force bool
	var typesCSV string
	cmd := &cobra.Command{
		Use:   "drift [snapshot-dir]",
		Short: "Compare a snapshot to current firewall state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := svc.DriftOptions{Latest: latest, Force: force}
			if len(args) == 1 {
				opts.SnapshotPath = args[0]
			}
			// CLI guard: must have exactly one of (positional, --latest).
			// Belt-and-braces — svc.BackupSvc.Drift also rejects the
			// "both set" case, but enforcing here yields a friendlier
			// error before any service plumbing runs.
			if opts.SnapshotPath == "" && !opts.Latest {
				return fmt.Errorf("%w: specify a snapshot directory or use --latest", sophos.ErrInvalidRequest)
			}
			if opts.SnapshotPath != "" && opts.Latest {
				return fmt.Errorf("%w: snapshot directory and --latest are mutually exclusive", sophos.ErrInvalidRequest)
			}
			if typesCSV != "" {
				opts.Types = splitCSV(typesCSV)
			}

			bs, err := backupSvc(d)
			if err != nil {
				return err
			}
			profiles, err := resolveTargetProfiles(cmd, d.Config)
			if err != nil {
				return err
			}
			if len(profiles) == 1 {
				result, err := bs.Drift(cmd.Context(), profiles[0], opts)
				if err != nil {
					return err
				}

				jsonMode, _ := cmd.Flags().GetBool("json")
				if jsonMode {
					body, err := render.DriftEnvelope(result)
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
					if err := render.DriftHumanText(cmd.OutOrStdout(), result); err != nil {
						return err
					}
				}

				// Non-zero summary → return the drift-detected sentinel so
				// HandleError maps to exit code 1 without printing an error
				// envelope. Output has already been written above.
				if result.Summary.Added+result.Summary.Modified+result.Summary.Removed > 0 {
					return ErrDriftDetected
				}
				return nil
			}
			// Fan-out: drift is a read-side op. Pre-flight is a no-op;
			// the apply phase per profile runs the actual comparison and
			// captures the summary in ApplyResult.
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				if preflight {
					return nil, nil
				}
				return bs.Drift(ctx, profile, opts)
			}
			fr := svc.Run(cmd.Context(), "drift_check", profiles, op, false)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().BoolVar(&latest, "latest", false, "use most recent snapshot under default location")
	cmd.Flags().BoolVar(&force, "force", false, "compare even if snapshot's profile differs from current")
	cmd.Flags().StringVar(&typesCSV, "types", "", "comma-separated catalog tags to check (default: all in snapshot)")
	AddProfileSetFlag(cmd)
	return cmd
}
