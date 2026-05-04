package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// newProfileSetCmd is the `auth profile set` sub-parent. It groups the
// add/list/remove sub-commands for managing named profile groups.
func newProfileSetCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "set", Short: "Manage named profile groups"}
	cmd.AddCommand(
		newProfileSetAddCmd(d),
		newProfileSetListCmd(d),
		newProfileSetRemoveCmd(d),
	)
	return cmd
}

// newProfileSetAddCmd: `auth profile set add <name> [csv]` with optional
// repeated --member flag. Persists via Config.Save.
func newProfileSetAddCmd(d RootDeps) *cobra.Command {
	var members []string
	cmd := &cobra.Command{
		Use:   "add <name> [profile,profile,...]",
		Short: "Add or overwrite a profile set",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if len(args) == 2 {
				for _, m := range strings.Split(args[1], ",") {
					if t := strings.TrimSpace(m); t != "" {
						members = append(members, t)
					}
				}
			}
			if len(members) == 0 {
				return fmt.Errorf("provide members via positional CSV or repeated --member")
			}
			if err := d.Config.AddProfileSet(name, members); err != nil {
				return err
			}
			if err := d.Config.Save(d.BaseDir); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Profile set %q saved with %d member(s).\n", name, len(members))
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&members, "member", nil, "profile name (repeatable)")
	return cmd
}

// newProfileSetListCmd: `auth profile set list` (--json for machine output).
func newProfileSetListCmd(d RootDeps) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List defined profile sets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			sets := d.Config.ProfileSets
			if jsonOut {
				env := map[string]any{
					"schema": "sophosfw.v1.profileSetList",
					"sets":   sets,
				}
				body, err := json.MarshalIndent(env, "", "  ")
				if err != nil {
					return err
				}
				_, _ = cmd.OutOrStdout().Write(body)
				return nil
			}
			if len(sets) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No profile sets.")
				return nil
			}
			for name, mem := range sets {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", name, strings.Join(mem, ", "))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	return cmd
}

// newProfileSetRemoveCmd: `auth profile set remove <name>`.
func newProfileSetRemoveCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a profile set",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := d.Config.RemoveProfileSet(args[0]); err != nil {
				return err
			}
			if err := d.Config.Save(d.BaseDir); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Profile set %q removed.\n", args[0])
			return nil
		},
	}
}
