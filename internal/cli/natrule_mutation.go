package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

func newNATRulePullCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "pull <name>",
		Short: "Pull a NAT rule into a local YAML draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleMutSvc(d, cat).Pull(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePullEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Draft written: %s\nSnapshot:      %s\nDiff hash:     %s\n",
				result.DraftPath, result.SnapshotPath, result.DiffHash)
			if len(result.References) > 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "References:")
				for _, rs := range result.References {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %v\n", rs.Type, rs.Names)
				}
			}
			return nil
		},
	}
	return c
}

func newNATRuleDiffCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "diff <name>",
		Short: "Show local diff between snapshot and draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleMutSvc(d, cat).Diff(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRuleDiffEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if !result.HasChanges {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no changes")
				return nil
			}
			_, err = cmd.OutOrStdout().Write([]byte(result.UnifiedDiff))
			return err
		},
	}
	return c
}

func newNATRulePushCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	c := &cobra.Command{
		Use:   "push <name>",
		Short: "Validate the NAT rule draft and apply it to the firewall",
		Long:  "Defaults to --dry-run preview. Pass --yes to apply. Use --ignore-diff-hash to skip drift detection.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleMutSvc(d, cat).Push(cmd.Context(), profile, args[0], ignoreHash, !yes)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePushEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if result.DryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would push %s\nverbs: %v\n", result.Rule, result.Preview.Verbs)
				return nil
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "applied: %s (newDiffHash: %s)\n", result.Rule, result.NewDiffHash)
			return nil
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection (use with care)")
	return c
}

func newNATRuleDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	var expectedHash string
	c := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a NAT rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			result, err := natRuleMutSvc(d, cat).Delete(cmd.Context(), profile, args[0], expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePushEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if result.DryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would delete %s\n", result.Rule)
				return nil
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "deleted: %s\n", result.Rule)
			return nil
		},
	}
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hex hash from a prior `nat rule pull`")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection")
	c.Flags().BoolVar(&yes, "yes", false, "apply the deletion (default is --dry-run)")
	return c
}

func newNATRuleNewCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var fromRule string
	c := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a new NAT rule draft (template or --from existing)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleMutSvc(d, cat).New(cmd.Context(), profile, args[0], fromRule)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePullEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"Draft written: %s\nOperation:     create\nSnapshot:      (none — first push will create one)\nEdit and run: sophosfw nat rule push %s --yes\n",
				result.DraftPath, args[0])
			return nil
		},
	}
	c.Flags().StringVar(&fromRule, "from", "", "clone an existing rule's body as the starting template")
	return c
}

// natRuleMutSvc builds a NATRuleSvc with Audit and BaseDir wired in,
// and runs MigrateLegacyLayout once per CLI invocation (idempotent).
func natRuleMutSvc(d RootDeps, cat *catalog.Catalog) *svc.NATRuleSvc {
	if _, pname, err := d.Config.ActiveProfile(""); err == nil {
		_ = draft.MigrateLegacyLayout(d.BaseDir, pname)
	}
	return &svc.NATRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit:   d.Audit,
		BaseDir: d.BaseDir,
	}
}
