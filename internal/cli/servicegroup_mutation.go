// Package cli — ServiceGroup mutating CLI surface (Phase 12, Task 11).
//
// `service group create|update|delete` over the body-as-map svc layer.
// Mechanical mirror of internal/cli/fqdnhostgroup_mutation.go; reuses
// the shared `printObjectMutation` helper.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newServiceGroupCmd is the `service group` parent command. Wired into
// `service` from internal/cli/service.go alongside the existing
// service create/update/delete and list/show/search/usage.
func newServiceGroupCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "ServiceGroup first-class commands"}
	cmd.AddCommand(
		newServiceGroupCreateCmd(d, cat),
		newServiceGroupUpdateCmd(d, cat),
		newServiceGroupDeleteCmd(d, cat),
	)
	return cmd
}

// serviceGroupSvc resolves a ServiceGroupSvc from RootDeps. Mirrors
// fqdnHostGroupSvc / iphostGroupSvc — same shape as every other svc
// factory.
func serviceGroupSvc(d RootDeps, cat *catalog.Catalog) *svc.ServiceGroupSvc {
	return &svc.ServiceGroupSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit: d.Audit,
	}
}

func newServiceGroupCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg string
	var yes bool
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new ServiceGroup from a JSON/YAML body",
		Long:  "Required body keys: Name. Defaults to --dry-run; pass --yes to apply.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			profile, _ := cmd.Flags().GetString("profile")
			body, err := LoadBody(bodyArg)
			if err != nil {
				return err
			}
			if bn, _ := body["Name"].(string); bn != "" && bn != name {
				return fmt.Errorf("body Name %q does not match positional arg %q", bn, name)
			}
			body["Name"] = name

			result, err := serviceGroupSvc(d, cat).Create(cmd.Context(), profile, name, body, !yes)
			if err != nil {
				return err
			}
			return printObjectMutation(cmd, result)
		},
	}
	cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	_ = cmd.MarkFlagRequired("body")
	return cmd
}

func newServiceGroupUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg, expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update an existing ServiceGroup",
		Long:  "Required body keys: Name. Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for update --yes (or pass --ignore-diff-hash)")
			}
			body, err := LoadBody(bodyArg)
			if err != nil {
				return err
			}
			if bn, _ := body["Name"].(string); bn != "" && bn != name {
				return fmt.Errorf("body Name %q does not match positional arg %q", bn, name)
			}
			body["Name"] = name

			result, err := serviceGroupSvc(d, cat).Update(cmd.Context(), profile, name, body, expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			return printObjectMutation(cmd, result)
		},
	}
	cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required for --yes unless --ignore-diff-hash")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	_ = cmd.MarkFlagRequired("body")
	return cmd
}

func newServiceGroupDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a ServiceGroup",
		Long:  "Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			result, err := serviceGroupSvc(d, cat).Delete(cmd.Context(), profile, name, expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			return printObjectMutation(cmd, result)
		},
	}
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required for --yes unless --ignore-diff-hash")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	return cmd
}
