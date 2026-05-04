// Package cli — MACHost mutating CLI surface (Phase 12, Task 9).
//
// `host mac create|update|delete` over the body-as-map svc layer.
// Mechanical mirror of internal/cli/iphostgroup_mutation.go; reuses
// the shared `printObjectMutation` helper defined there.
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newMACHostCmd is the `host mac` parent command. Wired into
// `host` from internal/cli/hostip.go alongside the existing
// `host group`, `host ip`, and `host fqdn` parents.
func newMACHostCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "mac", Short: "MACHost first-class commands"}
	cmd.AddCommand(
		newMACHostCreateCmd(d, cat),
		newMACHostUpdateCmd(d, cat),
		newMACHostDeleteCmd(d, cat),
	)
	return cmd
}

// macHostSvc resolves an MACHostSvc from RootDeps. Mirrors
// iphostGroupSvc / hostIpSvc — same shape as every other svc factory.
func macHostSvc(d RootDeps, cat *catalog.Catalog) *svc.MACHostSvc {
	return &svc.MACHostSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit: d.Audit,
	}
}

func newMACHostCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg string
	var yes bool
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new MACHost from a JSON/YAML body",
		Long:  "Required body keys: Name, Type. Body must set exactly one of MACAddress (string) or MACAddressList (list). Type is \"MACAddress\" or \"MACList\". Defaults to --dry-run; pass --yes to apply.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			body, err := LoadBody(bodyArg)
			if err != nil {
				return err
			}
			if bn, _ := body["Name"].(string); bn != "" && bn != name {
				return fmt.Errorf("body Name %q does not match positional arg %q", bn, name)
			}
			body["Name"] = name

			profiles, err := resolveTargetProfiles(cmd, d.Config)
			if err != nil {
				return err
			}
			if len(profiles) == 1 {
				result, err := macHostSvc(d, cat).Create(cmd.Context(), profiles[0], name, body, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return macHostSvc(d, cat).Create(ctx, profile, name, body, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "mac_host_create", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(cmd)
	_ = cmd.MarkFlagRequired("body")
	return cmd
}

func newMACHostUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg, expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update an existing MACHost",
		Long:  "Required body keys: Name, Type. Body must set exactly one of MACAddress (string) or MACAddressList (list). Type is \"MACAddress\" or \"MACList\". Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
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

			profiles, err := resolveTargetProfiles(cmd, d.Config)
			if err != nil {
				return err
			}
			if len(profiles) == 1 {
				result, err := macHostSvc(d, cat).Update(cmd.Context(), profiles[0], name, body, expectedHash, ignoreHash, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return macHostSvc(d, cat).Update(ctx, profile, name, body, expectedHash, ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "mac_host_update", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required for --yes unless --ignore-diff-hash")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(cmd)
	_ = cmd.MarkFlagRequired("body")
	return cmd
}

func newMACHostDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a MACHost",
		Long:  "Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			profiles, err := resolveTargetProfiles(cmd, d.Config)
			if err != nil {
				return err
			}
			if len(profiles) == 1 {
				result, err := macHostSvc(d, cat).Delete(cmd.Context(), profiles[0], name, expectedHash, ignoreHash, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return macHostSvc(d, cat).Delete(ctx, profile, name, expectedHash, ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "mac_host_delete", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required for --yes unless --ignore-diff-hash")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(cmd)
	return cmd
}
