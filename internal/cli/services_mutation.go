// Package cli — Services mutating CLI surface (Phase 12, Task 10).
//
// `service create|update|delete` over the body-as-map svc layer.
// Mechanical mirror of internal/cli/fqdnhost_mutation.go, but the
// commands attach to the existing `service` parent (alongside the
// read-only list/show/search/usage from Phase 3) rather than a new
// sub-parent. Reuses the shared `printObjectMutation` helper.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// servicesSvc resolves a ServicesSvc from RootDeps. Mirrors
// fqdnHostSvc / iphostGroupSvc — same shape as every other svc factory.
func servicesSvc(d RootDeps, cat *catalog.Catalog) *svc.ServicesSvc {
	return &svc.ServicesSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit: d.Audit,
	}
}

func newServicesCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg string
	var yes bool
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new Service from a JSON/YAML body",
		Long:  "Required body keys: Name, Type, ServiceDetails. Type is one of TCPorUDP, IP, ICMP, ICMPv6; ServiceDetails shape varies by Type. Defaults to --dry-run; pass --yes to apply.",
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

			result, err := servicesSvc(d, cat).Create(cmd.Context(), profile, name, body, !yes)
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

func newServicesUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg, expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update an existing Service",
		Long:  "Required body keys: Name, Type, ServiceDetails. Type is one of TCPorUDP, IP, ICMP, ICMPv6; ServiceDetails shape varies by Type. Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
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

			result, err := servicesSvc(d, cat).Update(cmd.Context(), profile, name, body, expectedHash, ignoreHash, !yes)
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

func newServicesDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a Service",
		Long:  "Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			result, err := servicesSvc(d, cat).Delete(cmd.Context(), profile, name, expectedHash, ignoreHash, !yes)
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
