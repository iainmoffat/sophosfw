// Package cli — IPsecPolicy mutating CLI surface (Phase 15, Task 7).
//
// `vpn policy list|show|create|update|delete` over the body-as-map svc
// layer. Mirrors internal/cli/iphostgroup_mutation.go (Phase 12 T6) with
// list/show added (the spec acceptance lists 5 sub-commands per type).
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newIPsecPolicyCmd is the `vpn policy` parent. Wired into `vpn` from
// internal/cli/vpn.go alongside `vpn ipsec` (T6) and `vpn ike-profile`.
func newIPsecPolicyCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "IPsecPolicy first-class commands"}
	cmd.AddCommand(
		newIPsecPolicyListCmd(d, cat),
		newIPsecPolicyShowCmd(d, cat),
		newIPsecPolicyCreateCmd(d, cat),
		newIPsecPolicyUpdateCmd(d, cat),
		newIPsecPolicyDeleteCmd(d, cat),
	)
	return cmd
}

// ipsecPolicySvc resolves an IPsecPolicySvc from RootDeps.
func ipsecPolicySvc(d RootDeps, cat *catalog.Catalog) *svc.IPsecPolicySvc {
	return &svc.IPsecPolicySvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit: d.Audit,
	}
}

func newIPsecPolicyListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List IPsec policies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			var filter *sophos.FilterClause
			if filterStr != "" {
				f, err := sophos.ParseFilterFlag(filterStr)
				if err != nil {
					return err
				}
				filter = &f
			}
			out, err := ipsecPolicySvc(d, cat).Inner.List(cmd.Context(), profile, "IPsecPolicy", filter)
			if err != nil {
				return err
			}
			return renderObjectList(cmd, out, cat)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newIPsecPolicyShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one IPsec policy by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			obj, err := ipsecPolicySvc(d, cat).Inner.Get(cmd.Context(), profile, "IPsecPolicy", args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.ObjectEnvelope(obj)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s:\n%v\n", obj.Tag, obj.Name, obj.Data)
			return nil
		},
	}
}

func newIPsecPolicyCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg string
	var yes bool
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new IPsecPolicy from a JSON/YAML body",
		Long:  "Required body keys: Name. Defaults to --dry-run; pass --yes to apply.",
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
				result, err := ipsecPolicySvc(d, cat).Create(cmd.Context(), profiles[0], name, body, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return ipsecPolicySvc(d, cat).Create(ctx, profile, name, body, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "ipsec_policy_create", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(cmd)
	_ = cmd.MarkFlagRequired("body")
	return cmd
}

func newIPsecPolicyUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg, expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update an existing IPsecPolicy",
		Long:  "Required body keys: Name. Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
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
				result, err := ipsecPolicySvc(d, cat).Update(cmd.Context(), profiles[0], name, body, expectedHash, ignoreHash, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return ipsecPolicySvc(d, cat).Update(ctx, profile, name, body, expectedHash, ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "ipsec_policy_update", profiles, op, !yes)
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

func newIPsecPolicyDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an IPsecPolicy",
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
				result, err := ipsecPolicySvc(d, cat).Delete(cmd.Context(), profiles[0], name, expectedHash, ignoreHash, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return ipsecPolicySvc(d, cat).Delete(ctx, profile, name, expectedHash, ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "ipsec_policy_delete", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required for --yes unless --ignore-diff-hash")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(cmd)
	return cmd
}
