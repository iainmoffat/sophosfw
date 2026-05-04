// Package cli — IPHostGroup mutating CLI surface (Phase 12, Task 6).
//
// `host group create|update|delete` over the body-as-map svc layer.
// This file is the canonical template for the other Phase 12 per-type
// CLI files (FQDNHost, FQDNHostGroup, MACHost, Services, ServiceGroup);
// it also defines the shared `printObjectMutation` helper used by all
// of them.
package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newIPHostGroupCmd is the `host group` parent command. Wired into
// `host` from internal/cli/hostip.go alongside the existing `host ip`
// parent.
func newIPHostGroupCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "IPHostGroup first-class commands"}
	cmd.AddCommand(
		newIPHostGroupCreateCmd(d, cat),
		newIPHostGroupUpdateCmd(d, cat),
		newIPHostGroupDeleteCmd(d, cat),
	)
	return cmd
}

// iphostGroupSvc resolves an IPHostGroupSvc from RootDeps. Mirrors
// firewallRuleSvc / hostIpSvc — same shape as every other svc factory.
func iphostGroupSvc(d RootDeps, cat *catalog.Catalog) *svc.IPHostGroupSvc {
	return &svc.IPHostGroupSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit: d.Audit,
	}
}

func newIPHostGroupCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg string
	var yes bool
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new IPHostGroup from a JSON/YAML body",
		Long:  "Required body keys: Name, IPFamily. Defaults to --dry-run; pass --yes to apply.",
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
				result, err := iphostGroupSvc(d, cat).Create(cmd.Context(), profiles[0], name, body, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return iphostGroupSvc(d, cat).Create(ctx, profile, name, body, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "ip_host_group_create", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(cmd)
	_ = cmd.MarkFlagRequired("body")
	return cmd
}

func newIPHostGroupUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var bodyArg, expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update an existing IPHostGroup",
		Long:  "Required body keys: Name, IPFamily. Defaults to --dry-run; pass --yes to apply. --expected-diff-hash is required for --yes (or pass --ignore-diff-hash).",
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
				result, err := iphostGroupSvc(d, cat).Update(cmd.Context(), profiles[0], name, body, expectedHash, ignoreHash, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return iphostGroupSvc(d, cat).Update(ctx, profile, name, body, expectedHash, ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "ip_host_group_update", profiles, op, !yes)
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

func newIPHostGroupDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var expectedHash string
	var yes, ignoreHash bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an IPHostGroup",
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
				result, err := iphostGroupSvc(d, cat).Delete(cmd.Context(), profiles[0], name, expectedHash, ignoreHash, !yes)
				if err != nil {
					return err
				}
				return printObjectMutation(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return iphostGroupSvc(d, cat).Delete(ctx, profile, name, expectedHash, ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "ip_host_group_delete", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required for --yes unless --ignore-diff-hash")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip the diff-hash check (dangerous)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	AddProfileSetFlag(cmd)
	return cmd
}

// printObjectMutation is the shared writer for ObjectMutationResult.
// JSON mode emits the per-type ObjectMutationEnvelope (camelCase schema
// per render/object_mutation.go); table mode emits a one-line human
// summary. Used by all six Phase 12 per-type CLI files.
func printObjectMutation(cmd *cobra.Command, r *svc.ObjectMutationResult) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		body, err := render.ObjectMutationEnvelope(r)
		if err != nil {
			return err
		}
		// Re-pretty-print so the embedded preview/item maps inherit
		// the surrounding indent (ObjectMutationEnvelope already
		// indents but cobra-bound writers benefit from a uniform
		// pass).
		var pretty any
		if err := json.Unmarshal(body, &pretty); err != nil {
			_, werr := cmd.OutOrStdout().Write(body)
			return werr
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(pretty)
	}
	if r.DryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would %s %s %q (%d bytes)\n",
			r.Operation, r.ObjectType, r.Name, r.Preview.WouldSendBytes)
		return nil
	}
	if r.NewDiffHash != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s %q applied (newDiffHash: %s)\n",
			r.Operation, r.ObjectType, r.Name, r.NewDiffHash)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s %q applied\n", r.Operation, r.ObjectType, r.Name)
	}
	return nil
}
