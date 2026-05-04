package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newVPNIPsecCmd wires the `vpn ipsec` sub-tree, mirroring the Phase
// 7-9 firewall_rule CLI: list / show / new / pull / diff / push /
// delete. Drafts live under drafts/vpn/<slug>.yaml; snapshots under
// snapshots/vpn/.
func newVPNIPsecCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "ipsec", Short: "Site-to-site IPsec VPN tunnel commands"}
	cmd.AddCommand(
		newVPNIPsecListCmd(d, cat),
		newVPNIPsecShowCmd(d, cat),
		newVPNIPsecNewCmd(d, cat),
		newVPNIPsecPullCmd(d, cat),
		newVPNIPsecDiffCmd(d, cat),
		newVPNIPsecPushCmd(d, cat),
		newVPNIPsecDeleteCmd(d, cat),
	)
	return cmd
}

// vpnIPsecSvc constructs a fresh VPNIPsecSvc per call, mirroring
// firewallRuleSvc. Triggers a one-shot legacy-layout migration so old
// flat drafts are moved under their kind subdirs before any read.
func vpnIPsecSvc(d RootDeps, cat *catalog.Catalog) *svc.VPNIPsecSvc {
	if _, pname, err := d.Config.ActiveProfile(""); err == nil {
		_ = draft.MigrateLegacyLayout(d.BaseDir, pname)
	}
	return &svc.VPNIPsecSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit:   d.Audit,
		BaseDir: d.BaseDir,
		Version: d.Version,
	}
}

func newVPNIPsecListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List IPsec VPN tunnels",
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
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			out, err := s.List(cmd.Context(), profile, "VPNIPsecConnection", filter)
			if err != nil {
				return err
			}
			items := make([]map[string]any, 0, len(out.Items))
			for _, raw := range out.Items {
				if m, ok := raw.(map[string]any); ok {
					items = append(items, m)
				}
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.VPNIPsecListEnvelope(out.Profile, len(items), items)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			entry, _ := cat.Resolve("VPNIPsecConnection")
			headers := resolveColumns(cmd, entry.Columns)
			rows := make([][]string, 0, len(items))
			for _, m := range items {
				rows = append(rows, mapRow(m, headers))
			}
			return render.WriteTable(cmd.OutOrStdout(), headers, rows)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newVPNIPsecShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one IPsec tunnel by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			tunnel, err := vpnIPsecSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.VPNIPsecEnvelope(tunnel)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%v\n", tunnel)
			return nil
		},
	}
}

func newVPNIPsecPullCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "pull <name>",
		Short: "Pull an IPsec tunnel into a local YAML draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := vpnIPsecSvc(d, cat).Pull(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.VPNIPsecPullEnvelope(result)
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

func newVPNIPsecNewCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var fromTunnel string
	c := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a new IPsec tunnel draft (template or --from existing)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := vpnIPsecSvc(d, cat).New(cmd.Context(), profile, args[0], fromTunnel)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.VPNIPsecPullEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			// Branch on whether a snapshot was written. Pure
			// templates (no --from) leave SnapshotPath/DiffHash
			// empty; --from <existing> seeds a snapshot from the
			// live record so diff/push behave like Pull.
			if result.SnapshotPath == "" || result.DiffHash == "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"Draft written: %s\nOperation:     create\nSnapshot:      (none — first push will create one)\nEdit and run: sophosfw vpn ipsec push %s --yes\n",
					result.DraftPath, args[0])
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"Draft written: %s\nOperation:     create\nSnapshot:      %s\nDiff hash:     %s\nEdit and run: sophosfw vpn ipsec push %s --yes\n",
					result.DraftPath, result.SnapshotPath, result.DiffHash, args[0])
			}
			return nil
		},
	}
	c.Flags().StringVar(&fromTunnel, "from", "", "clone an existing tunnel's body as the starting template")
	return c
}

func newVPNIPsecDiffCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "diff <name>",
		Short: "Show local diff between snapshot and draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := vpnIPsecSvc(d, cat).Diff(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.VPNIPsecDiffEnvelope(result)
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

func newVPNIPsecPushCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	c := &cobra.Command{
		Use:   "push <name>",
		Short: "Validate the draft and apply it to the firewall",
		Long:  "Defaults to --dry-run preview. Pass --yes to apply. Use --ignore-diff-hash to skip drift detection.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tunnel := args[0]
			profiles, err := resolveTargetProfiles(cmd, d.Config)
			if err != nil {
				return err
			}
			if len(profiles) == 1 {
				// Pass expectedHash="" so the svc-level Push falls
				// back to the draft header DiffHash. Preserves the
				// firewall_rule push UX from Phase 9.
				result, err := vpnIPsecSvc(d, cat).Push(cmd.Context(), profiles[0], tunnel, "", ignoreHash, !yes)
				if err != nil {
					return err
				}
				return renderVPNIPsecPush(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return vpnIPsecSvc(d, cat).Push(ctx, profile, tunnel, "", ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "vpn_ipsec_push", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection (use with care)")
	AddProfileSetFlag(c)
	return c
}

func newVPNIPsecDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	var expectedHash string
	c := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an IPsec tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			tunnel := args[0]
			profiles, err := resolveTargetProfiles(cmd, d.Config)
			if err != nil {
				return err
			}
			if len(profiles) == 1 {
				result, err := vpnIPsecSvc(d, cat).Delete(cmd.Context(), profiles[0], tunnel, expectedHash, ignoreHash, !yes)
				if err != nil {
					return err
				}
				return renderVPNIPsecDelete(cmd, result)
			}
			op := func(ctx context.Context, profile string, preflight bool) (any, error) {
				return vpnIPsecSvc(d, cat).Delete(ctx, profile, tunnel, expectedHash, ignoreHash, preflight || !yes)
			}
			fr := svc.Run(cmd.Context(), "vpn_ipsec_delete", profiles, op, !yes)
			return printFanout(cmd, fr)
		},
	}
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hex hash from a prior `vpn ipsec pull`")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection")
	c.Flags().BoolVar(&yes, "yes", false, "apply the deletion (default is --dry-run)")
	AddProfileSetFlag(c)
	return c
}

// renderVPNIPsecPush is the single-profile fast-path renderer for `vpn
// ipsec push`. Mirrors renderFirewallRulePush:
//   - JSON: emit the VPNIPsecPushEnvelope
//   - text dry-run: "DRY RUN: would push <tunnel> verbs: ..."
//   - text apply:   "applied: <tunnel> (newDiffHash: ...)"
func renderVPNIPsecPush(cmd *cobra.Command, result *svc.VPNIPsecPushResult) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		b, err := render.VPNIPsecPushEnvelope(result)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
	}
	if result.DryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would push %s\nverbs: %v\n", result.Tunnel, result.Preview.Verbs)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "applied: %s (newDiffHash: %s)\n", result.Tunnel, result.NewDiffHash)
	return nil
}

// renderVPNIPsecDelete mirrors renderFirewallRuleDelete.
func renderVPNIPsecDelete(cmd *cobra.Command, result *svc.VPNIPsecPushResult) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		b, err := render.VPNIPsecPushEnvelope(result)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
	}
	if result.DryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would delete %s\n", result.Tunnel)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "deleted: %s\n", result.Tunnel)
	return nil
}
