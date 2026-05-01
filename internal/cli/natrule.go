package cli

import (
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newNATCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "nat", Short: "NAT first-class commands"}
	cmd.AddCommand(newNATRuleCmd(d, cat))
	return cmd
}

func newNATRuleCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "NAT rule first-class commands"}
	cmd.AddCommand(
		newNATRuleListCmd(d, cat),
		newNATRuleShowCmd(d, cat),
	)
	return cmd
}

func natRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.NATRuleSvc {
	return &svc.NATRuleSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newNATRuleListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List NAT rules",
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
			out, err := natRuleSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderRuleMapList(cmd, cat, "NATRule", "sophosfw.v1.natRuleList", out.Profile, out.Count, out.Items)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newNATRuleShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one NAT rule by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			rule, err := natRuleSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.natRule", rule)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%v\n", rule)
			return nil
		},
	}
}
