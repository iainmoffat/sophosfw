package cli

import (
	"fmt"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newFirewallCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "firewall", Short: "Firewall first-class commands"}
	cmd.AddCommand(newFirewallRuleCmd(d, cat))
	return cmd
}

func newFirewallRuleCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "Firewall rule first-class commands"}
	cmd.AddCommand(
		newFirewallRuleListCmd(d, cat),
		newFirewallRuleShowCmd(d, cat),
	)
	return cmd
}

func firewallRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.FirewallRuleSvc {
	return &svc.FirewallRuleSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newFirewallRuleListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List firewall rules",
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
			out, err := firewallRuleSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderRuleMapList(cmd, cat, "FirewallRule", "sophosfw.v1.firewallRuleList", out.Profile, out.Count, out.Items)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newFirewallRuleShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one firewall rule by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			rule, err := firewallRuleSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.FirewallRuleEnvelope(rule)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%v\n", rule)
			return nil
		},
	}
}

// renderRuleMapList renders a list of map[string]any items as either JSON
// (with the given schema name) or a column-aware table. Used by both the
// firewall rule and nat rule list commands. Array values are comma-joined
// in the table view. The JSON envelope includes xmlTag (per spec section 6).
func renderRuleMapList(cmd *cobra.Command, cat *catalog.Catalog, tag, schema, profile string, count int, items []map[string]any) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		var b []byte
		var err error
		switch tag {
		case "FirewallRule":
			b, err = render.FirewallRuleListEnvelope(&svc.FirewallRuleList{Profile: profile, Count: count, Items: items})
		case "NATRule":
			b, err = render.NATRuleListEnvelope(&svc.NATRuleList{Profile: profile, Count: count, Items: items})
		default:
			return fmt.Errorf("renderRuleMapList: unknown tag %q", tag)
		}
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
	}
	entry, _ := cat.Resolve(tag)
	headers := resolveColumns(cmd, entry.Columns)
	rows := make([][]string, 0, len(items))
	for _, m := range items {
		rows = append(rows, mapRow(m, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

// mapRow extracts cells for a generic map[string]any record. Array values
// render comma-joined; map and other complex values render as their default
// fmt.Sprintf("%v") form.
func mapRow(m map[string]any, headers []string) []string {
	row := make([]string, len(headers))
	for i, col := range headers {
		row[i] = mapCell(m, col)
	}
	return row
}

func mapCell(m map[string]any, col string) string {
	v, ok := m[col]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			} else {
				parts = append(parts, fmt.Sprintf("%v", e))
			}
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}
