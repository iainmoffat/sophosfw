package cli

import (
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newHostCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "host", Short: "Host objects (first-class)"}
	cmd.AddCommand(newHostIpCmd(d, cat))
	return cmd
}

func newHostIpCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "ip", Short: "IPHost first-class commands"}
	cmd.AddCommand(
		newHostIpListCmd(d, cat),
		newHostIpShowCmd(d, cat),
		newHostIpSearchCmd(d, cat),
		newHostIpUsageCmd(d, cat),
	)
	return cmd
}

func hostIpSvc(d RootDeps, cat *catalog.Catalog) *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newHostIpListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List IP host objects",
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
			out, err := hostIpSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderHostIpList(cmd, cat, "sophosfw.v1.hostIpList", out)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newHostIpShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one IP host object by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			h, err := hostIpSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.hostIp", h)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n  IPAddress: %s\n  Subnet:    %s\n  Derived:   kind=%s cidr=%s\n",
				h.Name, h.HostType, h.IPAddress, h.Subnet, h.Derived.Kind, h.Derived.CIDR)
			return nil
		},
	}
}

func newHostIpSearchCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "search <query>",
		Short: "Multi-field substring search across IP hosts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := hostIpSvc(d, cat).Search(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			return renderHostIpList(cmd, cat, "sophosfw.v1.hostIpSearch", out)
		},
	}
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newHostIpUsageCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var withRefs bool
	c := &cobra.Command{
		Use:   "usage <name>",
		Short: "Show IPHostStatistics for a host (optionally with reference graph)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := hostIpSvc(d, cat).Usage(cmd.Context(), profile, args[0], withRefs)
			if err != nil {
				return err
			}
			payload := map[string]any{
				"profile": out.Profile,
				"name":    out.Name,
				"records": out.Records,
			}
			if out.References != nil {
				payload["references"] = out.References.Refs
				if len(out.References.Errors) > 0 {
					payload["referenceErrors"] = out.References.Errors
				}
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.hostIpUsage", payload)
		},
	}
	c.Flags().BoolVar(&withRefs, "with-references", false, "scan reference graph (rules + groups) for the host")
	return c
}

func renderHostIpList(cmd *cobra.Command, cat *catalog.Catalog, schema string, list *svc.HostIPList) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		return render.WriteJSON(cmd.OutOrStdout(), schema, map[string]any{
			"profile": list.Profile,
			"xmlTag":  "IPHost",
			"count":   list.Count,
			"items":   list.Items,
		})
	}
	entry, _ := cat.Resolve("IPHost")
	headers := resolveColumns(cmd, entry.Columns)
	rows := make([][]string, 0, len(list.Items))
	for _, h := range list.Items {
		rows = append(rows, hostIpRow(h, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

func hostIpRow(h svc.HostIP, headers []string) []string {
	row := make([]string, len(headers))
	for i, col := range headers {
		row[i] = hostIpCell(h, col)
	}
	return row
}

func hostIpCell(h svc.HostIP, col string) string {
	switch col {
	case "Name":
		return h.Name
	case "IPFamily":
		return h.IPFamily
	case "HostType":
		return h.HostType
	case "IPAddress":
		return h.IPAddress
	case "Subnet":
		return h.Subnet
	case "StartIPAddress":
		return h.StartIPAddress
	case "EndIPAddress":
		return h.EndIPAddress
	case "derived.cidr":
		return h.Derived.CIDR
	case "derived.kind":
		return h.Derived.Kind
	}
	return ""
}
