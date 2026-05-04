package cli

import (
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newServiceCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Service first-class commands"}
	cmd.AddCommand(
		newServiceListCmd(d, cat),
		newServiceShowCmd(d, cat),
		newServiceSearchCmd(d, cat),
		newServiceUsageCmd(d, cat),
		newServicesCreateCmd(d, cat),
		newServicesUpdateCmd(d, cat),
		newServicesDeleteCmd(d, cat),
		newServiceGroupCmd(d, cat),
	)
	return cmd
}

func serviceSvc(d RootDeps, cat *catalog.Catalog) *svc.ServiceSvc {
	return &svc.ServiceSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newServiceListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List service objects",
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
			out, err := serviceSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderServiceList(cmd, cat, "sophosfw.v1.serviceList", out)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newServiceShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one service by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			v, err := serviceSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.ServiceEnvelope(v)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n  Derived: protocol=%s portRange=%s\n",
				v.Name, v.Type, v.Derived.Protocol, v.Derived.PortRange)
			return nil
		},
	}
}

func newServiceSearchCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "search <query>",
		Short: "Substring search across service Name and synthesized portRange",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := serviceSvc(d, cat).Search(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			return renderServiceList(cmd, cat, "sophosfw.v1.serviceSearch", out)
		},
	}
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newServiceUsageCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var withRefs bool
	c := &cobra.Command{
		Use:   "usage <name>",
		Short: "Show ServicesStatistics for a service (optionally with reference graph)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := serviceSvc(d, cat).Usage(cmd.Context(), profile, args[0], withRefs)
			if err != nil {
				return err
			}
			b, err := render.ServiceUsageEnvelope(out)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
	c.Flags().BoolVar(&withRefs, "with-references", false, "scan reference graph (rules + groups) for the service")
	return c
}

func renderServiceList(cmd *cobra.Command, cat *catalog.Catalog, schema string, list *svc.ServiceList) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		b, err := render.ServiceListEnvelope(schema, list)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
	}
	entry, _ := cat.Resolve("Services")
	headers := resolveColumns(cmd, entry.Columns)
	rows := make([][]string, 0, len(list.Items))
	for _, v := range list.Items {
		rows = append(rows, serviceRow(v, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

func serviceRow(v svc.Service, headers []string) []string {
	row := make([]string, len(headers))
	for i, col := range headers {
		row[i] = serviceCell(v, col)
	}
	return row
}

func serviceCell(v svc.Service, col string) string {
	switch col {
	case "Name":
		return v.Name
	case "Type":
		return v.Type
	case "ServiceDetails":
		return v.Derived.PortRange // table-friendly substitute
	case "derived.protocol":
		return v.Derived.Protocol
	case "derived.portRange":
		return v.Derived.PortRange
	}
	return ""
}
