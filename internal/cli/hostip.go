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
		newHostIpCreateCmd(d, cat),
		newHostIpUpdateCmd(d, cat),
		newHostIpDeleteCmd(d, cat),
	)
	return cmd
}

func hostIpSvc(d RootDeps, cat *catalog.Catalog) *svc.HostIPSvc {
	return &svc.HostIPSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit: d.Audit,
	}
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
	var includeDiffHash bool
	cmd := &cobra.Command{
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
				var b []byte
				if includeDiffHash {
					hash, err := svc.DiffHash(h.IPHost)
					if err != nil {
						return err
					}
					b, err = render.HostIPEnvelopeWithDiffHash(h, hash)
					if err != nil {
						return err
					}
				} else {
					var err error
					b, err = render.HostIPEnvelope(h)
					if err != nil {
						return err
					}
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n  IPAddress: %s\n  Subnet:    %s\n  Derived:   kind=%s cidr=%s\n",
				h.Name, h.HostType, h.IPAddress, h.Subnet, h.Derived.Kind, h.Derived.CIDR)
			return nil
		},
	}
	cmd.Flags().BoolVar(&includeDiffHash, "include-diff-hash", true, "include _diffHash in JSON output")
	return cmd
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
			b, err := render.HostIPUsageEnvelope(out)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
	c.Flags().BoolVar(&withRefs, "with-references", false, "scan reference graph (rules + groups) for the host")
	return c
}

func renderHostIpList(cmd *cobra.Command, cat *catalog.Catalog, schema string, list *svc.HostIPList) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		b, err := render.HostIPListEnvelope(schema, list)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
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

func newHostIpCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var (
		name       string
		hostType   string
		ipAddress  string
		subnet     string
		startIP    string
		endIP      string
		ipFamily   string
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new IP host object",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			input := svc.HostIPCreateInput{
				Name:      name,
				HostType:  hostType,
				IPAddress: ipAddress,
				Subnet:    subnet,
				IPFamily:  ipFamily,
			}
			if hostType == "IPRange" {
				input.StartIPAddress = startIP
				input.EndIPAddress = endIP
			}
			result, err := hostIpSvc(d, cat).Create(cmd.Context(), profile, input, !yes)
			if err != nil {
				return err
			}
			if result.DryRun {
				jsonMode, _ := cmd.Flags().GetBool("json")
				if jsonMode {
					b, err := render.PreviewEnvelope(result.Preview)
					if err != nil {
						return err
					}
					_, err = cmd.OutOrStdout().Write(b)
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Dry run: would send %d bytes\n", result.Preview.WouldSendBytes)
				return nil
			}
			return renderHostIpMutation(cmd, "create", result)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "name of the host object")
	cmd.Flags().StringVar(&hostType, "host-type", "Network", "host type (Network|IP|IPRange|IPList)")
	cmd.Flags().StringVar(&ipAddress, "ip-address", "", "IP address")
	cmd.Flags().StringVar(&subnet, "subnet", "", "subnet mask")
	cmd.Flags().StringVar(&startIP, "start-ip", "", "start IP for IPRange")
	cmd.Flags().StringVar(&endIP, "end-ip", "", "end IP for IPRange")
	cmd.Flags().StringVar(&ipFamily, "ip-family", "IPv4", "IP family (IPv4|IPv6)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (skip dry-run)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newHostIpUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var (
		name           string
		hostType       string
		ipAddress      string
		subnet         string
		startIP        string
		endIP          string
		ipFamily       string
		expectedHash   string
		ignoreHash     bool
		yes            bool
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an existing IP host object",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for update --yes (or pass --ignore-diff-hash)")
			}
			profile, _ := cmd.Flags().GetString("profile")
			input := svc.HostIPCreateInput{
				Name:      name,
				HostType:  hostType,
				IPAddress: ipAddress,
				Subnet:    subnet,
				IPFamily:  ipFamily,
			}
			if hostType == "IPRange" {
				input.StartIPAddress = startIP
				input.EndIPAddress = endIP
			}
			result, err := hostIpSvc(d, cat).Update(cmd.Context(), profile, input, expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			if result.DryRun {
				jsonMode, _ := cmd.Flags().GetBool("json")
				if jsonMode {
					b, err := render.PreviewEnvelope(result.Preview)
					if err != nil {
						return err
					}
					_, err = cmd.OutOrStdout().Write(b)
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Dry run: would send %d bytes\n", result.Preview.WouldSendBytes)
				return nil
			}
			return renderHostIpMutation(cmd, "update", result)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "name of the host object")
	cmd.Flags().StringVar(&hostType, "host-type", "Network", "host type (Network|IP|IPRange|IPList)")
	cmd.Flags().StringVar(&ipAddress, "ip-address", "", "IP address")
	cmd.Flags().StringVar(&subnet, "subnet", "", "subnet mask")
	cmd.Flags().StringVar(&startIP, "start-ip", "", "start IP for IPRange")
	cmd.Flags().StringVar(&endIP, "end-ip", "", "end IP for IPRange")
	cmd.Flags().StringVar(&ipFamily, "ip-family", "IPv4", "IP family (IPv4|IPv6)")
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "expected diff hash for optimistic concurrency")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip diff hash check")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (skip dry-run)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newHostIpDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var (
		expectedHash string
		ignoreHash   bool
		yes          bool
	)
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an IP host object",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			profile, _ := cmd.Flags().GetString("profile")
			result, err := hostIpSvc(d, cat).Delete(cmd.Context(), profile, args[0], expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			if result.DryRun {
				jsonMode, _ := cmd.Flags().GetBool("json")
				if jsonMode {
					b, err := render.PreviewEnvelope(result.Preview)
					if err != nil {
						return err
					}
					_, err = cmd.OutOrStdout().Write(b)
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Dry run: would send %d bytes\n", result.Preview.WouldSendBytes)
				return nil
			}
			return renderHostIpMutation(cmd, "delete", result)
		},
	}
	cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "expected diff hash for optimistic concurrency")
	cmd.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip diff hash check")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the change (skip dry-run)")
	return cmd
}

func renderHostIpMutation(cmd *cobra.Command, operation string, result *svc.HostIPMutationResult) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if !jsonMode {
		fmt.Fprintf(cmd.OutOrStdout(), "%s applied\n", operation)
		return nil
	}
	b, err := render.HostIpMutationEnvelope(operation, true, result.Profile)
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(b)
	return err
}
