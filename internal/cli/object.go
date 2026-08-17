package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newObjectCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "object", Short: "Generic Sophos object commands"}
	cmd.AddCommand(
		newObjectListCmd(d, cat),
		newObjectGetCmd(d, cat),
		newObjectUsageCmd(d, cat),
		newObjectSchemaCmd(d, cat),
	)
	return cmd
}

func newObjectListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list <xml-tag-or-alias>",
		Short: "List all objects of the given XML tag",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")

			var filter *sophos.FilterClause
			if filterStr != "" {
				f, err := sophos.ParseFilterFlag(filterStr)
				if err != nil {
					return err
				}
				filter = &f
			}

			out, err := s.List(cmd.Context(), profile, args[0], filter)
			if err != nil {
				return err
			}
			return renderObjectList(cmd, out, cat)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value (e.g. Name:like:LAN)")
	c.Flags().String("columns", "", "comma-separated column override (default: catalog columns)")
	return c
}

func renderObjectList(cmd *cobra.Command, out *svc.ObjectList, cat *catalog.Catalog) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		b, err := render.ObjectListEnvelope(out)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
	}
	entry, _ := cat.Resolve(out.Tag)
	headers := resolveColumns(cmd, entry.Columns)
	rows := make([][]string, 0, len(out.Items))
	for _, item := range out.Items {
		rows = append(rows, columnsFor(item, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

func columnsFor(item any, columns []string) []string {
	m, ok := item.(map[string]any)
	if !ok {
		// Round-trip through JSON to reach struct fields by name.
		b, _ := json.Marshal(item)
		_ = json.Unmarshal(b, &m)
	}
	row := make([]string, len(columns))
	for i, col := range columns {
		if v, ok := m[col]; ok {
			row[i] = stringify(v)
		}
	}
	return row
}

// listCellBudget is the width, in characters, that a member list may occupy
// in a table cell before the remainder is summarised as "+N more".
const listCellBudget = 60

// stringify renders one table cell.
//
// Group types carry list columns (HostList, ServiceList, FQDNHostList) whose
// decoded shape is a single-key container wrapping either a scalar (one
// member) or a slice (many) — see the decode contract in
// internal/sophos.xmlFragmentToMap. Rendering those with %v yields a Go map
// dump, so unwrap them to a member summary.
//
// A multi-member list is always prefixed with its count, and any members that
// do not fit are reported as "+N more" rather than dropped. Both halves of
// that matter: a bare truncated list would read as complete while hiding
// membership, and the count is the signal an operator can check a group's
// real size against. Use `object get` or --json for the full list.
func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		return summarizeList(t)
	case map[string]any:
		// Single-key container (the Sophos list shape): render the members.
		if len(t) == 1 {
			for _, inner := range t {
				return stringify(inner)
			}
		}
	}
	return fmt.Sprintf("%v", v)
}

// summarizeList renders a member slice as "N members: a, b, +K more",
// keeping whole member names within listCellBudget. At least one member is
// always shown so the cell is never just a count.
func summarizeList(items []any) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		return stringify(items[0])
	}
	var shown []string
	used := 0
	for _, e := range items {
		s := stringify(e)
		if len(shown) > 0 && used+len(s)+2 > listCellBudget {
			break
		}
		used += len(s) + 2
		shown = append(shown, s)
	}
	out := fmt.Sprintf("%d members: %s", len(items), strings.Join(shown, ", "))
	if rest := len(items) - len(shown); rest > 0 {
		out += fmt.Sprintf(", +%d more", rest)
	}
	return out
}

func newObjectGetCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var name string
	c := &cobra.Command{
		Use:   "get <xml-tag-or-alias>",
		Short: "Get a single object by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")
			obj, err := s.Get(cmd.Context(), profile, args[0], name)
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
	c.Flags().StringVar(&name, "name", "", "object name")
	_ = c.MarkFlagRequired("name")
	return c
}

func newObjectUsageCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var name string
	c := &cobra.Command{
		Use:   "usage <xml-tag-or-alias>",
		Short: "Show object usage / statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")
			u, err := s.Usage(cmd.Context(), profile, args[0], name)
			if err != nil {
				return err
			}
			b, err := render.ObjectUsageEnvelope(u)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
	c.Flags().StringVar(&name, "name", "", "object name to look up usage for")
	return c
}

func newObjectSchemaCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "schema <xml-tag-or-alias>",
		Short: "Print the catalog entry for an XML tag",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			e, err := s.Schema(args[0])
			if err != nil {
				return err
			}
			b, err := render.ObjectSchemaEnvelope(e)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
}
