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

func newScheduleCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "schedule", Short: "Schedule first-class commands"}
	cmd.AddCommand(newScheduleListCmd(d, cat), newScheduleShowCmd(d, cat), newScheduleCreateCmd(d, cat), newScheduleUpdateCmd(d, cat), newScheduleDeleteCmd(d, cat))
	return cmd
}

func scheduleSvc(d RootDeps, cat *catalog.Catalog) *svc.ScheduleSvc {
	return &svc.ScheduleSvc{Inner: &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}, Audit: d.Audit}
}

func newScheduleListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{Use: "list", Short: "List schedules", RunE: func(cmd *cobra.Command, _ []string) error {
		profile, _ := cmd.Flags().GetString("profile")
		var filter *sophos.FilterClause
		if filterStr != "" {
			f, err := sophos.ParseFilterFlag(filterStr)
			if err != nil {
				return err
			}
			filter = &f
		}
		out, err := scheduleSvc(d, cat).List(cmd.Context(), profile, filter)
		if err != nil {
			return err
		}
		jsonMode, _ := cmd.Flags().GetBool("json")
		if jsonMode {
			b, err := render.ScheduleListEnvelope(out)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		}
		rows := make([][]string, 0, len(out.Items))
		for _, item := range out.Items {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			rows = append(rows, []string{stringField(m, "Name"), stringField(m, "Type"), schedulePeriodsCell(m)})
		}
		return render.WriteTable(cmd.OutOrStdout(), []string{"NAME", "TYPE", "PERIODS"}, rows)
	}}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newScheduleShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var withRefs bool
	return &cobra.Command{Use: "show <name>", Short: "Show one schedule", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		profile, _ := cmd.Flags().GetString("profile")
		out, err := scheduleSvc(d, cat).Show(cmd.Context(), profile, args[0], withRefs)
		if err != nil {
			return err
		}
		jsonMode, _ := cmd.Flags().GetBool("json")
		if jsonMode {
			b, err := render.ScheduleShowEnvelope(out)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		}
		m, ok := out.Object.Data.(map[string]any)
		if !ok {
			return fmt.Errorf("schedule %q data is not an object", args[0])
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Name: %s\nType: %s\n", stringField(m, "Name"), stringField(m, "Type"))
		if desc, ok := m["Description"]; ok {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Description: %v\n", desc)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Periods:")
		for _, p := range schedulePeriods(m) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", p)
		}
		hash, err := svc.DiffHash(m)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "DiffHash: %s\n", hash)
		if out.References != nil {
			names := out.References.Refs["FirewallRule"]
			by := "none"
			if len(names) > 0 {
				by = strings.Join(names, ", ")
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Referenced by FirewallRule: %s\n", by)
			if e := out.References.Errors["FirewallRule"]; e != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Reference scan errors: %s\n", e)
			}
		}
		return nil
	}}
}

func schedulePeriodsCell(record map[string]any) string {
	periods := schedulePeriods(record)
	if len(periods) == 0 {
		return "-"
	}
	if len(periods) == 1 {
		return periods[0]
	}
	items := make([]any, len(periods))
	for i, p := range periods {
		items[i] = p
	}
	return summarizeCell(items, "periods")
}

func schedulePeriods(record map[string]any) []string {
	details, ok := record["ScheduleDetails"].(map[string]any)
	if !ok {
		return nil
	}
	value, ok := details["ScheduleDetail"]
	if !ok || value == nil {
		return nil
	}
	values, ok := value.([]any)
	if !ok {
		values = []any{value}
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s-%s", stringField(m, "Days"), stringField(m, "StartTime"), stringField(m, "StopTime")))
	}
	return out
}

func stringField(m map[string]any, key string) string { s, _ := m[key].(string); return s }
