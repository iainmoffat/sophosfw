// Package cli — `sophosfw backup` (+ list + rotate) commands.
//
// The default `sophosfw backup` writes a per-record YAML snapshot tree
// under ~/.config/sophosfw/profiles/<name>/backups/<utc>/. `backup list`
// enumerates existing snapshots newest-first; `backup rotate --keep N`
// deletes all but the N most recent.
//
// All three commands route through BackupSvc and surface the
// sophosfw.v1.backup{Create,List} envelopes when --json is passed.
package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newBackupCmd is the top-level `backup` command. The default action
// (no subcommand) creates a new snapshot. `list` and `rotate` are
// attached as subcommands for management ops.
func newBackupCmd(d RootDeps) *cobra.Command {
	var outDir string
	var typesCSV, excludeCSV string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Snapshot the firewall config (per-record YAML tree)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			opts := svc.BackupCreateOptions{OutDir: outDir}
			if typesCSV != "" {
				opts.Types = splitCSV(typesCSV)
			}
			if excludeCSV != "" {
				opts.Exclude = splitCSV(excludeCSV)
			}
			s, err := backupSvc(d)
			if err != nil {
				return err
			}
			result, err := s.Create(cmd.Context(), profile, opts)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				body, err := render.BackupCreateEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(body)
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Backup written: %s\n", result.Path)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Profile: %s\n", result.Profile)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Records: %d across %d types\n",
				result.TotalRecords, len(result.TypesIncluded))
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "",
		"snapshot directory (default: ~/.config/sophosfw/profiles/<name>/backups/<utc>)")
	cmd.Flags().StringVar(&typesCSV, "types", "",
		"comma-separated catalog tags to include (default: all)")
	cmd.Flags().StringVar(&excludeCSV, "exclude", "",
		"comma-separated catalog tags to skip (mutually exclusive with --types)")

	cmd.AddCommand(newBackupListCmd(d))
	cmd.AddCommand(newBackupRotateCmd(d))
	return cmd
}

// newBackupListCmd: `sophosfw backup list`. Empty list prints
// "No snapshots." for human mode; --json always emits a (possibly
// empty) sophosfw.v1.backupList envelope.
func newBackupListCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List existing snapshots for the current profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			s, err := backupSvc(d)
			if err != nil {
				return err
			}
			entries, err := s.List(profile)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				body, err := render.BackupListEnvelope(profile, entries)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(body)
				return err
			}
			if len(entries) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No snapshots.")
				return nil
			}
			for _, e := range entries {
				total := 0
				for _, n := range e.RecordCounts {
					total += n
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  (%d records)\n",
					e.CreatedAt.UTC().Format(time.RFC3339), e.Path, total)
			}
			return nil
		},
	}
	return cmd
}

// newBackupRotateCmd: `sophosfw backup rotate --keep N`. --keep is
// required (cobra rejects with "required flag(s) ... not set"); the
// service layer rejects negative keep with ErrInvalidRequest.
func newBackupRotateCmd(d RootDeps) *cobra.Command {
	var keep int
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Delete snapshots, keeping the N most recent",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			s, err := backupSvc(d)
			if err != nil {
				return err
			}
			deleted, err := s.Rotate(profile, keep)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d snapshot(s).\n", len(deleted))
			for _, p := range deleted {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", p)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&keep, "keep", -1, "number of most recent snapshots to keep (required)")
	_ = cmd.MarkFlagRequired("keep")
	return cmd
}

// backupSvc resolves a BackupSvc from RootDeps. The catalog is built
// inline (RootDeps does not carry one); BuildVersion (RootDeps.Version)
// is injected so _meta.yaml records the running sophosfw build.
func backupSvc(d RootDeps) (*svc.BackupSvc, error) {
	cat, err := catalog.NewDefault()
	if err != nil {
		return nil, err
	}
	return &svc.BackupSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Catalog: cat,
		BaseDir: d.BaseDir,
		Now:     time.Now,
		Version: d.Version,
	}, nil
}

// splitCSV parses a comma-separated flag value into a clean slice of
// trimmed non-empty strings. "a, b ,, c" → ["a", "b", "c"].
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
