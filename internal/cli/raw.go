package cli

import (
	"io"
	"os"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newRawCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "raw",
		Short: "Raw Sophos XML API access (escape hatch)",
	}
	cmd.AddCommand(newRawGetCmd(d), newRawRequestCmd(d))
	return cmd
}

func newRawGetCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "get <xml-tag>",
		Short: "Issue <Get><Tag></Tag></Get> for an arbitrary XML tag",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.RawSvc{Config: d.Config, Creds: d.Creds, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")
			r, err := s.Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			body := map[string]any{}
			for tag, recs := range r.Body {
				items := make([]string, 0, len(recs))
				for _, rec := range recs {
					items = append(items, string(rec))
				}
				body[tag] = items
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.rawResponse", map[string]any{
				"profile": r.Profile,
				"xmlTag":  r.Tag,
				"body":    body,
			})
		},
	}
}

func newRawRequestCmd(d RootDeps) *cobra.Command {
	var dryRun, yes bool
	c := &cobra.Command{
		Use:   "request <file|->",
		Short: "Send (preview) a hand-authored Sophos XML envelope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")

			var (
				body []byte
				err  error
			)
			if args[0] == "-" {
				body, err = io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
			} else {
				body, err = os.ReadFile(args[0])
				if err != nil {
					return err
				}
			}

			s := &svc.RawSvc{Config: d.Config, Creds: d.Creds, NewClient: d.NewClient}

			if !dryRun && !yes {
				dryRun = true // default to safety
			}

			if yes {
				return s.Apply(cmd.Context(), profile, body)
			}

			pv, err := s.Preview(cmd.Context(), profile, body)
			if err != nil {
				return err
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.preview", map[string]any{
				"profile":        pv.Profile,
				"mutating":       pv.Mutating,
				"verbs":          pv.Verbs,
				"redactedXml":    pv.RedactedXML,
				"wouldSendBytes": pv.WouldSendBytes,
				"warning":        pv.Warning,
			})
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview only (default in foundation phase)")
	c.Flags().BoolVar(&yes, "yes", false, "(reserved) apply path is not implemented in foundation")
	return c
}
