package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/safety"
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
			b, err := render.RawResponseEnvelope(r)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
}

func newRawRequestCmd(d RootDeps) *cobra.Command {
	var dryRun, yes, confirmMutating bool
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

			s := &svc.RawSvc{Config: d.Config, Creds: d.Creds, NewClient: d.NewClient, Audit: d.Audit}

			if !dryRun && !yes {
				dryRun = true // default to safety
			}

			if yes {
				if mutating, _ := safety.IsMutating(body); mutating && !confirmMutating {
					return fmt.Errorf("raw request: envelope contains mutating verbs (Set/Remove); pass --confirm-mutating to acknowledge intent (with --yes)")
				}
				if err := s.Apply(cmd.Context(), profile, body); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "ok")
				return nil
			}

			pv, err := s.Preview(cmd.Context(), profile, body)
			if err != nil {
				return err
			}
			b, err := render.PreviewEnvelope(pv)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview only (default in foundation phase)")
	c.Flags().BoolVar(&yes, "yes", false, "send the envelope to the firewall")
	c.Flags().BoolVar(&confirmMutating, "confirm-mutating", false, "required when --yes is used and the envelope contains Set/Remove verbs")
	return c
}
