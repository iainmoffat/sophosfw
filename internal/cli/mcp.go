package cli

import (
	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/mcp"
	"github.com/spf13/cobra"
)

func newMCPCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "mcp", Short: "MCP server commands"}
	cmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server (foundation phase: zero tools registered)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s := mcp.NewServer(mcp.Deps{
				Config:  d.Config,
				Creds:   d.Creds,
				Catalog: cat,
			})
			return s.Serve(cmd.Context(), cmd.OutOrStdout())
		},
	})
	return cmd
}
