package cli

import (
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/mcp"
	"github.com/spf13/cobra"
)

func newMCPCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "mcp", Short: "MCP server commands"}
	cmd.AddCommand(newMCPServeCmd(d, cat))
	return cmd
}

func newMCPServeCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var defaultProfile string
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server (Phase 4: 21 read-only tools, stdio transport)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s := mcp.NewServer(d.Version, mcp.Deps{
				Config:         d.Config,
				Creds:          d.Creds,
				Catalog:        cat,
				NewClient:      d.NewClient,
				DefaultProfile: defaultProfile,
			})
			return s.Serve(cmd.Context(), &sdkmcp.StdioTransport{})
		},
	}
	c.Flags().StringVar(&defaultProfile, "profile", "", "default profile for tool calls (empty = config currentProfile)")
	return c
}
