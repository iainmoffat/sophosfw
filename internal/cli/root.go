package cli

import (
	"github.com/spf13/cobra"
)

// RootDeps holds dependencies injected into the root command. Keeping this
// explicit lets tests construct a root with controlled state.
type RootDeps struct {
	Version string
}

// NewRoot constructs the cobra root command with all subcommands wired in.
func NewRoot(d RootDeps) *cobra.Command {
	root := &cobra.Command{
		Use:           "sophosfw",
		Short:         "Sophos Firewall CLI + MCP server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags are added in later tasks (auth/object/raw etc.).
	root.PersistentFlags().String("profile", "", "config profile to use (default: currentProfile from config)")
	root.PersistentFlags().Bool("json", false, "emit JSON envelope output instead of tables")
	root.PersistentFlags().Duration("timeout", 0, "override per-request timeout")
	root.PersistentFlags().Bool("debug", false, "verbose logging (credentials always redacted)")

	root.AddCommand(newVersionCmd(d))

	return root
}
