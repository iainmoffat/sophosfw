package cli

import (
	"fmt"
	"os"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

// RootDeps holds dependencies injected into the root command.
type RootDeps struct {
	Version   string
	BaseDir   string
	SkillDir  string
	Config    *config.Config
	Creds     creds.Store
	NewClient svc.ClientFactory
}

// NewRoot constructs the cobra root command with all subcommands wired in.
func NewRoot(d RootDeps) *cobra.Command {
	root := &cobra.Command{
		Use:           "sophosfw",
		Short:         "Sophos Firewall CLI + MCP server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().String("profile", "", "config profile to use (default: currentProfile from config)")
	root.PersistentFlags().Bool("json", false, "emit JSON envelope output instead of tables")
	root.PersistentFlags().Duration("timeout", 0, "override per-request timeout")
	root.PersistentFlags().Bool("debug", false, "verbose logging (credentials always redacted)")
	root.PersistentFlags().Bool("insecure-skip-verify", false, "DANGER: skip TLS certificate verification for this invocation")

	root.AddCommand(newVersionCmd(d))
	root.AddCommand(newAuthCmd(d))
	root.AddCommand(newSkillCmd(d))

	cat, _ := catalog.NewDefault()
	root.AddCommand(newObjectCmd(d, cat))
	root.AddCommand(newRawCmd(d))
	root.AddCommand(newMCPCmd(d, cat))
	root.AddCommand(newHostCmd(d, cat))
	root.AddCommand(newServiceCmd(d, cat))

	return root
}

// HandleError maps a returned error to an exit code, printing either an
// error envelope (JSON mode) or a friendly stderr line. Use this from main().
func HandleError(cmd *cobra.Command, err error) int {
	if err == nil {
		return 0
	}
	kind := ErrorKind(err)
	jsonMode, _ := cmd.Flags().GetBool("json")
	profile, _ := cmd.Flags().GetString("profile")

	if jsonMode {
		_ = render.WriteError(os.Stderr, kind, err.Error(), profile, nil)
	} else {
		fmt.Fprintf(os.Stderr, "error (%s): %v\n", kind, err)
	}
	return ExitCodeFor(kind)
}
