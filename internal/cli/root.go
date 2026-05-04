package cli

import (
	"errors"
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
	Audit     *svc.AuditLog
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
	root.AddCommand(newFirewallCmd(d, cat))
	root.AddCommand(newNATCmd(d, cat))
	root.AddCommand(newBackupCmd(d))
	root.AddCommand(newDriftCmd(d))

	return root
}

// HandleError maps a returned error to an exit code, printing either an
// error envelope (JSON mode) or a friendly stderr line. Use this from main().
func HandleError(cmd *cobra.Command, err error) int {
	if err == nil {
		return 0
	}
	// ErrDriftDetected is a normal output mode for `sophosfw drift`,
	// not an error condition: exit 1 silently so callers behave like
	// `git diff --exit-code`.
	if errors.Is(err, ErrDriftDetected) {
		return 1
	}
	// Fan-out outcome sentinels: per-profile output already explained
	// the failure, so HandleError must NOT print an additional error
	// line/envelope. Exit codes mirror the design spec:
	//   1 = pre-flight failed (mirrors "drift detected" semantics)
	//   2 = apply failed mid-fleet (more severe — partial state on the
	//       firewall fleet; operator must investigate immediately).
	if errors.Is(err, ErrFanoutPreflightFailed) {
		return 1
	}
	if errors.Is(err, ErrFanoutApplyFailed) {
		return 2
	}
	kind := ErrorKind(err)
	jsonMode, _ := cmd.Flags().GetBool("json")
	profile, _ := cmd.Flags().GetString("profile")

	if jsonMode {
		_ = render.WriteError(os.Stderr, kind, err.Error(), profile, nil)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "error (%s): %v\n", kind, err)
	}
	return ExitCodeFor(kind)
}
