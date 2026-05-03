package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/cli"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

var version = "dev"

func main() {
	baseDir, err := config.DefaultBaseDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config dir:", err)
		os.Exit(2)
	}
	cfg, err := config.Load(baseDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config load:", err)
		os.Exit(2)
	}
	store := creds.New(baseDir)
	audit := svc.NewAuditLog(baseDir, cfg.AuditLogEnabled())

	// rootCmd is captured by the NewClient closure so the closure can read
	// --insecure-skip-verify at call time. Cobra parses flags before any
	// subcommand RunE fires, so by the time NewClient is invoked the flag
	// value is available.
	var rootCmd *cobra.Command
	rootCmd = cli.NewRoot(cli.RootDeps{
		Version:  version,
		BaseDir:  baseDir,
		SkillDir: filepath.Join(".claude", "skills", "sophos-firewall"),
		Config:   cfg,
		Creds:    store,
		Audit:    audit,
		NewClient: func(p config.Profile, c creds.Credentials) svc.Client {
			skip := false
			if rootCmd != nil {
				skip, _ = rootCmd.PersistentFlags().GetBool("insecure-skip-verify")
			}
			return svc.DefaultClientFactory(skip)(p, c)
		},
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(cli.HandleError(rootCmd, err))
	}
}
