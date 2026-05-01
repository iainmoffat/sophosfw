package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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

	root := cli.NewRoot(cli.RootDeps{
		Version:  version,
		BaseDir:  baseDir,
		SkillDir: filepath.Join(".claude", "skills", "sophos-firewall"),
		Config:   cfg,
		Creds:    store,
		NewClient: func(p config.Profile, c creds.Credentials) svc.Client {
			// Wire CLI flags here once we have access to them; for now, use defaults.
			return svc.DefaultClientFactory(false)(p, c)
		},
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(cli.HandleError(root, err))
	}
}
