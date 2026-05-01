package main

import (
	"fmt"
	"os"

	"github.com/iainmoffat/sophosfw/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(cli.RootDeps{Version: version})
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
