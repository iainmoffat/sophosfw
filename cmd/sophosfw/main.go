package main

import (
	"os"

	"github.com/iainmoffat/sophosfw/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(cli.RootDeps{Version: version})
	if err := root.Execute(); err != nil {
		os.Exit(cli.HandleError(root, err))
	}
}
