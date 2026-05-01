package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print sophosfw version, commit, and Go runtime",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"sophosfw %s (%s/%s, %s)\n",
				d.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return err
		},
	}
}
