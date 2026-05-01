package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// resolveColumns returns the column list for a list-style table render. If
// the cobra command has a --columns flag set to a non-empty value, the
// caller-supplied list (split on commas) wins; otherwise the catalog
// default is returned. Whitespace around comma-separated names is trimmed.
func resolveColumns(cmd *cobra.Command, defaultCols []string) []string {
	v, _ := cmd.Flags().GetString("columns")
	if v == "" {
		return defaultCols
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return defaultCols
	}
	return out
}
