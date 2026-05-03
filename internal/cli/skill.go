package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var requiredCommandsInExamples = []string{
	"sophosfw auth status",        // Phase 1
	"sophosfw object list",        // Phase 2
	"sophosfw raw get",            // Phase 2
	"sophosfw mcp serve",          // Phase 2
	"sophosfw host ip list",       // Phase 3
	"sophosfw service list",       // Phase 3
	"sophosfw firewall rule list", // Phase 3
	"sophosfw nat rule list",      // Phase 3
	"host_ip_list",                // Phase 4 MCP sentinel; if this is documented, the rest of the MCP surface is too
	// Phase 6 additions:
	"sophosfw host ip create",
	"sophosfw host ip delete",
	"host_ip_create", // MCP sentinel for mutating tools
}

func newSkillCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "skill", Short: "Agent-skill maintenance helpers"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "path",
			Short: "Print the absolute path to the installed agent skill",
			RunE: func(cmd *cobra.Command, _ []string) error {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), d.SkillDir)
				return nil
			},
		},
		&cobra.Command{
			Use:   "doctor",
			Short: "Validate that the agent skill is in sync with the implementation",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runSkillDoctor(cmd.OutOrStdout(), d.SkillDir)
			},
		},
	)
	return cmd
}

func runSkillDoctor(out io.Writer, skillDir string) error {
	if _, err := os.Stat(skillDir); err != nil {
		return fmt.Errorf("skill directory missing: %s", skillDir)
	}
	if _, err := os.Stat(filepath.Join(skillDir, "SKILL.md")); err != nil {
		return fmt.Errorf("SKILL.md missing in %s", skillDir)
	}

	examplesBody, err := os.ReadFile(filepath.Join(skillDir, "examples.md"))
	if err != nil {
		return fmt.Errorf("examples.md missing in %s: %w", skillDir, err)
	}
	mcpToolsBody, err := os.ReadFile(filepath.Join(skillDir, "mcp-tools.md"))
	if err != nil {
		return fmt.Errorf("mcp-tools.md missing in %s: %w", skillDir, err)
	}

	haystack := string(examplesBody) + "\n" + string(mcpToolsBody)

	missing := []string{}
	for _, req := range requiredCommandsInExamples {
		if !strings.Contains(haystack, req) {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required surface not documented in examples.md or mcp-tools.md: %s", strings.Join(missing, ", "))
	}
	_, _ = fmt.Fprintln(out, "skill ok")
	return nil
}
