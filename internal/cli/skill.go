package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var requiredCommandsInExamples = []string{
	"sophosfw auth status",
	"sophosfw object list",
	"sophosfw raw get",
	"sophosfw mcp serve",
}

func newSkillCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "skill", Short: "Agent-skill maintenance helpers"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "path",
			Short: "Print the absolute path to the installed agent skill",
			RunE: func(cmd *cobra.Command, _ []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), d.SkillDir)
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

func runSkillDoctor(out interface{ Write([]byte) (int, error) }, skillDir string) error {
	if _, err := os.Stat(skillDir); err != nil {
		return fmt.Errorf("skill directory missing: %s", skillDir)
	}

	skillFile := filepath.Join(skillDir, "SKILL.md")
	if _, err := os.Stat(skillFile); err != nil {
		return fmt.Errorf("SKILL.md missing in %s", skillDir)
	}

	examplesFile := filepath.Join(skillDir, "examples.md")
	body, err := os.ReadFile(examplesFile)
	if err != nil {
		return fmt.Errorf("examples.md missing in %s: %w", skillDir, err)
	}
	text := string(body)
	missing := []string{}
	for _, req := range requiredCommandsInExamples {
		if !strings.Contains(text, req) {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("examples.md is missing required commands: %s", strings.Join(missing, ", "))
	}
	fmt.Fprintln(out, "skill ok")
	return nil
}
