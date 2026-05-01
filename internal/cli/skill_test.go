package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkillDoctor_PassesWhenSkillExists(t *testing.T) {
	// Set up a fake project root with a fake skill.
	dir := t.TempDir()
	skillDir := filepath.Join(dir, ".claude", "skills", "sophos-firewall")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"),
		[]byte(`# Skill

References sophosfw auth status, sophosfw object list, sophosfw raw get, sophosfw mcp serve.`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status
sophosfw object list IPHost
sophosfw raw get IPHost
sophosfw mcp serve`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.NoError(t, root.Execute())
}

func TestSkillDoctor_FailsWhenSkillMissing(t *testing.T) {
	d, _ := newRootForTest(t)
	d.SkillDir = filepath.Join(t.TempDir(), "absent")
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}

func TestSkillDoctor_FailsIfRequiredCommandMissingFromExamples(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`x`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}
