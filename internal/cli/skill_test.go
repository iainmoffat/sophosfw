package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkillDoctor_PassesWhenSkillExists(t *testing.T) {
	// Set up a fake project root with a fake skill that has all 12 required
	// strings split across examples.md and mcp-tools.md.
	dir := t.TempDir()
	skillDir := filepath.Join(dir, ".claude", "skills", "sophos-firewall")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"),
		[]byte(`# Skill\n\nReferences sophosfw cli + MCP.`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status
sophosfw object list IPHost
sophosfw raw get IPHost
sophosfw mcp serve
sophosfw host ip list
sophosfw service list
sophosfw firewall rule list
sophosfw nat rule list
sophosfw host ip create
sophosfw host ip delete`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "mcp-tools.md"),
		[]byte(`# MCP Tools\n\nIncludes host_ip_list and host_ip_create and other MCP tools.`), 0o600))

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
	// examples.md has only one of the required cli strings; mcp-tools.md
	// is present but has no required strings either.
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "mcp-tools.md"),
		[]byte(`# MCP Tools\n`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}

func TestSkillDoctor_FindsRequiredInMcpTools(t *testing.T) {
	// host_ip_list and host_ip_create live in mcp-tools.md, NOT examples.md. The other 10
	// required strings live in examples.md. Doctor must concatenate
	// both files and find all 12.
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`x`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status
sophosfw object list IPHost
sophosfw raw get IPHost
sophosfw mcp serve
sophosfw host ip list
sophosfw service list
sophosfw firewall rule list
sophosfw nat rule list
sophosfw host ip create
sophosfw host ip delete`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "mcp-tools.md"),
		[]byte(`# MCP Tools

The host_ip_list and host_ip_create tools list and mutate IPHost records.`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.NoError(t, root.Execute())
}

func TestSkillDoctor_FailsWhenMcpToolsMissing(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`x`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status
sophosfw object list IPHost
sophosfw raw get IPHost
sophosfw mcp serve
sophosfw host ip list
sophosfw service list
sophosfw firewall rule list
sophosfw nat rule list
host_ip_list`), 0o600))
	// mcp-tools.md intentionally NOT created.

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}
