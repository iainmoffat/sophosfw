package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// addTwoProfilesForSetMgmt registers two profiles ("home", "work") so that
// AddProfileSet's member-existence check passes.
func addTwoProfilesForSetMgmt(t *testing.T, root *bytes.Buffer, cmd executeFn) {
	t.Helper()
	cmd([]string{"auth", "profile", "add", "home", "--url", "https://h:4444"})
	cmd([]string{"auth", "profile", "add", "work", "--url", "https://w:4444"})
	root.Reset()
}

type executeFn func(args []string)

func TestCmd_AuthProfileSetAdd_PersistsToConfig(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	exec := func(args []string) {
		root.SetArgs(args)
		require.NoError(t, root.Execute())
	}
	addTwoProfilesForSetMgmt(t, out, exec)

	out.Reset()
	root.SetArgs([]string{"auth", "profile", "set", "add", "staging", "home,work"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"staging" saved with 2 member(s)`)

	require.Equal(t, []string{"home", "work"}, d.Config.ProfileSets["staging"])
}

func TestCmd_AuthProfileSetAdd_RejectsCollision(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	exec := func(args []string) {
		root.SetArgs(args)
		require.NoError(t, root.Execute())
	}
	addTwoProfilesForSetMgmt(t, out, exec)

	// Try to create a set named "home" — collides with profile name.
	out.Reset()
	root.SetArgs([]string{"auth", "profile", "set", "add", "home", "home,work"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "collides with profile name")
	require.NotContains(t, d.Config.ProfileSets, "home")
}

func TestCmd_AuthProfileSetList_Empty(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	root.SetArgs([]string{"auth", "profile", "set", "list"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "No profile sets.")
	_ = d
}

func TestCmd_AuthProfileSetList_JSONShape(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	exec := func(args []string) {
		root.SetArgs(args)
		require.NoError(t, root.Execute())
	}
	addTwoProfilesForSetMgmt(t, out, exec)
	exec([]string{"auth", "profile", "set", "add", "staging", "home,work"})

	out.Reset()
	root.SetArgs([]string{"auth", "profile", "set", "list", "--json"})
	require.NoError(t, root.Execute())

	var payload struct {
		Schema string              `json:"schema"`
		Sets   map[string][]string `json:"sets"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &payload))
	require.Equal(t, "sophosfw.v1.profileSetList", payload.Schema)
	require.Equal(t, []string{"home", "work"}, payload.Sets["staging"])
	_ = d
}

func TestCmd_AuthProfileSetRemove(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	exec := func(args []string) {
		root.SetArgs(args)
		require.NoError(t, root.Execute())
	}
	addTwoProfilesForSetMgmt(t, out, exec)
	exec([]string{"auth", "profile", "set", "add", "staging", "home,work"})
	require.Contains(t, d.Config.ProfileSets, "staging")

	out.Reset()
	root.SetArgs([]string{"auth", "profile", "set", "remove", "staging"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"staging" removed`)
	require.NotContains(t, d.Config.ProfileSets, "staging")
}

func TestCmd_AuthProfileSetRemove_NotFound(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	root.SetArgs([]string{"auth", "profile", "set", "remove", "missing"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "not found")
	_ = d
}
