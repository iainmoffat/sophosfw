package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionCommand_PrintsVersion(t *testing.T) {
	root := NewRoot(RootDeps{Version: "1.2.3"})
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetArgs([]string{"version"})

	require.NoError(t, root.Execute())
	require.True(t, strings.Contains(out.String(), "1.2.3"),
		"expected output to contain version, got: %q", out.String())
}
