package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMCPServe_PrintsStartupAndExitsOnContextCancel(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	root.SetContext(ctx)
	root.SetArgs([]string{"mcp", "serve"})

	err := root.Execute()
	// We expect either nil (clean shutdown) or context-canceled — both are OK.
	if err != nil {
		require.True(t, strings.Contains(err.Error(), "context"), "unexpected error: %v", err)
	}
	require.Contains(t, out.String(), "0 tools registered")
}
