package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMCPServe_StartsAndExitsOnContextCancel(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	// Stdin must be a real readable thing for the SDK transport.
	// We give it an empty pipe; SDK will not get a request before ctx times out.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	root.SetContext(ctx)
	root.SetArgs([]string{"mcp", "serve"})

	err := root.Execute()
	if err != nil {
		require.True(t,
			strings.Contains(err.Error(), "context") || strings.Contains(err.Error(), "EOF"),
			"unexpected error: %v", err)
	}
}
