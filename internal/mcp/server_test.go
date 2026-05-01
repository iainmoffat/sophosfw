package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/stretchr/testify/require"
)

func TestServer_StartupExercisesSeam(t *testing.T) {
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	store := creds.NewFileStore(t.TempDir())

	s := NewServer(Deps{
		Config:  cfg,
		Creds:   store,
		Catalog: cat,
	})
	msg, err := s.StartupReport(context.Background())
	require.NoError(t, err)
	require.True(t, strings.Contains(msg, "0 tools registered"),
		"got: %s", msg)
}
