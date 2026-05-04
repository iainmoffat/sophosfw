// Package mcp profileset_mgmt_test.go: tests for the read-only
// auth_profile_set_list MCP tool. Profile-set add/remove are CLI-only;
// agents discover sets through this read-only handler and then pass the
// set name to a mutating tool's `profileSet` field.
package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// newProfileSetTestServer builds an MCP server with caller-supplied
// profile sets installed in config. No firewall calls are made by the
// list handler so a nil client factory is fine.
func newProfileSetTestServer(t *testing.T, sets map[string][]string) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://h:4444"})
	for name, members := range sets {
		// Register the member profiles first so AddProfileSet's
		// allowlist check passes.
		for _, m := range members {
			if _, ok := cfg.Profiles[m]; !ok {
				cfg.AddProfile(m, config.Profile{URL: "https://" + m + ":4444"})
			}
		}
		require.NoError(t, cfg.AddProfileSet(name, members))
	}
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return nil },
		DefaultProfile: "home",
	})
}

func TestAuthProfileSetList_Handler_Empty(t *testing.T) {
	s := newProfileSetTestServer(t, nil)
	out, _, err := s.handleAuthProfileSetList(context.Background(), nil, AuthProfileSetListInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.profileSetList"`)
	// With no sets defined, ProfileSets is nil and json.Marshal renders
	// the field as null. Either form is acceptable for the empty case;
	// the schema field is the load-bearing assertion.
	require.Contains(t, body, `"sets"`)
}

func TestAuthProfileSetList_Handler_ReturnsSets(t *testing.T) {
	s := newProfileSetTestServer(t, map[string][]string{
		"staging":    {"home", "office"},
		"production": {"home"},
	})
	out, _, err := s.handleAuthProfileSetList(context.Background(), nil, AuthProfileSetListInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.profileSetList"`)
	require.Contains(t, body, `"staging"`)
	require.Contains(t, body, `"production"`)
	require.Contains(t, body, `"home"`)
	require.Contains(t, body, `"office"`)
}
