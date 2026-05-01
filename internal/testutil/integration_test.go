//go:build integration

package testutil

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func loadProfile(t *testing.T) (config.Profile, creds.Credentials) {
	t.Helper()
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName, "set SOPHOSFW_PROFILE for integration tests")

	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	p, _, err := cfg.ActiveProfile(profileName)
	require.NoError(t, err)

	store := creds.New(baseDir)
	c, err := store.Load(profileName)
	require.NoError(t, err)
	return p, c
}

func newClient(t *testing.T) *IntegrationClient {
	t.Helper()
	p, c := loadProfile(t)
	inner := sophos.NewClient(sophos.ClientConfig{
		BaseURL:  p.URL,
		Username: c.Username,
		Password: c.Password,
		Timeout:  15 * time.Second,
	})
	return NewIntegrationClient(inner)
}

func TestIntegration_AuthTest_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}},
	})
	require.NoError(t, err)
}

func TestIntegration_CatalogTagsAllRoundTrip(t *testing.T) {
	c := newClient(t)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)

	for _, tag := range cat.Tags() {
		t.Run(tag, func(t *testing.T) {
			_, err := c.Do(context.Background(), sophos.Envelope{
				Operations: []sophos.Op{sophos.GetOp{XMLTag: tag}},
			})
			// Some tags may legitimately 404 in an empty environment;
			// accept ErrNotFound but reject auth/permission/server failures.
			if err != nil && !errorsIsAny(err, sophos.ErrNotFound) {
				t.Fatalf("tag %q: unexpected error: %v", tag, err)
			}
		})
	}
}

func errorsIsAny(err error, targets ...error) bool {
	for _, t := range targets {
		if err == t {
			return true
		}
	}
	return false
}

func TestIntegration_HostIPList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}},
	})
	require.NoError(t, err)
}

func TestIntegration_ServiceList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "Services"}},
	})
	require.NoError(t, err)
}

func TestIntegration_FirewallRuleList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "FirewallRule"}},
	})
	require.NoError(t, err)
}

func TestIntegration_NATRuleList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "NATRule"}},
	})
	require.NoError(t, err)
}
