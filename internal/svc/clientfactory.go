package svc

import (
	"context"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// Client is the subset of sophos.Client used by services. Allows fakes in tests.
type Client interface {
	Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error)
	DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error)
}

// ClientFactory builds a Client for a profile + credentials. Production code
// returns a real *sophos.Client; tests can swap in fakes.
type ClientFactory func(p config.Profile, c creds.Credentials) Client

// DefaultClientFactory builds a real sophos.Client honoring profile settings.
// The insecureSkipVerify override is passed through (e.g. from a CLI flag).
func DefaultClientFactory(insecureSkipVerify bool) ClientFactory {
	return func(p config.Profile, c creds.Credentials) Client {
		return sophos.NewClient(sophos.ClientConfig{
			BaseURL:            p.URL,
			Username:           c.Username,
			Password:           c.Password,
			Timeout:            p.Timeout,
			InsecureSkipVerify: insecureSkipVerify || p.InsecureSkipVerify,
			ReadOnly:           p.ReadOnly,
		})
	}
}
