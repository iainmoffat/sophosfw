//go:build integration

// Package testutil provides test helpers including the IntegrationClient
// wrapper that mechanically prevents mutating envelopes during integration
// tests. The build tag ensures this code is only compiled when the
// integration tests are explicitly requested.
package testutil

import (
	"context"
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// IntegrationClient wraps a sophos.Client and panics at construction time on
// any envelope containing mutating verbs. This is stronger than the runtime
// read-only check because it fails *during the test*, not on a server response.
type IntegrationClient struct {
	inner *sophos.Client
}

// NewIntegrationClient builds the wrapper. Caller must construct the inner
// sophos.Client themselves so test setup remains explicit.
func NewIntegrationClient(inner *sophos.Client) *IntegrationClient {
	return &IntegrationClient{inner: inner}
}

func (c *IntegrationClient) Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error) {
	xml, err := sophos.BuildEnvelope(env, c.inner.Username, c.inner.Password)
	if err != nil {
		return nil, err
	}
	if mutating, verbs := safety.IsMutating(xml); mutating {
		panic(fmt.Sprintf("integration test attempted mutating envelope: %v", verbs))
	}
	return c.inner.Do(ctx, env)
}

func (c *IntegrationClient) DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error) {
	if mutating, verbs := safety.IsMutating(raw); mutating {
		panic(fmt.Sprintf("integration test attempted mutating raw envelope: %v", verbs))
	}
	return c.inner.DoRaw(ctx, raw)
}
