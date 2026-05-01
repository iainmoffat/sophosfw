package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDefault_LoadsAndRegistersTypedParsers(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(c.Tags()), 12)

	// IPHost should dispatch to the typed parser.
	v, err := c.Parse("IPHost", json.RawMessage(`{"Name":"x","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0"}`))
	require.NoError(t, err)
	_, ok := v.(IPHost)
	require.True(t, ok)

	// FQDNHost should fall through to map (no typed parser).
	v, err = c.Parse("FQDNHost", json.RawMessage(`{"Name":"x","FQDN":"a.b"}`))
	require.NoError(t, err)
	_, ok = v.(map[string]any)
	require.True(t, ok)
}
