package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFQDNHostParser_ParsesSimpleRecord(t *testing.T) {
	raw := json.RawMessage(`{"Name":"example.com","FQDN":"example.com","IPFamily":"IPv4"}`)
	v, err := FQDNHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(FQDNHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "example.com", host.Name)
	require.Equal(t, "example.com", host.FQDN)
	require.Equal(t, "IPv4", host.IPFamily)
}

func TestFQDNHostParser_ParsesWildcard(t *testing.T) {
	raw := json.RawMessage(`{"Name":"all-cdn","FQDN":"*.cdn.example.com","IPFamily":"IPv4"}`)
	v, err := FQDNHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(FQDNHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "*.cdn.example.com", host.FQDN)
}
