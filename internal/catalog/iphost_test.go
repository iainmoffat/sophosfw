package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPHostParser_ParsesNetworkRecord(t *testing.T) {
	raw := json.RawMessage(`{
		"Name": "LAN-network",
		"IPFamily": "IPv4",
		"HostType": "Network",
		"IPAddress": "10.0.0.0",
		"Subnet": "255.255.255.0"
	}`)
	v, err := IPHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(IPHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "LAN-network", host.Name)
	require.Equal(t, "Network", host.HostType)
	require.Equal(t, "10.0.0.0", host.IPAddress)
}

func TestIPHostParser_ParsesRangeRecord(t *testing.T) {
	raw := json.RawMessage(`{"Name":"R","IPFamily":"IPv4","HostType":"IPRange","StartIPAddress":"10.0.0.1","EndIPAddress":"10.0.0.10"}`)
	v, err := IPHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(IPHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "10.0.0.1", host.StartIPAddress)
	require.Equal(t, "10.0.0.10", host.EndIPAddress)
}
