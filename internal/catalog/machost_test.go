package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMACHostParser_ParsesSingleAddress(t *testing.T) {
	raw := json.RawMessage(`{"Name":"laptop-mac","Type":"MACAddress","MACAddress":"00:11:22:33:44:55"}`)
	v, err := MACHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(MACHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "laptop-mac", host.Name)
	require.Equal(t, "00:11:22:33:44:55", host.MACAddress)
	require.Equal(t, "MACAddress", host.Type)
	require.Empty(t, host.MACAddressList)
}

func TestMACHostParser_ParsesMultiAddress(t *testing.T) {
	raw := json.RawMessage(`{"Name":"lab-macs","Type":"MACList","MACAddressList":["00:11:22:33:44:55","aa:bb:cc:dd:ee:ff"]}`)
	v, err := MACHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(MACHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "lab-macs", host.Name)
	require.Equal(t, []string{"00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"}, host.MACAddressList)
	require.Empty(t, host.MACAddress)
}
