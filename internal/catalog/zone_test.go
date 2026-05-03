package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZoneParser_ParsesBuiltInZone(t *testing.T) {
	raw := json.RawMessage(`{"Name":"LAN","Type":"LAN","Description":"Default LAN zone"}`)
	v, err := ZoneParser(raw)
	require.NoError(t, err)
	zone, ok := v.(Zone)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "LAN", zone.Name)
	require.Equal(t, "LAN", zone.Type)
	require.Equal(t, "Default LAN zone", zone.Description)
}

func TestZoneParser_ParsesCustomZone(t *testing.T) {
	raw := json.RawMessage(`{"Name":"DMZ-Servers","Type":"DMZ"}`)
	v, err := ZoneParser(raw)
	require.NoError(t, err)
	zone, ok := v.(Zone)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "DMZ-Servers", zone.Name)
	require.Equal(t, "DMZ", zone.Type)
	require.Empty(t, zone.Description)
}
