package svc

import (
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/stretchr/testify/require"
)

func TestDiffHash_StableForSameInput(t *testing.T) {
	h1 := catalog.IPHost{
		Name: "LAN-network", IPFamily: "IPv4", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}
	h2 := catalog.IPHost{
		Name: "LAN-network", IPFamily: "IPv4", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}
	got1, err := DiffHash(h1)
	require.NoError(t, err)
	got2, err := DiffHash(h2)
	require.NoError(t, err)
	require.Equal(t, got1, got2)
	require.Len(t, got1, 64) // hex-encoded SHA-256
}

func TestDiffHash_DifferentForDifferentInput(t *testing.T) {
	h1 := catalog.IPHost{Name: "A", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	h2 := catalog.IPHost{Name: "A", IPFamily: "IPv4", HostType: "IP", IPAddress: "2.2.2.2"}
	got1, _ := DiffHash(h1)
	got2, _ := DiffHash(h2)
	require.NotEqual(t, got1, got2)
}

func TestDiffHash_KeyOrderingInvariant(t *testing.T) {
	// Two map[string]any with identical content but different insertion order
	// must produce the same hash.
	a := map[string]any{"Name": "X", "IPAddress": "1.1.1.1", "HostType": "IP"}
	b := map[string]any{"HostType": "IP", "IPAddress": "1.1.1.1", "Name": "X"}
	ha, _ := DiffHash(a)
	hb, _ := DiffHash(b)
	require.Equal(t, ha, hb)
}
