package catalog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad_ReadsObjects(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)
	tags := c.Tags()
	require.ElementsMatch(t, []string{"IPHost", "Services"}, tags)
}

func TestResolve_ByTag(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)
	e, ok := c.Resolve("IPHost")
	require.True(t, ok)
	require.Equal(t, "IPHost", e.Tag)
	require.Equal(t, "IPHostStatistics", e.UsageTag)
	require.Equal(t, []string{"Name", "IPFamily", "HostType", "IPAddress", "Subnet"}, e.Columns)
}

func TestResolve_ByAlias(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)

	e, ok := c.Resolve("host-ip")
	require.True(t, ok)
	require.Equal(t, "IPHost", e.Tag)

	e, ok = c.Resolve("service")
	require.True(t, ok)
	require.Equal(t, "Services", e.Tag)
}

func TestResolve_Unknown(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)
	_, ok := c.Resolve("nope")
	require.False(t, ok)
}

func TestLoad_AmbiguousAliasIsAnError(t *testing.T) {
	_, err := loadFromBytes([]byte(`
objects:
  - tag: A
    aliases: [shared]
  - tag: B
    aliases: [shared]
`))
	require.Error(t, err)
}

func TestCatalog_IPHostMutable(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	entry, ok := c.Resolve("IPHost")
	require.True(t, ok)
	require.True(t, entry.Mutable, "IPHost should be marked mutable in Phase 6")
}

func TestCatalog_OtherEntriesNotMutable(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	for _, tag := range []string{"FQDNHost", "MACHost", "Zone", "FirewallRule", "NATRule", "Services"} {
		entry, ok := c.Resolve(tag)
		require.True(t, ok, "tag %q should exist", tag)
		require.False(t, entry.Mutable, "tag %q must NOT be mutable in Phase 6", tag)
	}
}
