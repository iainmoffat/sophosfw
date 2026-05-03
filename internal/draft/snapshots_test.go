package draft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestListSnapshots_Empty(t *testing.T) {
	base := t.TempDir()
	out, err := ListSnapshots(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestListSnapshots_OrderedOldestToNewest(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	for _, stamp := range []string{
		"2026-05-02T10-00-00Z",
		"2026-05-02T08-00-00Z",
		"2026-05-02T09-00-00Z",
	} {
		path := filepath.Join(dir, "wan-to-lan-"+stamp+".yaml")
		require.NoError(t, os.WriteFile(path, []byte("# rule: WAN-to-LAN\n"), 0o600))
	}

	out, err := ListSnapshots(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 3)
	require.Contains(t, out[0], "08-00-00Z")
	require.Contains(t, out[1], "09-00-00Z")
	require.Contains(t, out[2], "10-00-00Z")
}

func TestListSnapshots_FiltersUnrelatedSlugs(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other-rule-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))

	out, err := ListSnapshots(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Contains(t, out[0], "wan-to-lan-")
}

func TestListSnapshots_IncludesDeletedSuffix(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T11-00-00Z-deleted.yaml"), []byte{}, 0o600))
	out, err := ListSnapshots(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 2)
}

func TestRotateSnapshots_KeepsLastN(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	for i := 0; i < 15; i++ {
		stamp := time.Date(2026, 5, 2, 10+i, 0, 0, 0, time.UTC).Format("2006-01-02T15-04-05Z")
		path := filepath.Join(dir, "wan-to-lan-"+stamp+".yaml")
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("snapshot %d", i)), 0o600))
	}

	require.NoError(t, RotateSnapshots(base, "home", "firewall", "WAN-to-LAN", 10))

	out, err := ListSnapshots(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 10)
	for _, p := range out {
		baseName := filepath.Base(p)
		// Oldest 5 (hours 10-14) should be gone.
		require.False(t, strings.Contains(baseName, "T10-00-00Z"))
		require.False(t, strings.Contains(baseName, "T11-00-00Z"))
		require.False(t, strings.Contains(baseName, "T12-00-00Z"))
		require.False(t, strings.Contains(baseName, "T13-00-00Z"))
		require.False(t, strings.Contains(baseName, "T14-00-00Z"))
	}
}

func TestRotateSnapshots_NoOpWhenUnderCap(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))

	require.NoError(t, RotateSnapshots(base, "home", "firewall", "WAN-to-LAN", 10))

	out, err := ListSnapshots(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 1)
}

func TestRotateSnapshots_KeepZero_NoOp(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))

	require.NoError(t, RotateSnapshots(base, "home", "firewall", "WAN-to-LAN", 0))

	out, err := ListSnapshots(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 1) // unchanged: keep<=0 is a no-op safeguard
}
