package draft

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrateLegacyLayout_NoOp_EmptyProfile(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, MigrateLegacyLayout(base, "home"))
}

func TestMigrateLegacyLayout_MovesFlatDraftsToFirewall(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "wan-to-lan.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("# rule: WAN-to-LAN\n"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	_, err := os.Stat(legacy)
	require.True(t, os.IsNotExist(err))
	migrated := filepath.Join(dir, "firewall", "wan-to-lan.yaml")
	_, err = os.Stat(migrated)
	require.NoError(t, err)
}

func TestMigrateLegacyLayout_MovesFlatSnapshotsToFirewall(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("# rule: WAN-to-LAN\n"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	_, err := os.Stat(legacy)
	require.True(t, os.IsNotExist(err))
	migrated := filepath.Join(dir, "firewall", "wan-to-lan-2026-05-02T10-00-00Z.yaml")
	_, err = os.Stat(migrated)
	require.NoError(t, err)
}

func TestMigrateLegacyLayout_SkipsCollisions(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "firewall"), 0o700))
	legacy := filepath.Join(dir, "x.yaml")
	migrated := filepath.Join(dir, "firewall", "x.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("legacy"), 0o600))
	require.NoError(t, os.WriteFile(migrated, []byte("migrated"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	got, err := os.ReadFile(legacy)
	require.NoError(t, err)
	require.Equal(t, "legacy", string(got))
	got2, err := os.ReadFile(migrated)
	require.NoError(t, err)
	require.Equal(t, "migrated", string(got2))
}

func TestMigrateLegacyLayout_Idempotent(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "x.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("a"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))
	require.NoError(t, MigrateLegacyLayout(base, "home"))

	migrated := filepath.Join(dir, "firewall", "x.yaml")
	got, err := os.ReadFile(migrated)
	require.NoError(t, err)
	require.Equal(t, "a", string(got))
}

func TestMigrateLegacyLayout_LeavesSubdirEntriesAlone(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	already := filepath.Join(dir, "x.yaml")
	require.NoError(t, os.WriteFile(already, []byte("ok"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	got, err := os.ReadFile(already)
	require.NoError(t, err)
	require.Equal(t, "ok", string(got))
}
