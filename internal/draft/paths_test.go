package draft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSlug_BasicCases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"WAN-to-LAN", "wan-to-lan"},
		{"My Rule (test)", "my-rule-test"},
		{"Allow / SSH", "allow-ssh"},
		{"trailing-dashes---", "trailing-dashes"},
		{"---leading", "leading"},
		{"runs   of   spaces", "runs-of-spaces"},
		{"123 numeric", "123-numeric"},
		{"under_score", "under-score"},
		{"already-good-slug", "already-good-slug"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			require.Equal(t, c.want, Slug(c.in))
		})
	}
}

func TestSlug_UnicodeFallback(t *testing.T) {
	require.Equal(t, "rule", Slug("🔥🔥🔥"))
	require.Equal(t, "rule", Slug("中文"))
}

func TestDraftPath_NoCollision(t *testing.T) {
	base := t.TempDir()
	p, err := DraftPath(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "profiles", "home", "drafts", "firewall", "wan-to-lan.yaml"), p)
}

func TestDraftPath_CollisionAppendsHashSuffix(t *testing.T) {
	base := t.TempDir()
	draftsDir := filepath.Join(base, "profiles", "home", "drafts", "firewall")
	require.NoError(t, os.MkdirAll(draftsDir, 0o700))

	conflictingDraft := filepath.Join(draftsDir, "wan-to-lan.yaml")
	require.NoError(t, os.WriteFile(conflictingDraft,
		[]byte("# rule: Wan To Lan\n# DO NOT EDIT ABOVE THIS LINE\n---\nName: Wan To Lan\n"),
		0o600))

	p, err := DraftPath(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(filepath.Base(p), "wan-to-lan-"))
	require.True(t, strings.HasSuffix(p, ".yaml"))
	require.NotEqual(t, conflictingDraft, p)
}

func TestDraftPath_SameNameResolvesToSamePath(t *testing.T) {
	base := t.TempDir()
	p1, err := DraftPath(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	p2, err := DraftPath(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, p1, p2)
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tt, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return tt
}

func TestSnapshotPath_TimestampInName(t *testing.T) {
	base := t.TempDir()
	tt := mustParseTime(t, "2026-05-02T15:30:00Z")
	p, err := SnapshotPath(base, "home", "firewall", "WAN-to-LAN", tt)
	require.NoError(t, err)
	require.Contains(t, filepath.Base(p), "wan-to-lan-")
	require.Contains(t, filepath.Base(p), "2026-05-02T15-30-00Z")
	require.True(t, strings.HasSuffix(p, ".yaml"))
}

func TestDraftPath_TagInPath(t *testing.T) {
	base := t.TempDir()
	p, err := DraftPath(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "profiles", "home", "drafts", "firewall", "wan-to-lan.yaml"), p)

	p2, err := DraftPath(base, "home", "nat", "DNAT-to-X")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "profiles", "home", "drafts", "nat", "dnat-to-x.yaml"), p2)
}

func TestSnapshotPath_TagInPath(t *testing.T) {
	base := t.TempDir()
	tt := mustParseTime(t, "2026-05-02T15:30:00Z")
	p, err := SnapshotPath(base, "home", "nat", "X", tt)
	require.NoError(t, err)
	require.Contains(t, p, filepath.Join("profiles", "home", "snapshots", "nat"))
}

func TestDraftPath_RejectsInvalidTag(t *testing.T) {
	base := t.TempDir()
	_, err := DraftPath(base, "home", "../etc", "X")
	require.Error(t, err)
	_, err = DraftPath(base, "home", "", "X")
	require.Error(t, err)
}

func TestSnapshotPath_RejectsInvalidTag(t *testing.T) {
	base := t.TempDir()
	tt := mustParseTime(t, "2026-05-02T15:30:00Z")
	_, err := SnapshotPath(base, "home", "../etc", "X", tt)
	require.Error(t, err)
}

func TestListSnapshots_RejectsInvalidTag(t *testing.T) {
	base := t.TempDir()
	_, err := ListSnapshots(base, "home", "../etc", "X")
	require.Error(t, err)
}

func TestBackupRootDir_Format(t *testing.T) {
	p, err := BackupRootDir("/base", "home")
	require.NoError(t, err)
	require.Equal(t, "/base/profiles/home/backups", p)
}

func TestBackupRootDir_RejectsInvalidProfile(t *testing.T) {
	_, err := BackupRootDir("/base", "../etc")
	require.Error(t, err)
}

func TestBackupSnapshotDir_Format(t *testing.T) {
	tt := time.Date(2026, 5, 3, 20, 30, 0, 0, time.UTC)
	p, err := BackupSnapshotDir("/base", "home", tt)
	require.NoError(t, err)
	require.Equal(t, "/base/profiles/home/backups/2026-05-03T20-30-00Z", p)
}
