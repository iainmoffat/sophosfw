package draft

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadWriteDraft_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "draft.yaml")
	d := &Draft{
		Profile:  "home",
		Rule:     "WAN-to-LAN",
		PulledAt: mustParseTime(t, "2026-05-02T15:30:00Z"),
		DiffHash: "8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50",
		Body:     []byte("Name: WAN-to-LAN\nStatus: Enable\n"),
	}
	require.NoError(t, WriteDraft(path, d))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	got, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, d.Profile, got.Profile)
	require.Equal(t, d.Rule, got.Rule)
	require.True(t, d.PulledAt.Equal(got.PulledAt))
	require.Equal(t, d.DiffHash, got.DiffHash)
	require.Equal(t, string(d.Body), string(got.Body))
}

func TestReadDraft_FileMissing_ReturnsErrDraftMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadDraft(filepath.Join(dir, "nope.yaml"))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDraftMissing))
}

func TestReadDraft_MissingRequiredHeader_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# pulledAt: 2026-05-02T15:30:00Z\n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "diffHash")
}

func TestReadDraft_InvalidHashFormat_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badhash.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: not-a-hex-hash\n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "diffHash")
}

func TestReadDraft_InvalidTimestamp_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badtime.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# pulledAt: yesterday\n# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pulledAt")
}

func TestReadDraft_NoDocumentMarker_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noend.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# pulledAt: 2026-05-02T15:30:00Z\n# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
}

func TestWriteDraft_CreatesParentDir_0700(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "deeply", "nested", "draft.yaml")
	d := &Draft{
		Profile:  "home",
		Rule:     "X",
		PulledAt: time.Now().UTC(),
		DiffHash: "8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50",
		Body:     []byte("Name: X\n"),
	}
	require.NoError(t, WriteDraft(path, d))
	_, err := os.Stat(path)
	require.NoError(t, err)
	parent, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), parent.Mode().Perm())
}

func TestErrSnapshotMissing_Defined(t *testing.T) {
	// Smoke test: the sentinel exists.
	require.NotNil(t, ErrSnapshotMissing)
	require.True(t, errors.Is(ErrSnapshotMissing, ErrSnapshotMissing))
}

func TestReadDraft_HeaderKey_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "case.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# Profile: home\n# Rule: X\n# PulledAt: 2026-05-02T15:30:00Z\n# DiffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\n---\nName: X\n"),
		0o600))
	d, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, "home", d.Profile)
	require.Equal(t, "X", d.Rule)
}

func TestReadDraft_NormalizesCRLF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crlf.yaml")
	body := "# profile: home\r\n# rule: X\r\n# pulledAt: 2026-05-02T15:30:00Z\r\n# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50\r\n---\r\nName: X\r\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	d, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, "X", d.Rule)
	require.Contains(t, string(d.Body), "Name: X")
}
