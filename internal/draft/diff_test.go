package draft

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnifiedDiff_Identical_Empty(t *testing.T) {
	a := "Name: X\nStatus: Enable\n"
	b := "Name: X\nStatus: Enable\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Empty(t, diff)
}

func TestUnifiedDiff_LineChange(t *testing.T) {
	a := "Name: X\nStatus: Enable\nIPAddress: 1.1.1.1\n"
	b := "Name: X\nStatus: Disable\nIPAddress: 1.1.1.1\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Contains(t, diff, "--- snapshot")
	require.Contains(t, diff, "+++ draft")
	require.Contains(t, diff, "-Status: Enable")
	require.Contains(t, diff, "+Status: Disable")
}

func TestUnifiedDiff_LineAdded(t *testing.T) {
	a := "Name: X\nStatus: Enable\n"
	b := "Name: X\nStatus: Enable\nDescription: new\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Contains(t, diff, "+Description: new")
}

func TestUnifiedDiff_LineRemoved(t *testing.T) {
	a := "Name: X\nStatus: Enable\nDescription: gone\n"
	b := "Name: X\nStatus: Enable\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Contains(t, diff, "-Description: gone")
}

func TestUnifiedDiff_OutputFormat_HeaderHunkBody(t *testing.T) {
	a := "a\nb\nc\n"
	b := "a\nB\nc\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "old", "new")
	lines := strings.Split(strings.TrimRight(diff, "\n"), "\n")
	require.Equal(t, "--- old", lines[0])
	require.Equal(t, "+++ new", lines[1])
	require.True(t, strings.HasPrefix(lines[2], "@@"))
}

func TestUnifiedDiff_BothEmpty_ReturnsEmpty(t *testing.T) {
	diff := UnifiedDiff([]byte(""), []byte(""), "a", "b")
	require.Empty(t, diff)
}
