package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteTable_RendersHeadersAndRows(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	require.NoError(t, WriteTable(buf, []string{"Name", "IPAddress"}, [][]string{
		{"LAN-network", "10.0.0.0"},
		{"DMZ", "192.168.10.0"},
	}))
	out := buf.String()
	require.Contains(t, out, "Name")
	require.Contains(t, out, "IPAddress")
	require.Contains(t, out, "LAN-network")
	require.Contains(t, out, "10.0.0.0")
	require.Contains(t, out, "DMZ")
	require.Contains(t, out, "192.168.10.0")
}

func TestWriteTable_EmptyRowsStillRendersHeader(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	require.NoError(t, WriteTable(buf, []string{"Name"}, nil))
	require.Contains(t, buf.String(), "Name")
}

func TestWriteTable_NoColorModeIsAnsiClean(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	require.NoError(t, WriteTable(buf, []string{"A"}, [][]string{{"x"}}))
	require.False(t, strings.Contains(buf.String(), "\x1b["),
		"NO_COLOR mode must not emit ANSI escape sequences")
}
