package safety

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactXML_ReplacesUsernameAndPassword(t *testing.T) {
	in := []byte(`<Request><Login><Username>admin</Username><Password>hunter2</Password></Login><Get><IPHost></IPHost></Get></Request>`)
	out := RedactXML(in)
	require.False(t, strings.Contains(string(out), "admin"))
	require.False(t, strings.Contains(string(out), "hunter2"))
	require.True(t, strings.Contains(string(out), "<Username>***</Username>"))
	require.True(t, strings.Contains(string(out), "<Password>***</Password>"))
	require.True(t, strings.Contains(string(out), "<Get><IPHost></IPHost></Get>"))
}

func TestRedactXML_Idempotent(t *testing.T) {
	in := []byte(`<Login><Username>x</Username><Password>y</Password></Login>`)
	once := RedactXML(in)
	twice := RedactXML(once)
	require.Equal(t, string(once), string(twice))
}

func TestRedactXML_NoCredentials_Unchanged(t *testing.T) {
	in := []byte(`<Get><IPHost></IPHost></Get>`)
	require.Equal(t, string(in), string(RedactXML(in)))
}

func TestRedactString_ReplacesPasswordSubstring(t *testing.T) {
	got := RedactString("connecting as admin with password=hunter2")
	require.False(t, strings.Contains(got, "hunter2"))
}
