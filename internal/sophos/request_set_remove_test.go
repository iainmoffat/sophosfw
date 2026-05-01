package sophos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildSetEnvelope_AddOperation(t *testing.T) {
	inner := []byte(`<IPHost><Name>X</Name><HostType>IP</HostType><IPAddress>1.1.1.1</IPAddress></IPHost>`)
	out, err := BuildSetEnvelope("add", inner, "u", "p")
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "<Request>")
	require.Contains(t, s, "<Login>")
	require.Contains(t, s, "<Username>u</Username>")
	require.Contains(t, s, `<Set operation="add">`)
	require.Contains(t, s, "<IPHost>")
	require.Contains(t, s, "<Name>X</Name>")
	require.Contains(t, s, "</Set>")
	require.True(t, strings.HasSuffix(strings.TrimSpace(s), "</Request>"))
}

func TestBuildSetEnvelope_UpdateOperation(t *testing.T) {
	inner := []byte(`<IPHost><Name>X</Name></IPHost>`)
	out, err := BuildSetEnvelope("update", inner, "u", "p")
	require.NoError(t, err)
	require.Contains(t, string(out), `<Set operation="update">`)
}

func TestBuildSetEnvelope_RejectsUnknownOperation(t *testing.T) {
	_, err := BuildSetEnvelope("delete", []byte(`<IPHost/>`), "u", "p")
	require.Error(t, err)
}

func TestBuildRemoveEnvelope_WrapsInner(t *testing.T) {
	inner := []byte(`<IPHost><Name>X</Name></IPHost>`)
	out, err := BuildRemoveEnvelope(inner, "u", "p")
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "<Request>")
	require.Contains(t, s, "<Remove>")
	require.Contains(t, s, "<IPHost>")
	require.Contains(t, s, "<Name>X</Name>")
	require.Contains(t, s, "</Remove>")
	require.True(t, strings.HasSuffix(strings.TrimSpace(s), "</Request>"))
}
