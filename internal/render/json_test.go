package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteJSON_WrapsPayloadWithSchemaField(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteJSON(buf, "sophosfw.v1.authStatus", map[string]any{
		"profile":  "home",
		"loggedIn": true,
	})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "sophosfw.v1.authStatus", got["schema"])
	require.Equal(t, "home", got["profile"])
	require.Equal(t, true, got["loggedIn"])
}

func TestWriteJSON_PrettyPrintedWithTrailingNewline(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, WriteJSON(buf, "sophosfw.v1.test", struct{}{}))
	require.True(t, bytes.HasSuffix(buf.Bytes(), []byte("\n")))
	require.Contains(t, buf.String(), "  ") // indented
}

func TestWriteError_EmitsErrorEnvelope(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteError(buf, "auth_failed", "bad credentials", "home", map[string]any{"hint": "check password"})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "sophosfw.v1.error", got["schema"])
	require.Equal(t, "auth_failed", got["kind"])
	require.Equal(t, "bad credentials", got["message"])
	require.Equal(t, "home", got["profile"])
	details, ok := got["details"].(map[string]any)
	require.True(t, ok, "got %T", got["details"])
	require.Equal(t, "check password", details["hint"])
}
