package sophos

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func TestParseResponse_IPHostList(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/iphost_list_2.xml"))
	require.NoError(t, err)
	require.True(t, r.LoginOK)
	require.Equal(t, "Authentication Successful", r.LoginStatus)
	require.Len(t, r.Body["IPHost"], 2)
}

func TestParseResponse_AuthFailure(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/auth_failure.xml"))
	require.NoError(t, err) // parse OK
	require.False(t, r.LoginOK)
	require.ErrorIs(t, r.AsError(), ErrAuthFailed)
}

func TestParseResponse_EmptyResultIsNotFound(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/empty_result.xml"))
	require.NoError(t, err)
	require.True(t, r.LoginOK)
	// Per-tag inner Status code 526 should surface via AsError as ErrNotFound.
	require.ErrorIs(t, r.AsError(), ErrNotFound)
}

func TestParseResponse_MalformedXML(t *testing.T) {
	_, err := ParseResponse([]byte("<not xml"))
	require.Error(t, err)
}

func TestParseResponse_LoginStatus_TrimsWhitespace(t *testing.T) {
	// Real Sophos firewall responses wrap the status text in <Login><status>
	// with whitespace around it. The parser must trim before comparing to
	// "Authentication Successful".
	body := []byte("<Response><Login>\n    <status>Authentication Successful</status>\n</Login></Response>")
	r, err := ParseResponse(body)
	require.NoError(t, err)
	require.Equal(t, "Authentication Successful", r.LoginStatus)
	require.True(t, r.LoginOK)
}
