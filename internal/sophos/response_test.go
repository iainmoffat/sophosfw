package sophos

import (
	"encoding/json"
	"os"
	"strings"
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

// Repeated sibling elements are how Sophos represents group membership. A
// decoder that overwrites on repeat reports a 17-member group as a 1-member
// group, and every downstream artifact (backup, diffHash, drift, usage) then
// agrees with the truncated view. Fixtures here must carry MORE THAN ONE
// member: a single-member fixture passes under both the broken and the fixed
// decoder.
func TestParseResponse_RepeatedElements_AccumulateIntoSlice(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/fqdnhostgroup_get_multi.xml"))
	require.NoError(t, err)
	require.NoError(t, r.AsError())
	require.Len(t, r.Body["FQDNHostGroup"], 1)

	var rec map[string]any
	require.NoError(t, json.Unmarshal(r.Body["FQDNHostGroup"][0], &rec))
	require.Equal(t, "smtp-bypass", rec["Name"])

	list := childMap(t, rec["FQDNHostList"])
	require.Equal(t, []any{
		"dingo.example.org",
		"docker01.example.org",
		"docker02.example.org",
		"fnas01.example.org",
		"veeam01.example.org",
	}, list["FQDNHost"], "all repeated members must survive, in document order")
}

// A one-member list stays a scalar. That asymmetry is deliberate (it matches
// what Sophos accepts on the write side) and is exactly where a follow-up bug
// would hide, so it is pinned.
func TestParseResponse_SingleElement_StaysScalar(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/fqdnhostgroup_get_single.xml"))
	require.NoError(t, err)
	var rec map[string]any
	require.NoError(t, json.Unmarshal(r.Body["FQDNHostGroup"][0], &rec))

	require.Equal(t, "dingo.example.org", childMap(t, rec["FQDNHostList"])["FQDNHost"])
}

// childMap asserts that a decoded value is a nested element (not a leaf
// string), failing the test cleanly instead of panicking.
func childMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	require.True(t, ok, "expected a nested element, got %T (%v)", v, v)
	return m
}

// childSlice asserts that a decoded value accumulated into a slice, which is
// what repeated sibling elements must produce.
func childSlice(t *testing.T, v any) []any {
	t.Helper()
	s, ok := v.([]any)
	require.True(t, ok, "expected repeated elements to accumulate into a slice, got %T (%v)", v, v)
	return s
}

func TestXMLFragmentToMap_RepeatCardinality(t *testing.T) {
	member := func(names ...string) []byte {
		var sb strings.Builder
		sb.WriteString("<G><Name>g</Name><L>")
		for _, n := range names {
			sb.WriteString("<M>" + n + "</M>")
		}
		sb.WriteString("</L></G>")
		return []byte(sb.String())
	}

	t.Run("zero", func(t *testing.T) {
		m, err := xmlFragmentToMap(member())
		require.NoError(t, err)
		require.Equal(t, "", m["L"])
	})
	t.Run("one", func(t *testing.T) {
		m, err := xmlFragmentToMap(member("a"))
		require.NoError(t, err)
		require.Equal(t, "a", childMap(t, m["L"])["M"])
	})
	t.Run("two", func(t *testing.T) {
		m, err := xmlFragmentToMap(member("a", "b"))
		require.NoError(t, err)
		require.Equal(t, []any{"a", "b"}, childMap(t, m["L"])["M"])
	})
	t.Run("many", func(t *testing.T) {
		names := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q"}
		m, err := xmlFragmentToMap(member(names...))
		require.NoError(t, err)
		got := childSlice(t, childMap(t, m["L"])["M"])
		require.Len(t, got, 17)
		for i, n := range names {
			require.Equal(t, n, got[i])
		}
	})
}

// Repeated complex children (objects, not leaf strings) must accumulate too —
// e.g. a Service with several <ServiceDetail> entries, or a rule with several
// structured members.
func TestXMLFragmentToMap_RepeatedComplexChildren(t *testing.T) {
	raw := []byte(`<Services><Name>web</Name><ServiceDetails>` +
		`<ServiceDetail><Protocol>TCP</Protocol><DestinationPort>80</DestinationPort></ServiceDetail>` +
		`<ServiceDetail><Protocol>TCP</Protocol><DestinationPort>443</DestinationPort></ServiceDetail>` +
		`</ServiceDetails></Services>`)
	m, err := xmlFragmentToMap(raw)
	require.NoError(t, err)

	details := childSlice(t, childMap(t, m["ServiceDetails"])["ServiceDetail"])
	require.Len(t, details, 2)
	require.Equal(t, "80", childMap(t, details[0])["DestinationPort"])
	require.Equal(t, "443", childMap(t, details[1])["DestinationPort"])
}

// Sibling lists must not bleed into one another: two different repeated keys
// under the same parent each accumulate independently.
func TestXMLFragmentToMap_IndependentSiblingLists(t *testing.T) {
	raw := []byte(`<FirewallRule><Name>r</Name><Zones>` +
		`<Zone>LAN</Zone><Zone>DMZ</Zone>` +
		`<Network>net1</Network><Network>net2</Network><Network>net3</Network>` +
		`</Zones></FirewallRule>`)
	m, err := xmlFragmentToMap(raw)
	require.NoError(t, err)

	zones := childMap(t, m["Zones"])
	require.Equal(t, []any{"LAN", "DMZ"}, zones["Zone"])
	require.Equal(t, []any{"net1", "net2", "net3"}, zones["Network"])
}
