package sophos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildEnvelope_GetSimpleTag(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}}
	xml, err := BuildEnvelope(env, "admin", "secret")
	require.NoError(t, err)
	s := string(xml)
	require.Contains(t, s, "<Request>")
	require.Contains(t, s, "<Login>")
	require.Contains(t, s, "<Username>admin</Username>")
	require.Contains(t, s, "<Password>secret</Password>")
	require.Contains(t, s, "<Get>")
	require.Contains(t, s, "<IPHost></IPHost>")
}

func TestBuildEnvelope_GetWithName(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost", Name: "LAN"}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	s := string(xml)
	require.Contains(t, s, "<IPHost>")
	require.Contains(t, s, "<Filter>")
	require.Contains(t, s, "<key name=\"Name\" criteria=\"=\">LAN</key>")
}

func TestBuildEnvelope_GetWithFilterLike(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{
		XMLTag: "IPHost",
		Filter: &FilterClause{Field: "Name", Criteria: "like", Value: "LAN"},
	}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	require.Contains(t, string(xml), `<key name="Name" criteria="like">LAN</key>`)
}

func TestBuildEnvelope_StatisticsOp(t *testing.T) {
	env := Envelope{Operations: []Op{StatisticsOp{
		XMLTag: "IPHostStatistics",
		Filter: &FilterClause{Field: "Name", Criteria: "=", Value: "LAN"},
	}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	s := string(xml)
	require.Contains(t, s, "<IPHostStatistics>")
	require.Contains(t, s, `<key name="Name" criteria="=">LAN</key>`)
}

func TestBuildEnvelope_EscapesUserInput(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost", Name: "LAN<bad>&'"}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	// Critical: must be escaped, not concatenated.
	require.NotContains(t, string(xml), "<bad>")
	require.Contains(t, string(xml), "&lt;")
	require.Contains(t, string(xml), "&amp;")
}

func TestBuildEnvelope_WithTransactionID(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}, TxnID: "abc-123"}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	require.Contains(t, string(xml), "<transactionid>abc-123</transactionid>")
}

func TestBuildEnvelope_RawIsReturnedAsIs(t *testing.T) {
	raw := []byte(`<Request><Get><Zone></Zone></Get></Request>`)
	got, err := BuildRawEnvelope(raw, "u", "p")
	require.NoError(t, err)
	// Login must be injected even into a raw envelope.
	require.True(t, strings.Contains(string(got), "<Login>"))
	require.True(t, strings.Contains(string(got), "<Username>u</Username>"))
	require.True(t, strings.Contains(string(got), "<Password>p</Password>"))
	require.True(t, strings.Contains(string(got), "<Get><Zone></Zone></Get>"))
}
