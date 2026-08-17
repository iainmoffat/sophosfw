package svc

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func TestMarshalObjectBody_SimpleScalars(t *testing.T) {
	out, err := marshalObjectBody("Foo", map[string]any{"Name": "x", "Count": 3})
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "<Foo>")
	require.Contains(t, s, "<Name>x</Name>")
	require.Contains(t, s, "<Count>3</Count>")
	require.Contains(t, s, "</Foo>")
}

func TestMarshalObjectBody_NestedMap(t *testing.T) {
	out, err := marshalObjectBody("Foo", map[string]any{
		"Name":  "x",
		"Inner": map[string]any{"K": "v"},
	})
	require.NoError(t, err)
	require.Contains(t, string(out), "<Inner><K>v</K></Inner>")
}

// TestMarshalObjectBody_StringList documents the list-emission contract:
// []any items repeat the parent <key> element flat (e.g. <Host>a</Host>
// <Host>b</Host>), not wrapped in a synthetic plural element. Phase 12
// callers nest lists inside an outer map for grouped output, e.g.
// {HostList: {Host: ["a", "b"]}} → <HostList><Host>a</Host><Host>b</Host></HostList>.
func TestMarshalObjectBody_StringList(t *testing.T) {
	out, err := marshalObjectBody("Group", map[string]any{
		"Name":     "g",
		"HostList": map[string]any{"Host": []any{"a", "b"}},
	})
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "<HostList><Host>a</Host><Host>b</Host></HostList>")
}

func TestMarshalObjectBody_RejectsInvalidTag(t *testing.T) {
	_, err := marshalObjectBody("Foo<Bar>", map[string]any{"Name": "x"})
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}

func TestMarshalObjectBody_EscapesValues(t *testing.T) {
	out, err := marshalObjectBody("Foo", map[string]any{"Name": "a&b<c>"})
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "&amp;")
	require.NotContains(t, s, "a&b<c>")
}

// TestReadModifyWrite_PreservesGroupMembership is the regression test for
// the truncating decoder (issue #8): a group read from the device, edited,
// and marshalled back must carry every member. FQDNHostGroup updates use
// replace semantics, so a member lost between read and write is a member
// evicted from the live group.
//
// The fixture deliberately holds FIVE members — a single-member fixture
// passes under both the broken and the fixed decoder.
func TestReadModifyWrite_PreservesGroupMembership(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/sophos/responses/fqdnhostgroup_get_multi.xml")
	require.NoError(t, err)
	resp, err := sophos.ParseResponse(raw)
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(resp.Body["FQDNHostGroup"][0], &body))

	// Read-modify-write: append one member, exactly as the documented
	// workflow does.
	list := memberList(t, body)
	members, ok := list["FQDNHost"].([]any)
	require.True(t, ok, "a 5-member group must decode FQDNHost as a slice, got %T", list["FQDNHost"])
	list["FQDNHost"] = append(members, "new01.example.org")

	out, err := marshalObjectBody("FQDNHostGroup", body)
	require.NoError(t, err)
	s := string(out)

	for _, want := range []string{
		"dingo.example.org", "docker01.example.org", "docker02.example.org",
		"fnas01.example.org", "veeam01.example.org", "new01.example.org",
	} {
		require.Contains(t, s, "<FQDNHost>"+want+"</FQDNHost>",
			"member %q must survive read-modify-write", want)
	}
	require.Equal(t, 6, strings.Count(s, "<FQDNHost>"))
}

// The concurrency gate is only sound if the hash covers every member.
// Removing a member from the middle of a group must change the diffHash;
// under the truncating decoder it did not, because only the last member
// reached the hash.
func TestDiffHash_ChangesWhenMiddleMemberRemoved(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/sophos/responses/fqdnhostgroup_get_multi.xml")
	require.NoError(t, err)
	resp, err := sophos.ParseResponse(raw)
	require.NoError(t, err)

	var before map[string]any
	require.NoError(t, json.Unmarshal(resp.Body["FQDNHostGroup"][0], &before))
	beforeHash, err := DiffHash(before)
	require.NoError(t, err)

	var after map[string]any
	require.NoError(t, json.Unmarshal(resp.Body["FQDNHostGroup"][0], &after))
	list := memberList(t, after)
	members, ok := list["FQDNHost"].([]any)
	require.True(t, ok, "a 5-member group must decode FQDNHost as a slice, got %T", list["FQDNHost"])
	// Drop "docker02.example.org" — a middle member, not the last.
	list["FQDNHost"] = append(append([]any{}, members[:2]...), members[3:]...)
	afterHash, err := DiffHash(after)
	require.NoError(t, err)

	require.NotEqual(t, beforeHash, afterHash,
		"removing a middle member must change the diffHash")
}

// memberList pulls the FQDNHostList container out of a decoded group body,
// failing the test rather than panicking so a regression reports cleanly
// instead of aborting the whole package run.
func memberList(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	list, ok := body["FQDNHostList"].(map[string]any)
	require.True(t, ok, "FQDNHostList should decode to an object, got %T", body["FQDNHostList"])
	return list
}
