package svc

import (
	"errors"
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
