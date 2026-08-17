package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Group types (IPHostGroup, ServiceGroup, FQDNHostGroup) declare a list
// column in objects.yaml. The decoded shape is a single-key container
// wrapping a scalar (one member) or a slice (many) — see the decode contract
// on internal/sophos.xmlFragmentToMap. The table must show the members, not a
// Go map dump, because this cell is where an operator would spot a wrong
// membership count from inside the tool.
func TestStringify_GroupMemberList(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{
			name: "many members carry a count",
			in:   map[string]any{"FQDNHost": []any{"a.example.org", "b.example.org", "c.example.org"}},
			want: "3 members: a.example.org, b.example.org, c.example.org",
		},
		{
			name: "one member stays scalar",
			in:   map[string]any{"FQDNHost": "a.example.org"},
			want: "a.example.org",
		},
		{
			name: "empty list",
			in:   map[string]any{"FQDNHost": ""},
			want: "",
		},
		{
			name: "bare slice",
			in:   []any{"a", "b"},
			want: "2 members: a, b",
		},
		{
			name: "plain string passes through",
			in:   "LAN-network",
			want: "LAN-network",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, stringify(tc.in))
		})
	}
}

// A multi-key map is not the list-container shape, so it falls back to the
// default rendering rather than silently showing only one of its values.
func TestStringify_MultiKeyMapIsNotUnwrapped(t *testing.T) {
	got := stringify(map[string]any{"A": "1", "B": "2"})
	require.Contains(t, got, "A:1")
	require.Contains(t, got, "B:2")
}

// A long list is summarised, never silently truncated: the true count leads
// the cell and the unshown remainder is reported as "+N more". A bare
// truncated list would read as complete while hiding members.
func TestStringify_LongListReportsTrueCountAndRemainder(t *testing.T) {
	names := make([]string, 17)
	members := make([]any, len(names))
	for i := range names {
		names[i] = string(rune('a'+i)) + ".example.org"
		members[i] = names[i]
	}
	got := stringify(map[string]any{"FQDNHost": members})
	require.True(t, strings.HasPrefix(got, "17 members: "),
		"the true member count must lead the cell, got %q", got)
	require.Regexp(t, `\+\d+ more$`, got,
		"unshown members must be reported, not dropped, got %q", got)
	require.Contains(t, got, names[0], "at least one member is always shown")

	// The reported count and the "+N more" remainder must reconcile to 17.
	shown := strings.Count(got, ".example.org")
	var rest int
	_, err := fmt.Sscanf(got[strings.LastIndex(got, "+"):], "+%d more", &rest)
	require.NoError(t, err)
	require.Equal(t, 17, shown+rest, "shown members plus remainder must equal the true count")
}

func TestColumnsFor_RendersListColumn(t *testing.T) {
	item := map[string]any{
		"Name":         "smtp-bypass",
		"FQDNHostList": map[string]any{"FQDNHost": []any{"a.example.org", "b.example.org"}},
	}
	row := columnsFor(item, []string{"Name", "FQDNHostList"})
	require.Equal(t, []string{"smtp-bypass", "2 members: a.example.org, b.example.org"}, row)
}
