package safety

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsMutating_DetectsSetAdd(t *testing.T) {
	x := []byte(`<Request><Set operation="add"><IPHost><Name>x</Name></IPHost></Set></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Contains(t, verbs, "Set:add")
}

func TestIsMutating_DetectsSetUpdate(t *testing.T) {
	x := []byte(`<Request><Set operation="update"><IPHost></IPHost></Set></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Contains(t, verbs, "Set:update")
}

func TestIsMutating_DetectsRemove(t *testing.T) {
	x := []byte(`<Request><Remove><IPHost><Name>x</Name></IPHost></Remove></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Contains(t, verbs, "Remove")
}

func TestIsMutating_GetIsNotMutating(t *testing.T) {
	x := []byte(`<Request><Get><IPHost></IPHost></Get></Request>`)
	mutating, verbs := IsMutating(x)
	require.False(t, mutating)
	require.Empty(t, verbs)
}

func TestIsMutating_StatisticsIsNotMutating(t *testing.T) {
	x := []byte(`<Request><IPHostStatistics><Filter><key name="Name" criteria="like">LAN</key></Filter></IPHostStatistics></Request>`)
	mutating, verbs := IsMutating(x)
	require.False(t, mutating)
	require.Empty(t, verbs)
}

func TestIsMutating_MultipleVerbsAllReported(t *testing.T) {
	x := []byte(`<Request><Set operation="add"></Set><Remove></Remove></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Len(t, verbs, 2)
}
