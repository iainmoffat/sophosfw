package sophos

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterClauseValidate_Object_AllowedCriteria(t *testing.T) {
	for _, c := range []string{"=", "!=", "like"} {
		require.NoError(t, FilterClause{Field: "Name", Criteria: c, Value: "x"}.ValidateForGet(),
			"criteria %q must be allowed for Get", c)
	}
}

func TestFilterClauseValidate_Object_RejectsStatsCriteria(t *testing.T) {
	require.Error(t, FilterClause{Field: "Name", Criteria: "startswith", Value: "x"}.ValidateForGet())
	require.Error(t, FilterClause{Field: "Name", Criteria: ">=", Value: "x"}.ValidateForGet())
}

func TestFilterClauseValidate_Stats_AllowsRichCriteria(t *testing.T) {
	for _, c := range []string{"=", "!=", "like", "not like", "startswith", "in", ">", ">="} {
		require.NoError(t, FilterClause{Field: "Name", Criteria: c, Value: "x"}.ValidateForStatistics(),
			"criteria %q must be allowed for Statistics", c)
	}
}

func TestFilterClauseValidate_RejectsEmptyField(t *testing.T) {
	require.Error(t, FilterClause{Field: "", Criteria: "=", Value: "x"}.ValidateForGet())
}

func TestParseFilterFlag_FieldCriteriaValue(t *testing.T) {
	f, err := ParseFilterFlag("Name:like:LAN")
	require.NoError(t, err)
	require.Equal(t, "Name", f.Field)
	require.Equal(t, "like", f.Criteria)
	require.Equal(t, "LAN", f.Value)
}

func TestParseFilterFlag_AllowsColonsInValue(t *testing.T) {
	f, err := ParseFilterFlag("URL:like:https://x:4444")
	require.NoError(t, err)
	require.Equal(t, "URL", f.Field)
	require.Equal(t, "like", f.Criteria)
	require.Equal(t, "https://x:4444", f.Value)
}

func TestParseFilterFlag_BadFormat(t *testing.T) {
	_, err := ParseFilterFlag("Name=LAN")
	require.Error(t, err)
}
