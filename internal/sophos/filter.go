package sophos

import (
	"fmt"
	"strings"
)

var (
	getCriteria = map[string]struct{}{
		"=":    {},
		"!=":   {},
		"like": {},
	}
	statsCriteria = map[string]struct{}{
		"=":          {},
		"!=":         {},
		"like":       {},
		"not like":   {},
		"startswith": {},
		"in":         {},
		">":          {},
		">=":         {},
	}
)

// ValidateForGet returns an error if the criteria isn't valid for object Get.
func (f FilterClause) ValidateForGet() error {
	if f.Field == "" {
		return fmt.Errorf("filter: Field is required")
	}
	if _, ok := getCriteria[f.Criteria]; !ok {
		return fmt.Errorf("filter: %q is not a valid Get criteria (allowed: =, !=, like)", f.Criteria)
	}
	return nil
}

// ValidateForStatistics returns an error if the criteria isn't valid for *Statistics queries.
func (f FilterClause) ValidateForStatistics() error {
	if f.Field == "" {
		return fmt.Errorf("filter: Field is required")
	}
	if _, ok := statsCriteria[f.Criteria]; !ok {
		return fmt.Errorf("filter: %q is not a valid Statistics criteria", f.Criteria)
	}
	return nil
}

// ParseFilterFlag parses the user-facing `--filter Field:Criteria:Value`
// syntax. Values may contain colons; only the first two colons split the
// fields.
func ParseFilterFlag(s string) (FilterClause, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return FilterClause{}, fmt.Errorf("filter: expected Field:Criteria:Value, got %q", s)
	}
	return FilterClause{Field: parts[0], Criteria: parts[1], Value: parts[2]}, nil
}
