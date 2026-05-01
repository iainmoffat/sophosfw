package safety

import (
	"regexp"
	"sort"
)

// setOpRe matches <Set operation="add|update"> opening tags.
var setOpRe = regexp.MustCompile(`<Set\s+operation\s*=\s*"(add|update)"`)

// removeRe matches a <Remove> opening tag (any whitespace/attrs after).
var removeRe = regexp.MustCompile(`<Remove[\s>]`)

// IsMutating returns true if the XML envelope contains any verb that would
// modify firewall configuration. The second return value lists the detected
// verbs in a stable order (e.g. "Set:add", "Set:update", "Remove"). Statistics
// queries (`<*Statistics>`) are read-only and are not flagged.
func IsMutating(xml []byte) (bool, []string) {
	seen := map[string]struct{}{}

	for _, m := range setOpRe.FindAllSubmatch(xml, -1) {
		seen["Set:"+string(m[1])] = struct{}{}
	}
	if removeRe.Find(xml) != nil {
		seen["Remove"] = struct{}{}
	}

	if len(seen) == 0 {
		return false, nil
	}
	verbs := make([]string, 0, len(seen))
	for v := range seen {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	return true, verbs
}
