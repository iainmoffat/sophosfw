// Package safety holds defensive helpers used across the rest of the codebase:
// credential redaction and mutating-XML detection.
package safety

import (
	"regexp"
)

var (
	xmlUsernameRe = regexp.MustCompile(`(?s)<Username>.*?</Username>`)
	xmlPasswordRe = regexp.MustCompile(`(?s)<Password>.*?</Password>`)

	// Loose substring redactor for log lines that mention creds in non-XML form.
	stringPasswordRe = regexp.MustCompile(`(?i)(password\s*[=:]\s*)\S+`)
)

// RedactXML replaces <Username>…</Username> and <Password>…</Password> contents
// with ***. Idempotent. Never modifies any other XML structure.
func RedactXML(b []byte) []byte {
	b = xmlUsernameRe.ReplaceAll(b, []byte("<Username>***</Username>"))
	b = xmlPasswordRe.ReplaceAll(b, []byte("<Password>***</Password>"))
	return b
}

// RedactString scrubs `password=...` style substrings from arbitrary log lines.
func RedactString(s string) string {
	return stringPasswordRe.ReplaceAllString(s, "${1}***")
}
