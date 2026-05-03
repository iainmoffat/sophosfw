// Package draft owns the on-disk YAML draft and snapshot file format
// for the Phase 7 firewall rule editing workflow.
package draft

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Slug derives a filesystem-safe slug from a Sophos rule name.
// Rule names can contain spaces, slashes, punctuation, and unicode;
// the slug is lowercase ASCII alphanumerics with single dashes between
// runs of replaced characters. If the input slugs to the empty string
// (e.g., all-unicode), the literal "rule" is returned.
func Slug(name string) string {
	lower := strings.ToLower(name)
	re := regexp.MustCompile(`[^a-z0-9]+`)
	s := re.ReplaceAllString(lower, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "rule"
	}
	return s
}

// DraftPath returns the absolute path to the draft file for ruleName.
// If a draft already exists at the plain-slug path but its header
// records a DIFFERENT original rule name, returns a path with a
// 6-hex-char suffix derived from SHA-256(ruleName).
func DraftPath(baseDir, profile, ruleName string) (string, error) {
	dir := filepath.Join(baseDir, "profiles", profile, "drafts")
	slug := Slug(ruleName)
	plain := filepath.Join(dir, slug+".yaml")

	existing, err := readHeaderRule(plain)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if os.IsNotExist(err) || existing == "" || existing == ruleName {
		return plain, nil
	}

	suffix := nameHash(ruleName)
	return filepath.Join(dir, slug+"-"+suffix+".yaml"), nil
}

// SnapshotPath returns the absolute path to the snapshot file for
// ruleName at time t. Time formatted as ISO 8601 UTC with colons
// replaced by dashes.
func SnapshotPath(baseDir, profile, ruleName string, t time.Time) (string, error) {
	dir := filepath.Join(baseDir, "profiles", profile, "snapshots")
	slug := Slug(ruleName)
	stamp := t.UTC().Format("2006-01-02T15-04-05Z")
	return filepath.Join(dir, slug+"-"+stamp+".yaml"), nil
}

// nameHash returns the first 6 hex chars of SHA-256(name).
func nameHash(name string) string {
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:])[:6]
}

// readHeaderRule reads just the `# rule:` line from a draft file's
// header. Returns "" if the file exists but has no parseable header.
// Returns os.IsNotExist if the file is absent.
func readHeaderRule(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.SplitN(string(b), "\n", 33)
	for i, line := range lines {
		if i >= 32 {
			break
		}
		if strings.TrimSpace(line) == "---" {
			break
		}
		const prefix = "# rule:"
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix)), nil
		}
	}
	return "", nil
}
