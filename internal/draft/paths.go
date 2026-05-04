// Package draft owns the on-disk YAML draft and snapshot file format
// for the Phase 7 firewall rule editing workflow.
package draft

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/iainmoffat/sophosfw/internal/sophos"
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

// validTags lists the tag values DraftPath/SnapshotPath/ListSnapshots/
// RotateSnapshots accept. A closed allowlist defends against
// path-traversal via the tag parameter.
var validTags = map[string]struct{}{
	"firewall": {},
	"nat":      {},
}

// DraftPath returns the absolute path to the draft file for ruleName
// under baseDir/profiles/<profile>/drafts/<tag>/. Tag must be a member
// of validTags.
func DraftPath(baseDir, profile, tag, ruleName string) (string, error) {
	if _, ok := validTags[tag]; !ok {
		return "", fmt.Errorf("draft: invalid tag %q (allowed: firewall, nat)", tag)
	}
	dir := filepath.Join(baseDir, "profiles", profile, "drafts", tag)
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
// ruleName at time t under baseDir/profiles/<profile>/snapshots/<tag>/.
func SnapshotPath(baseDir, profile, tag, ruleName string, t time.Time) (string, error) {
	if _, ok := validTags[tag]; !ok {
		return "", fmt.Errorf("draft: invalid tag %q (allowed: firewall, nat)", tag)
	}
	dir := filepath.Join(baseDir, "profiles", profile, "snapshots", tag)
	slug := Slug(ruleName)
	stamp := t.UTC().Format("2006-01-02T15-04-05Z")
	return filepath.Join(dir, slug+"-"+stamp+".yaml"), nil
}

// nameHash returns the first 6 hex chars of SHA-256(name).
// 6 hex chars = 24 bits → ~50% collision probability around 4096
// distinct rule names per profile. Acceptable for per-user local
// stores; revisit if multi-tenant usage emerges.
func nameHash(name string) string {
	h := sha256.Sum256([]byte(name))
	return hex.EncodeToString(h[:])[:6]
}

// profileNameRe is the allowlist for profile names embedded in filesystem
// paths. ASCII letters, digits, dash, and underscore. Defends against
// path-traversal (e.g. "../etc") and surprising filesystem characters.
var profileNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validProfileName reports whether name is safe to embed in a filesystem
// path under baseDir/profiles/. Empty names and names with separators or
// traversal sequences are rejected.
func validProfileName(name string) bool {
	if name == "" {
		return false
	}
	return profileNameRe.MatchString(name)
}

// BackupRootDir returns the directory containing all backup snapshots
// for a profile. Created lazily by BackupSvc.Create.
func BackupRootDir(baseDir, profile string) (string, error) {
	if !validProfileName(profile) {
		return "", fmt.Errorf("%w: invalid profile name %q", sophos.ErrInvalidRequest, profile)
	}
	return filepath.Join(baseDir, "profiles", profile, "backups"), nil
}

// BackupSnapshotDir returns the absolute path for a single backup
// snapshot. Format mirrors SnapshotPath: <root>/2026-05-03T20-30-00Z.
func BackupSnapshotDir(baseDir, profile string, t time.Time) (string, error) {
	root, err := BackupRootDir(baseDir, profile)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, t.UTC().Format("2006-01-02T15-04-05Z")), nil
}

// readHeaderRule reads just the `# rule:` line from a draft or snapshot
// file's header. Both formats share the same header structure so this
// helper works on either. Returns "" if the file exists but has no
// parseable header. Returns os.IsNotExist if the file is absent.
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
