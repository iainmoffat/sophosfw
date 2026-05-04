package draft

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ListSnapshots returns the absolute paths of all snapshot files for
// ruleName under <profile>/snapshots/<tag>/, sorted oldest-first.
// Includes both regular and -deleted tombstones.
func ListSnapshots(baseDir, profile, tag, ruleName string) ([]string, error) {
	if _, ok := validTags[tag]; !ok {
		return nil, fmt.Errorf("draft: invalid tag %q (allowed: firewall, nat, vpn)", tag)
	}
	dir := filepath.Join(baseDir, "profiles", profile, "snapshots", tag)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	slug := Slug(ruleName)
	prefix := slug + "-"
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	return out, nil
}

// RotateSnapshots deletes oldest snapshots for ruleName so at most
// `keep` remain. keep <= 0 → no-op.
func RotateSnapshots(baseDir, profile, tag, ruleName string, keep int) error {
	if keep <= 0 {
		return nil
	}
	all, err := ListSnapshots(baseDir, profile, tag, ruleName)
	if err != nil {
		return err
	}
	if len(all) <= keep {
		return nil
	}
	toDelete := all[:len(all)-keep]
	for _, p := range toDelete {
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	return nil
}
