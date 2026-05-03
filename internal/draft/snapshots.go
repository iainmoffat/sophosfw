package draft

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ListSnapshots returns the absolute paths of all snapshot files for
// ruleName, sorted oldest-first by filename. Includes both regular
// `<slug>-<ts>.yaml` files and the `-deleted` tombstones.
func ListSnapshots(baseDir, profile, ruleName string) ([]string, error) {
	dir := filepath.Join(baseDir, "profiles", profile, "snapshots")
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

// RotateSnapshots deletes the oldest snapshots for ruleName so that at
// most `keep` remain. If keep <= 0, nothing is deleted (defensive
// guard). If fewer than keep snapshots exist, no-op.
func RotateSnapshots(baseDir, profile, ruleName string, keep int) error {
	if keep <= 0 {
		return nil
	}
	all, err := ListSnapshots(baseDir, profile, ruleName)
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
