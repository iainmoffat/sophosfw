package draft

import (
	"os"
	"path/filepath"
	"strings"
)

// MigrateLegacyLayout walks <baseDir>/profiles/<profile>/drafts/ and
// <baseDir>/profiles/<profile>/snapshots/ for *.yaml files at the top
// level (pre-Phase-8 flat layout) and moves them into the firewall/
// subdirectory. Idempotent: safe to call on every cli invocation. On
// collision (target path already exists), leaves the legacy file in
// place — no overwrite.
func MigrateLegacyLayout(baseDir, profile string) error {
	for _, kind := range []string{"drafts", "snapshots"} {
		dir := filepath.Join(baseDir, "profiles", profile, kind)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		targetDir := filepath.Join(dir, "firewall")
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".yaml") {
				continue
			}
			src := filepath.Join(dir, name)
			dst := filepath.Join(targetDir, name)
			if _, err := os.Stat(dst); err == nil {
				continue // collision — leave legacy in place
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := os.MkdirAll(targetDir, 0o700); err != nil {
				return err
			}
			if err := os.Rename(src, dst); err != nil {
				return err
			}
		}
	}
	return nil
}
