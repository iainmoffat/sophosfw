# sophosfw Phase 8 Implementation Plan

**Goal:** Extend the Phase 7 pull/diff/push/delete pipeline to NATRule, validating that the draft-edit machinery generalizes to a second rule type.

**Architecture:** A new `NATRuleSvc` mirrors `FirewallRuleSvc` 1:1 with three differences (XML wrapper tag, required-fields list, reference extractor). The `internal/draft/` path API gains a `tag` parameter (`"firewall"` | `"nat"`) that selects a per-tag subdirectory for drafts and snapshots; a one-time migration moves any pre-Phase-8 flat-layout files into the `firewall/` subdirectory at first cli invocation.

**Tech Stack:** Go 1.26+, `gopkg.in/yaml.v3`, `encoding/xml`. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-02-sophosfw-phase8-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.6.1`. Working dir: `/Users/ipm/code/sophosfw`.

Before starting Task 1:
```bash
git status
go test ./... -count=1
```
Expected: clean status, all tests pass.

## File structure

**New files:**
- `internal/draft/migrate.go` — `MigrateLegacyLayout(baseDir, profile string) error`.
- `internal/draft/migrate_test.go` — migration unit tests.
- `internal/svc/natrule_pull.go` — `NATRuleSvc` with Pull/Diff/Push/Delete + helpers.
- `internal/svc/natrule_pull_test.go` — service-layer tests.
- `internal/cli/natrule_mutation.go` — 4 cobra subcommands.
- `internal/cli/natrule_mutation_test.go` — cli tests.

**Modified files:**
- `internal/catalog/objects.yaml` — flag NATRule mutable.
- `internal/catalog/catalog_test.go` — assert NATRule.Mutable.
- `internal/draft/paths.go` — `DraftPath` and `SnapshotPath` gain `tag` parameter.
- `internal/draft/paths_test.go` — update existing tests + add tag-subdir tests.
- `internal/draft/snapshots.go` — `ListSnapshots` and `RotateSnapshots` gain `tag`.
- `internal/draft/snapshots_test.go` — update + extend.
- `internal/svc/firewallrule_pull.go` — pass `"firewall"` to all draft-package calls.
- `internal/svc/firewallrule_pull_test.go` — pass `"firewall"` through; otherwise unchanged.
- `internal/cli/firewallrule.go` — invoke migration in factory.
- `internal/cli/natrule.go` — register the 4 new subcommands.
- `internal/render/envelope.go` — 3 new envelope functions.
- `internal/render/envelope_test.go` — assertions for the 3 schemas.
- `internal/testutil/integration_test.go` — 3 new integration tests.
- `docs/api-coverage.md` — NATRule row update.
- `docs/roadmap.md` — Phase 8 marked complete.

---

## Task 1: Flag NATRule as Mutable in the catalog

**Files:**
- Modify: `internal/catalog/objects.yaml`
- Modify: `internal/catalog/catalog_test.go`

Tiny mechanical change — same shape as Phase 7 T1 for FirewallRule.

- [ ] **Step 1: Find the NATRule entry**

```bash
grep -n -A 4 "xmlTag: NATRule" /Users/ipm/code/sophosfw/internal/catalog/objects.yaml
```

- [ ] **Step 2: Add `mutable: true` to the NATRule entry**

In `internal/catalog/objects.yaml`, locate the `- xmlTag: NATRule` block and add `mutable: true` as a sibling field, matching how IPHost and FirewallRule have it.

- [ ] **Step 3: Add a test asserting NATRule is mutable**

Append to `internal/catalog/catalog_test.go`:

```go
func TestCatalog_NATRuleIsMutable(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	entry, ok := c.Resolve("NATRule")
	require.True(t, ok)
	require.True(t, entry.Mutable)
}
```

If `TestCatalog_OtherEntriesNotMutable` lists "NATRule" (it does in the existing test), remove it from that list.

- [ ] **Step 4: Run**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/catalog -count=1 -v
```
Expected: PASS, including the new test.

- [ ] **Step 5: Commit**

```bash
git add internal/catalog/objects.yaml internal/catalog/catalog_test.go
git commit -m "feat(catalog): NATRule flagged mutable for Phase 8"
```

---

## Task 2: Add `tag` parameter to draft path API

**Files:**
- Modify: `internal/draft/paths.go`
- Modify: `internal/draft/paths_test.go`
- Modify: `internal/draft/snapshots.go`
- Modify: `internal/draft/snapshots_test.go`
- Modify: `internal/svc/firewallrule_pull.go`
- Modify: `internal/svc/firewallrule_pull_test.go`

Refactor: `DraftPath`, `SnapshotPath`, `ListSnapshots`, `RotateSnapshots` all gain a `tag string` parameter (after `profile`, before `ruleName`). Tag is the subdirectory name (`"firewall"` or `"nat"`).

- [ ] **Step 1: Write tag validation tests first**

Append to `internal/draft/paths_test.go`:

```go
func TestDraftPath_TagInPath(t *testing.T) {
	base := t.TempDir()
	p, err := DraftPath(base, "home", "firewall", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "profiles", "home", "drafts", "firewall", "wan-to-lan.yaml"), p)

	p2, err := DraftPath(base, "home", "nat", "DNAT-to-X")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "profiles", "home", "drafts", "nat", "dnat-to-x.yaml"), p2)
}

func TestSnapshotPath_TagInPath(t *testing.T) {
	base := t.TempDir()
	tt := mustParseTime(t, "2026-05-02T15:30:00Z")
	p, err := SnapshotPath(base, "home", "nat", "X", tt)
	require.NoError(t, err)
	require.Contains(t, p, filepath.Join("profiles", "home", "snapshots", "nat"))
}

func TestDraftPath_RejectsInvalidTag(t *testing.T) {
	base := t.TempDir()
	_, err := DraftPath(base, "home", "../etc", "X")
	require.Error(t, err)
}
```

- [ ] **Step 2: Run — expected to fail to compile**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
```

- [ ] **Step 3: Update `internal/draft/paths.go`**

Replace the existing `DraftPath` and `SnapshotPath` with these versions (preserving everything else in the file):

```go
// validTags lists the tag values DraftPath/SnapshotPath accept. A
// closed allowlist is the safest defense against path-traversal via the
// tag parameter.
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
```

Add `"fmt"` to the imports if not already present.

- [ ] **Step 4: Update `internal/draft/snapshots.go`**

```go
// ListSnapshots returns the absolute paths of all snapshot files for
// ruleName under <profile>/snapshots/<tag>/, sorted oldest-first.
func ListSnapshots(baseDir, profile, tag, ruleName string) ([]string, error) {
	if _, ok := validTags[tag]; !ok {
		return nil, fmt.Errorf("draft: invalid tag %q (allowed: firewall, nat)", tag)
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

// RotateSnapshots deletes the oldest snapshots for ruleName so that at
// most `keep` remain. If keep <= 0, no-op.
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
```

Add `"fmt"` to the imports if not already present.

- [ ] **Step 5: Update existing draft tests to pass `"firewall"` tag**

In `internal/draft/paths_test.go`, every existing call to `DraftPath(base, "home", "X")` must become `DraftPath(base, "home", "firewall", "X")`. Same for `SnapshotPath`.

In `internal/draft/snapshots_test.go`, every existing call to `ListSnapshots(base, "home", "X")` becomes `ListSnapshots(base, "home", "firewall", "X")`. Same for `RotateSnapshots`. Also: each test that pre-populates a snapshots directory needs to write to the `firewall/` subdir:

```go
dir := filepath.Join(base, "profiles", "home", "snapshots", "firewall")
require.NoError(t, os.MkdirAll(dir, 0o700))
```

- [ ] **Step 6: Update `internal/svc/firewallrule_pull.go` callers**

In every place `firewallrule_pull.go` calls `draft.DraftPath`, `draft.SnapshotPath`, `draft.ListSnapshots`, `draft.RotateSnapshots`, insert `"firewall"` as the third argument. Roughly 8 call sites — search with:

```bash
grep -n "draft\." /Users/ipm/code/sophosfw/internal/svc/firewallrule_pull.go
```

For each, change e.g.:
```go
draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
```
to:
```go
draftPath, err := draft.DraftPath(s.BaseDir, name, "firewall", ruleName)
```

Same for `SnapshotPath`, `ListSnapshots`, `RotateSnapshots`.

- [ ] **Step 7: Update `internal/svc/firewallrule_pull_test.go` if it calls draft functions directly**

```bash
grep -n "draft\." /Users/ipm/code/sophosfw/internal/svc/firewallrule_pull_test.go
```

For each direct call to `draft.ListSnapshots`/`draft.ReadDraft`/`draft.WriteDraft`, update the signature where needed. (Note: `ReadDraft` and `WriteDraft` take a path string and don't change signature; only the `*Path`/`*Snapshots` helpers gain `tag`.)

A few tests pre-create snapshot files at `filepath.Join(baseDir, "profiles", "home", "snapshots")` — these need to use the `firewall/` subdir now: `filepath.Join(baseDir, "profiles", "home", "snapshots", "firewall")`.

- [ ] **Step 8: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft ./internal/svc -count=1 -v 2>&1 | tail -40
```

If anything fails, the most likely cause is a missed call site in `firewallrule_pull.go` or `firewallrule_pull_test.go`.

- [ ] **Step 9: Commit**

```bash
git add internal/draft/paths.go internal/draft/paths_test.go internal/draft/snapshots.go internal/draft/snapshots_test.go internal/svc/firewallrule_pull.go internal/svc/firewallrule_pull_test.go
git commit -m "refactor(draft): add tag parameter to path API for per-tag subdirs"
```

---

## Task 3: Migration helper

**Files:**
- Create: `internal/draft/migrate.go`
- Create: `internal/draft/migrate_test.go`

`MigrateLegacyLayout` walks `<profile>/drafts/` and `<profile>/snapshots/` for top-level `*.yaml` files (pre-Phase-8 layout) and moves them into the `firewall/` subdirectory.

- [ ] **Step 1: Write failing tests**

Create `/Users/ipm/code/sophosfw/internal/draft/migrate_test.go`:

```go
package draft

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrateLegacyLayout_NoOp_EmptyProfile(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, MigrateLegacyLayout(base, "home"))
}

func TestMigrateLegacyLayout_MovesFlatDraftsToFirewall(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "wan-to-lan.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("# rule: WAN-to-LAN\n"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	// Legacy file gone, file present in firewall/
	_, err := os.Stat(legacy)
	require.True(t, os.IsNotExist(err))
	migrated := filepath.Join(dir, "firewall", "wan-to-lan.yaml")
	_, err = os.Stat(migrated)
	require.NoError(t, err)
}

func TestMigrateLegacyLayout_MovesFlatSnapshotsToFirewall(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("# rule: WAN-to-LAN\n"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	_, err := os.Stat(legacy)
	require.True(t, os.IsNotExist(err))
	migrated := filepath.Join(dir, "firewall", "wan-to-lan-2026-05-02T10-00-00Z.yaml")
	_, err = os.Stat(migrated)
	require.NoError(t, err)
}

func TestMigrateLegacyLayout_SkipsCollisions(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "firewall"), 0o700))
	legacy := filepath.Join(dir, "x.yaml")
	migrated := filepath.Join(dir, "firewall", "x.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("legacy"), 0o600))
	require.NoError(t, os.WriteFile(migrated, []byte("migrated"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	// Both should still exist; legacy not overwritten.
	got, err := os.ReadFile(legacy)
	require.NoError(t, err)
	require.Equal(t, "legacy", string(got))
	got2, err := os.ReadFile(migrated)
	require.NoError(t, err)
	require.Equal(t, "migrated", string(got2))
}

func TestMigrateLegacyLayout_Idempotent(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "x.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("a"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))
	require.NoError(t, MigrateLegacyLayout(base, "home"))

	migrated := filepath.Join(dir, "firewall", "x.yaml")
	got, err := os.ReadFile(migrated)
	require.NoError(t, err)
	require.Equal(t, "a", string(got))
}

func TestMigrateLegacyLayout_LeavesSubdirEntriesAlone(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "drafts", "firewall")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	already := filepath.Join(dir, "x.yaml")
	require.NoError(t, os.WriteFile(already, []byte("ok"), 0o600))

	require.NoError(t, MigrateLegacyLayout(base, "home"))

	got, err := os.ReadFile(already)
	require.NoError(t, err)
	require.Equal(t, "ok", string(got))
}
```

- [ ] **Step 2: Run — must fail (function not defined)**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -run TestMigrateLegacyLayout -v
```

- [ ] **Step 3: Implement `internal/draft/migrate.go`**

```go
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
			// On collision, skip (don't overwrite).
			if _, err := os.Stat(dst); err == nil {
				continue
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
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/draft/migrate.go internal/draft/migrate_test.go
git commit -m "feat(draft): MigrateLegacyLayout for pre-Phase-8 flat directory"
```

---

## Task 4: `NATRuleSvc.Pull` + reference extractor

**Files:**
- Create: `internal/svc/natrule_pull.go`
- Create: `internal/svc/natrule_pull_test.go`

Mirrors `FirewallRuleSvc.Pull` with NAT-specific changes: tag `"nat"`, `extractNATReferences` instead of `extractReferences`, audit operation `nat_rule_pull`.

`FirewallRuleSvc.Get` exists as a method on the existing struct — but `NATRuleSvc` needs its own `Get` returning a `map[string]any`. Pattern: mirror the existing `FirewallRuleSvc.Get` (which delegates to `Inner.Get` and converts to map).

- [ ] **Step 1: Write failing tests**

Create `/Users/ipm/code/sophosfw/internal/svc/natrule_pull_test.go`:

```go
package svc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeNATClient struct {
	body    map[string]any
	sent    [][]byte
	sendErr error
}

func (f *fakeNATClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "NATRule" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["NATRule"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeNATClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sophos.Response{LoginOK: true}, nil
}

func newNATSvc(t *testing.T, body map[string]any) (*NATRuleSvc, *fakeNATClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	baseDir := t.TempDir()
	fc := &fakeNATClient{body: body}
	svc := &NATRuleSvc{
		Inner: &ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		},
		Audit:   audit,
		BaseDir: baseDir,
		Now:     func() time.Time { return time.Date(2026, 5, 2, 15, 30, 0, 0, time.UTC) },
	}
	return svc, fc, baseDir
}

func TestNATRuleSvc_Pull_WritesSnapshotAndDraft(t *testing.T) {
	body := map[string]any{
		"Name":     "DNAT-X",
		"Status":   "Enable",
		"IPFamily": "IPv4",
		"Position": "Top",
		"OriginalSourceNetworks":      map[string]any{"Network": "Any"},
		"OriginalDestinationNetworks": map[string]any{"Network": "#Port4"},
		"OriginalServices":            map[string]any{"Service": "HTTPS"},
		"TranslatedSource":            "Original",
		"TranslatedDestination":       "http-proxy01",
		"TranslatedService":           "Original",
		"LinkedFirewallrule":          "None",
	}
	svc, _, _ := newNATSvc(t, body)

	out, err := svc.Pull(context.Background(), "home", "DNAT-X")
	require.NoError(t, err)
	require.Equal(t, "DNAT-X", out.Rule)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)
	// Path should be under nat/ subdir.
	require.Contains(t, out.DraftPath, filepath.Join("drafts", "nat"))
	require.Contains(t, out.SnapshotPath, filepath.Join("snapshots", "nat"))

	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "DNAT-X", d.Rule)
	require.Contains(t, string(d.Body), "Name: DNAT-X")

	allRefs := []string{}
	for _, rs := range out.References {
		allRefs = append(allRefs, rs.Type+":"+fmt.Sprint(rs.Names))
	}
	joined := strings.Join(allRefs, ",")
	require.Contains(t, joined, "#Port4")
	require.Contains(t, joined, "http-proxy01")
	require.Contains(t, joined, "HTTPS")
	// "Original", "None", "Any" should be filtered out — they're sentinels.
	require.NotContains(t, joined, "Original")
	require.NotContains(t, joined, "[None]")
}

func TestNATRuleSvc_Pull_RuleNotFound(t *testing.T) {
	svc, _, _ := newNATSvc(t, nil)
	_, err := svc.Pull(context.Background(), "home", "Missing")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestNATRuleSvc_Pull_AuditLogged(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_pull"`)
	require.Contains(t, string(logBody), `"objectType":"NATRule"`)
}

func TestExtractNATReferences_AllFieldKinds(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
		"OriginalSourceNetworks":      map[string]any{"Network": []any{"A", "B"}},
		"OriginalDestinationNetworks": map[string]any{"Network": "C"},
		"OriginalServices":            map[string]any{"Service": "HTTP"},
		"TranslatedSource":            "src-translated",
		"TranslatedDestination":       "dst-translated",
		"TranslatedService":           "svc-translated",
		"LinkedFirewallrule":          "linked-rule",
		"InboundInterfaces":           map[string]any{"Interface": "Port4"},
	}
	refs := extractNATReferences(body)

	collect := func(kind string) []string {
		for _, r := range refs {
			if r.Type == kind {
				return r.Names
			}
		}
		return nil
	}

	ipHosts := collect("IPHost")
	require.Contains(t, ipHosts, "A")
	require.Contains(t, ipHosts, "B")
	require.Contains(t, ipHosts, "C")
	require.Contains(t, ipHosts, "src-translated")
	require.Contains(t, ipHosts, "dst-translated")

	services := collect("Service")
	require.Contains(t, services, "HTTP")
	require.Contains(t, services, "svc-translated")

	rules := collect("FirewallRule")
	require.Contains(t, rules, "linked-rule")

	ifaces := collect("Interface")
	require.Contains(t, ifaces, "Port4")
}

func TestExtractNATReferences_FiltersSentinels(t *testing.T) {
	body := map[string]any{
		"TranslatedSource":      "Original",
		"TranslatedDestination": "Original",
		"TranslatedService":     "Original",
		"LinkedFirewallrule":    "None",
	}
	refs := extractNATReferences(body)
	// All sentinels → no references at all.
	require.Empty(t, refs)
}
```

- [ ] **Step 2: Run — must fail (compile)**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestNATRuleSvc_Pull|TestExtractNATReferences" -v
```

- [ ] **Step 3: Implement `internal/svc/natrule_pull.go`**

```go
package svc

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// NATRuleSvc serves the typed `nat rule` mutating surface (Phase 8).
// Mirrors FirewallRuleSvc with NATRule-specific marshaling, references,
// and required-field validation.
type NATRuleSvc struct {
	Inner   *ObjectSvc
	Audit   *AuditLog
	BaseDir string
	Now     func() time.Time
}

// NATRulePullResult is what Pull returns.
type NATRulePullResult struct {
	Profile      string
	Rule         string
	DraftPath    string
	SnapshotPath string
	DiffHash     string
	References   []ReferenceSummary
}

// Get fetches one NATRule by name, returned as a plain map.
func (s *NATRuleSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
	inner, err := s.Inner.Get(ctx, profileName, "NATRule", name)
	if err != nil {
		return nil, err
	}
	return toMap(inner.Data)
}

// Pull fetches the live NATRule, writes a snapshot + draft, rotates,
// audits, and returns paths + hash + references.
func (s *NATRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*NATRulePullResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	body, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("NAT rule %q: %w", ruleName, sophos.ErrNotFound)
	}

	hash, err := DiffHash(body)
	if err != nil {
		return nil, err
	}

	yamlBytes, err := marshalCanonicalYAML(body)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	snapPath, err := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
	if err != nil {
		return nil, err
	}

	d := &draft.Draft{
		Profile:  name,
		Rule:     ruleName,
		PulledAt: now,
		DiffHash: hash,
		Body:     yamlBytes,
	}

	// Draft first (Phase 7 cleanup ordering).
	if err := draft.WriteDraft(draftPath, d); err != nil {
		return nil, err
	}
	if err := draft.WriteDraft(snapPath, d); err != nil {
		return nil, err
	}
	if err := draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10); err != nil {
		return nil, err
	}

	if s.Audit != nil {
		_ = s.Audit.Write(AuditEntry{
			Profile:    name,
			Operation:  "nat_rule_pull",
			ObjectType: "NATRule",
			ObjectName: ruleName,
			Result:     "ok",
		})
	}

	return &NATRulePullResult{
		Profile:      name,
		Rule:         ruleName,
		DraftPath:    draftPath,
		SnapshotPath: snapPath,
		DiffHash:     hash,
		References:   extractNATReferences(body),
	}, nil
}

func (s *NATRuleSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// extractNATReferences walks a NATRule body for known reference-bearing
// fields and returns a deduplicated summary. Sentinel values "Original"
// (translation no-op) and "None" (no link) are filtered.
func extractNATReferences(body map[string]any) []ReferenceSummary {
	ipHosts := map[string]struct{}{}
	services := map[string]struct{}{}
	rules := map[string]struct{}{}
	ifaces := map[string]struct{}{}

	collectNames(body, "OriginalSourceNetworks", "Network", ipHosts)
	collectNames(body, "OriginalDestinationNetworks", "Network", ipHosts)
	collectNames(body, "OriginalServices", "Service", services)
	collectNames(body, "InboundInterfaces", "Interface", ifaces)

	addStringIfNot := func(sink map[string]struct{}, key, sentinel string) {
		v, ok := body[key].(string)
		if !ok || v == "" || v == sentinel {
			return
		}
		sink[v] = struct{}{}
	}

	addStringIfNot(ipHosts, "TranslatedSource", "Original")
	addStringIfNot(ipHosts, "TranslatedDestination", "Original")
	addStringIfNot(services, "TranslatedService", "Original")
	addStringIfNot(rules, "LinkedFirewallrule", "None")

	out := []ReferenceSummary{}
	if len(ipHosts) > 0 {
		out = append(out, ReferenceSummary{Type: "IPHost", Names: sortedKeysSet(ipHosts)})
	}
	if len(services) > 0 {
		out = append(out, ReferenceSummary{Type: "Service", Names: sortedKeysSet(services)})
	}
	if len(rules) > 0 {
		out = append(out, ReferenceSummary{Type: "FirewallRule", Names: sortedKeysSet(rules)})
	}
	if len(ifaces) > 0 {
		out = append(out, ReferenceSummary{Type: "Interface", Names: sortedKeysSet(ifaces)})
	}
	return out
}

// sortedKeysSet returns sorted keys of a string-set map. Helper avoids
// reusing firewallrule_pull.go's `keys` helper signature collision.
func sortedKeysSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

If `firewallrule_pull.go`'s `sortedKeys` (or `keys`) helper is already exported with a compatible signature, reuse that and delete `sortedKeysSet`. Verify:

```bash
grep -n "func sortedKeys\|func keys" /Users/ipm/code/sophosfw/internal/svc/firewallrule_pull.go
```

If the existing helper takes `map[string]struct{}` and returns sorted `[]string`, just use it. The reference test should pass either way.

`collectNames` and `toMap` are existing helpers in the svc package (from Phase 7 / Phase 3) — confirm by grep before assuming they're available.

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestNATRuleSvc_Pull|TestExtractNATReferences" -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/natrule_pull.go internal/svc/natrule_pull_test.go
git commit -m "feat(svc): NATRuleSvc.Pull with NAT-specific reference extractor"
```

---

## Task 5: `NATRuleSvc.Diff`

**Files:**
- Modify: `internal/svc/natrule_pull.go`
- Modify: `internal/svc/natrule_pull_test.go`

Local-only diff. Mirrors `FirewallRuleSvc.Diff` exactly except the tag is `"nat"`.

- [ ] **Step 1: Append failing tests**

Append to `internal/svc/natrule_pull_test.go`:

```go
import "bytes" // add to imports if not present

func TestNATRuleSvc_Diff_NoChanges(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Diff(context.Background(), "home", "X")
	require.NoError(t, err)
	require.False(t, out.HasChanges)
	require.Empty(t, out.UnifiedDiff)
}

func TestNATRuleSvc_Diff_DetectsFieldChange(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, _ := newNATSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("Status: Enable"), []byte("Status: Disable"))
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	out, err := svc.Diff(context.Background(), "home", "X")
	require.NoError(t, err)
	require.True(t, out.HasChanges)
	require.Contains(t, out.UnifiedDiff, "-Status: Enable")
	require.Contains(t, out.UnifiedDiff, "+Status: Disable")
}

func TestNATRuleSvc_Diff_MissingSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, _, baseDir := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots", "nat")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		require.NoError(t, os.Remove(filepath.Join(dir, e.Name())))
	}
	_, err = svc.Diff(context.Background(), "home", "X")
	require.Error(t, err)
	require.True(t, errors.Is(err, draft.ErrSnapshotMissing))
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_Diff -v
```

- [ ] **Step 3: Append Diff to `internal/svc/natrule_pull.go`**

```go
// NATRuleDiffResult is what Diff returns.
type NATRuleDiffResult struct {
	Profile        string
	Rule           string
	HasChanges     bool
	UnifiedDiff    string
	StructuredDiff []DiffEntry
}

// Diff reads the draft for ruleName, finds the snapshot whose diffHash
// matches, and returns unified + structured diff. Local only.
func (s *NATRuleSvc) Diff(ctx context.Context, profileName, ruleName string) (*NATRuleDiffResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	snaps, err := draft.ListSnapshots(s.BaseDir, name, "nat", ruleName)
	if err != nil {
		return nil, err
	}
	var snapBody []byte
	for _, p := range snaps {
		sd, err := draft.ReadDraft(p)
		if err != nil {
			continue
		}
		if sd.DiffHash == d.DiffHash {
			snapBody = sd.Body
			break
		}
	}
	if snapBody == nil {
		return nil, fmt.Errorf("for draft %s: %w", draftPath, draft.ErrSnapshotMissing)
	}

	out := &NATRuleDiffResult{
		Profile:        name,
		Rule:           ruleName,
		StructuredDiff: []DiffEntry{},
	}
	out.UnifiedDiff = draft.UnifiedDiff(snapBody, d.Body, "snapshot", "draft")
	out.HasChanges = out.UnifiedDiff != ""
	if out.HasChanges {
		entries, err := structuredDiff(snapBody, d.Body)
		if err != nil {
			return nil, err
		}
		out.StructuredDiff = entries
	}
	return out, nil
}
```

(`structuredDiff` is the existing helper from `firewallrule_pull.go` — it parses YAML maps and produces `[]DiffEntry`. Reuse as-is.)

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run "TestNATRuleSvc" -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/natrule_pull.go internal/svc/natrule_pull_test.go
git commit -m "feat(svc): NATRuleSvc.Diff — local unified + structured diff"
```

---

## Task 6: `NATRuleSvc.Push` + `marshalNATRule`

**Files:**
- Modify: `internal/svc/natrule_pull.go`
- Modify: `internal/svc/natrule_pull_test.go`

The mutating critical path. Mirrors Phase 7's `FirewallRuleSvc.Push` with deferred audit pattern from v0.6.1.

- [ ] **Step 1: Append failing tests**

Append to `internal/svc/natrule_pull_test.go`:

```go
func TestNATRuleSvc_Push_DryRun_NoSend(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_Apply_RefetchAndArchive(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)
}

func TestNATRuleSvc_Push_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_DiffHashMismatch_IgnoreFlag_Applies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", true, false)
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
}

func TestNATRuleSvc_Push_HeaderRuleMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Rule = "Different"
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("IPFamily: IPv4\n"), nil)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "IPFamily")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Push_Failure_AuditLogged(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.sendErr = sophos.ErrServerError

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)

	logBody, err := os.ReadFile(filepath.Join(svc.Audit.Dir(), "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"nat_rule_push"`)
	require.Contains(t, string(logBody), `"result":"error:server_error"`)
}

func TestMarshalNATRule_TagWrapper(t *testing.T) {
	rule := map[string]any{
		"Name": "X", "Status": "Enable",
	}
	out, err := marshalNATRule(rule)
	require.NoError(t, err)
	s := string(out)
	require.True(t, strings.HasPrefix(s, "<NATRule>"))
	require.True(t, strings.HasSuffix(s, "</NATRule>"))
	require.Contains(t, s, "<Name>X</Name>")
	require.Contains(t, s, "<Status>Enable</Status>")
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_Push -v
```

- [ ] **Step 3: Append Push and marshalNATRule to `internal/svc/natrule_pull.go`**

```go
import (
	// ADD if not already imported:
	"bytes"
	"github.com/iainmoffat/sophosfw/internal/safety"
)

// NATRulePushResult is what Push and Delete return.
type NATRulePushResult struct {
	Profile     string
	Rule        string
	Operation   string
	DryRun      bool
	Preview     *Preview
	NewDiffHash string
	Item        map[string]any
}

var requiredNATRuleFields = []string{"Name", "Status", "IPFamily"}

// Push validates the draft and applies it to the firewall.
func (s *NATRuleSvc) Push(ctx context.Context, profileName, ruleName string, ignoreHash, dryRun bool) (out *NATRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_push",
		ObjectType: "NATRule",
		ObjectName: ruleName,
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	draftPath, perr := draft.DraftPath(s.BaseDir, name, "nat", ruleName)
	if perr != nil {
		return nil, perr
	}
	d, perr := draft.ReadDraft(draftPath)
	if perr != nil {
		return nil, perr
	}

	if d.Rule != ruleName {
		return nil, fmt.Errorf("%w: draft header rule %q does not match cli arg %q", sophos.ErrInvalidRequest, d.Rule, ruleName)
	}
	if d.Profile != name {
		return nil, fmt.Errorf("%w: draft header profile %q does not match active profile %q", sophos.ErrInvalidRequest, d.Profile, name)
	}

	parsed, perr := parseAndValidateNATRuleBody(d.Body)
	if perr != nil {
		return nil, perr
	}

	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("NATRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: NATRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	entryAudit.ExpectedDiffHash = d.DiffHash
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}

	if !ignoreHash {
		live, perr := s.Get(ctx, profileName, ruleName)
		if perr != nil {
			return nil, perr
		}
		liveHash, perr := DiffHash(live)
		if perr != nil {
			return nil, perr
		}
		if liveHash != d.DiffHash {
			return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, d.DiffHash)
		}
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	inner, perr := marshalNATRule(parsed)
	if perr != nil {
		return nil, perr
	}
	full, perr := sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
	if perr != nil {
		return nil, perr
	}
	entryAudit.RedactedXML = string(safety.RedactXML(full))

	if dryRun {
		mutating, verbs := safety.IsMutating(full)
		pv := &Preview{
			Profile:        name,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    entryAudit.RedactedXML,
			WouldSendBytes: len(full),
		}
		entryAudit.Result = "ok (dry-run)"
		_ = s.Audit.Write(entryAudit)
		return &NATRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "update",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	refetched, _ := s.Get(ctx, profileName, ruleName)
	newHash := ""
	if refetched != nil {
		nh, hashErr := DiffHash(refetched)
		if hashErr == nil {
			newHash = nh
		}
	}
	if refetched != nil && newHash != "" {
		now := s.now()
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile: name, Rule: ruleName, PulledAt: now, DiffHash: newHash, Body: yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10)
			}
		}
		d.DiffHash = newHash
		_ = draft.WriteDraft(draftPath, d)
	}

	return &NATRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}

func parseAndValidateNATRuleBody(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := yamlUnmarshalNAT(body, &m); err != nil {
		return nil, fmt.Errorf("%w: draft body is not valid YAML: %v", sophos.ErrInvalidRequest, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: draft body is empty", sophos.ErrInvalidRequest)
	}
	for _, k := range requiredNATRuleFields {
		v, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("%w: draft body missing required field %q", sophos.ErrInvalidRequest, k)
		}
		if str, isStr := v.(string); isStr && str == "" {
			return nil, fmt.Errorf("%w: draft body field %q is empty", sophos.ErrInvalidRequest, k)
		}
	}
	return m, nil
}

// yamlUnmarshalNAT exists so this file doesn't need to import yaml.v3
// directly; the firewallrule_pull.go file already imports it. We
// dispatch through a small wrapper that calls yaml.Unmarshal via the
// existing path. If that wrapper isn't already defined, define one
// here:
var yamlUnmarshalNAT = parseYAMLBody

// parseYAMLBody is defined in firewallrule_pull.go (or elsewhere in
// this package) as a thin wrapper around yaml.Unmarshal returning
// map[string]any. If it doesn't already exist, the implementer should
// add it to firewallrule_pull.go and reuse — OR just add the yaml.v3
// import directly to natrule_pull.go and call yaml.Unmarshal here.
// Either is acceptable; the latter is simpler.
```

**Implementer note on the yaml import:** the cleanest path is to drop the indirection and just import `yaml.v3` directly:

```go
import "gopkg.in/yaml.v3"

func parseAndValidateNATRuleBody(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: draft body is not valid YAML: %v", sophos.ErrInvalidRequest, err)
	}
	// ... required-field check identical to above ...
}
```

Delete the `yamlUnmarshalNAT` and `parseYAMLBody` indirection. Use `yaml.Unmarshal` directly.

**marshalNATRule:**

```go
// marshalNATRule converts the parsed rule body to XML wrapped in
// <NATRule>...</NATRule>. Lower-level helpers (writeMapChildren,
// writeKeyValue, writeOpen, writeClose, validateXMLName) are
// tag-agnostic and live in firewallrule_pull.go — reused as-is.
func marshalNATRule(rule map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<NATRule>")
	if err := writeMapChildren(&buf, rule); err != nil {
		return nil, err
	}
	buf.WriteString("</NATRule>")
	return buf.Bytes(), nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_Push -v
go test ./internal/svc -run TestMarshalNATRule -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/natrule_pull.go internal/svc/natrule_pull_test.go
git commit -m "feat(svc): NATRuleSvc.Push with diff-hash, dry-run, audit, archive"
```

---

## Task 7: `NATRuleSvc.Delete`

**Files:**
- Modify: `internal/svc/natrule_pull.go`
- Modify: `internal/svc/natrule_pull_test.go`

Mirror of FirewallRuleSvc.Delete with `<NATRule>` envelope and `nat_rule_delete` audit op.

- [ ] **Step 1: Append failing tests**

Append to `internal/svc/natrule_pull_test.go`:

```go
func TestNATRuleSvc_Delete_RequiresExpectedHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestNATRuleSvc_Delete_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, baseDir := newNATSvc(t, body)
	hash, err := DiffHash(body)
	require.NoError(t, err)

	out, err := svc.Delete(context.Background(), "home", "X", hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "delete", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
	require.Contains(t, string(fc.sent[0]), `<Name>X</Name>`)

	dir := filepath.Join(baseDir, "profiles", "home", "snapshots", "nat")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	hasDeleted := false
	for _, e := range entries {
		if strings.Contains(e.Name(), "-deleted") {
			hasDeleted = true
		}
	}
	require.True(t, hasDeleted)
}

func TestNATRuleSvc_Delete_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	svc, fc, _ := newNATSvc(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc_Delete -v
```

- [ ] **Step 3: Append Delete to `internal/svc/natrule_pull.go`**

```go
import (
	// ADD if not already imported:
	"encoding/xml"
	"strings"
)

// Delete removes a NATRule by name. Same semantics as FirewallRuleSvc.Delete.
func (s *NATRuleSvc) Delete(ctx context.Context, profileName, ruleName, expectedHash string, ignoreHash, dryRun bool) (out *NATRulePushResult, err error) {
	profile, name, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	entryAudit := AuditEntry{
		Profile:    name,
		Operation:  "nat_rule_delete",
		ObjectType: "NATRule",
		ObjectName: ruleName,
	}
	if expectedHash != "" {
		entryAudit.ExpectedDiffHash = expectedHash
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}
	defer func() {
		if err != nil && s.Audit != nil && entryAudit.Result == "" {
			entryAudit.Result = "error:" + ErrorKind(err)
			entryAudit.ErrorMessage = err.Error()
			_ = s.Audit.Write(entryAudit)
		}
	}()

	if expectedHash == "" && !ignoreHash {
		return nil, fmt.Errorf("%w: expectedDiffHash is required for delete (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
	}

	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	catEntry, ok := s.Inner.Catalog.Resolve("NATRule")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: NATRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	live, perr := s.Get(ctx, profileName, ruleName)
	if perr != nil {
		return nil, perr
	}
	if live == nil {
		return nil, fmt.Errorf("NAT rule %q: %w", ruleName, sophos.ErrNotFound)
	}
	if !ignoreHash {
		liveHash, perr := DiffHash(live)
		if perr != nil {
			return nil, perr
		}
		if liveHash != expectedHash {
			return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, expectedHash)
		}
	}

	c, perr := s.Inner.Creds.Load(name)
	if perr != nil {
		return nil, perr
	}
	var inner bytes.Buffer
	inner.WriteString("<NATRule><Name>")
	if err := xml.EscapeText(&inner, []byte(ruleName)); err != nil {
		return nil, err
	}
	inner.WriteString("</Name></NATRule>")
	full, perr := sophos.BuildRemoveEnvelope(inner.Bytes(), c.Username, c.Password)
	if perr != nil {
		return nil, perr
	}
	entryAudit.RedactedXML = string(safety.RedactXML(full))

	if dryRun {
		mutating, verbs := safety.IsMutating(full)
		pv := &Preview{
			Profile:        name,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    entryAudit.RedactedXML,
			WouldSendBytes: len(full),
		}
		entryAudit.Result = "ok (dry-run)"
		_ = s.Audit.Write(entryAudit)
		return &NATRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "delete",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	now := s.now()
	regularPath, _ := draft.SnapshotPath(s.BaseDir, name, "nat", ruleName, now)
	deletedPath := strings.TrimSuffix(regularPath, ".yaml") + "-deleted.yaml"
	yamlBytes, merr := marshalCanonicalYAML(live)
	if merr == nil {
		liveHash, _ := DiffHash(live)
		_ = draft.WriteDraft(deletedPath, &draft.Draft{
			Profile: name, Rule: ruleName, PulledAt: now, DiffHash: liveHash, Body: yamlBytes,
		})
		_ = draft.RotateSnapshots(s.BaseDir, name, "nat", ruleName, 10)
	}

	return &NATRulePushResult{
		Profile:   name,
		Rule:      ruleName,
		Operation: "delete",
		DryRun:    false,
	}, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestNATRuleSvc -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/natrule_pull.go internal/svc/natrule_pull_test.go
git commit -m "feat(svc): NATRuleSvc.Delete with diff hash and -deleted archive"
```

---

## Task 8: Render envelopes

**Files:**
- Modify: `internal/render/envelope.go`
- Modify: `internal/render/envelope_test.go`

Three new functions, mechanical mirror of the firewallRule* envelopes.

- [ ] **Step 1: Append failing tests**

Append to `internal/render/envelope_test.go`:

```go
func TestNATRulePullEnvelope_Schema(t *testing.T) {
	r := &svc.NATRulePullResult{
		Profile: "home", Rule: "X", DraftPath: "/p/d.yaml",
		SnapshotPath: "/p/s.yaml", DiffHash: "abc",
		References: []svc.ReferenceSummary{{Type: "IPHost", Names: []string{"LAN"}}},
	}
	b, err := NATRulePullEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.natRulePull"`)
	require.Contains(t, string(b), `"diffHash": "abc"`)
}

func TestNATRuleDiffEnvelope_Schema(t *testing.T) {
	r := &svc.NATRuleDiffResult{
		Profile: "home", Rule: "X",
		HasChanges: true, UnifiedDiff: "...",
		StructuredDiff: []svc.DiffEntry{{Path: "Status", Op: "changed", OldValue: "Enable", NewValue: "Disable"}},
	}
	b, err := NATRuleDiffEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.natRuleDiff"`)
	require.Contains(t, string(b), `"hasChanges": true`)
	require.Contains(t, string(b), `"path": "Status"`)
}

func TestNATRulePushEnvelope_DryRun(t *testing.T) {
	r := &svc.NATRulePushResult{
		Profile: "home", Rule: "X", Operation: "update", DryRun: true,
		Preview: &svc.Preview{Mutating: true, Verbs: []string{"Set:update"}},
	}
	b, err := NATRulePushEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.natRulePush"`)
	require.Contains(t, string(b), `"applied": false`)
	require.Contains(t, string(b), `"dryRun": true`)
}

func TestNATRulePushEnvelope_Apply(t *testing.T) {
	r := &svc.NATRulePushResult{
		Profile: "home", Rule: "X", Operation: "update", DryRun: false,
		NewDiffHash: "def", Item: map[string]any{"Name": "X"},
	}
	b, err := NATRulePushEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"applied": true`)
	require.Contains(t, string(b), `"newDiffHash": "def"`)
	require.Contains(t, string(b), `"item":`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/render -run TestNATRule -v
```

- [ ] **Step 3: Implement the envelopes**

Append to `internal/render/envelope.go`:

```go
// NATRulePullEnvelope renders sophosfw.v1.natRulePull.
func NATRulePullEnvelope(r *svc.NATRulePullResult) ([]byte, error) {
	refs := make([]map[string]any, 0, len(r.References))
	for _, rs := range r.References {
		refs = append(refs, map[string]any{"type": rs.Type, "names": rs.Names})
	}
	payload := map[string]any{
		"profile":      r.Profile,
		"rule":         r.Rule,
		"draftPath":    r.DraftPath,
		"snapshotPath": r.SnapshotPath,
		"diffHash":     r.DiffHash,
		"references":   refs,
	}
	return marshalEnvelope("sophosfw.v1.natRulePull", payload)
}

// NATRuleDiffEnvelope renders sophosfw.v1.natRuleDiff.
func NATRuleDiffEnvelope(r *svc.NATRuleDiffResult) ([]byte, error) {
	entries := make([]map[string]any, 0, len(r.StructuredDiff))
	for _, e := range r.StructuredDiff {
		entries = append(entries, map[string]any{
			"path":     e.Path,
			"op":       e.Op,
			"oldValue": e.OldValue,
			"newValue": e.NewValue,
		})
	}
	payload := map[string]any{
		"profile":     r.Profile,
		"rule":        r.Rule,
		"hasChanges":  r.HasChanges,
		"unifiedDiff": r.UnifiedDiff,
		"diffEntries": entries,
	}
	return marshalEnvelope("sophosfw.v1.natRuleDiff", payload)
}

// NATRulePushEnvelope renders sophosfw.v1.natRulePush.
func NATRulePushEnvelope(r *svc.NATRulePushResult) ([]byte, error) {
	payload := map[string]any{
		"profile":   r.Profile,
		"rule":      r.Rule,
		"operation": r.Operation,
		"applied":   !r.DryRun,
		"dryRun":    r.DryRun,
	}
	if r.DryRun && r.Preview != nil {
		payload["preview"] = map[string]any{
			"mutating":       r.Preview.Mutating,
			"verbs":          r.Preview.Verbs,
			"redactedXml":    r.Preview.RedactedXML,
			"wouldSendBytes": r.Preview.WouldSendBytes,
		}
	}
	if !r.DryRun {
		payload["newDiffHash"] = r.NewDiffHash
		if r.Item != nil {
			payload["item"] = r.Item
		}
	}
	return marshalEnvelope("sophosfw.v1.natRulePush", payload)
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/render -run TestNATRule -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/render/envelope.go internal/render/envelope_test.go
git commit -m "feat(render): natRulePull/Diff/Push envelopes"
```

---

## Task 9: cli `nat rule pull/diff/push/delete` + migration wiring

**Files:**
- Create: `internal/cli/natrule_mutation.go`
- Create: `internal/cli/natrule_mutation_test.go`
- Modify: `internal/cli/natrule.go` (register new subcommands)
- Modify: `internal/cli/firewallrule.go` (call migration in factory)

- [ ] **Step 1: Write failing tests**

Create `/Users/ipm/code/sophosfw/internal/cli/natrule_mutation_test.go`:

```go
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeNATCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeNATCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "NATRule" {
		if f.body != nil {
			raw, _ := json.Marshal(f.body)
			resp.Body["NATRule"] = []json.RawMessage{raw}
		}
	}
	return resp, nil
}

func (f *fakeNATCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForNATTest(t *testing.T, body map[string]any) (*RootDeps, *fakeNATCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeNATCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestNATRule_Pull_WritesFiles_Json(t *testing.T) {
	body := map[string]any{
		"Name": "DNAT-X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, _ := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "DNAT-X", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRulePull"`)
	require.Contains(t, out.String(), `"rule": "DNAT-X"`)
}

func TestNATRule_Push_DryRunDefault(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, fc := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"nat", "rule", "push", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"dryRun": true`)
	require.Empty(t, fc.sent)
}

func TestNATRule_Push_YesApplies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, fc := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"nat", "rule", "push", "X", "--yes", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
	require.Contains(t, string(fc.sent[0]), `<NATRule>`)
}

func TestNATRule_Diff_Json(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, _ := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"nat", "rule", "diff", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRuleDiff"`)
	require.Contains(t, out.String(), `"hasChanges": false`)
}

func TestNATRule_Delete_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4",
	}
	d, _ := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "delete", "X", "--yes"})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expected-diff-hash") || strings.Contains(err.Error(), "expectedDiffHash"))
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/cli -run TestNATRule -v
```

- [ ] **Step 3: Implement `internal/cli/natrule_mutation.go`**

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

func natRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.NATRuleSvc {
	// Run migration once per cli invocation. Idempotent. We pass the
	// active profile name; on resolution failure (e.g., no profile
	// configured) the migration silently no-ops.
	if pname, _, err := d.Config.ActiveProfile(""); err == nil {
		_ = draft.MigrateLegacyLayout(d.BaseDir, pname)
	}
	return &svc.NATRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit:   d.Audit,
		BaseDir: d.BaseDir,
	}
}

func newNATRulePullCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "pull <name>",
		Short: "Pull a NAT rule into a local YAML draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleSvc(d, cat).Pull(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePullEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Draft written: %s\nSnapshot:      %s\nDiff hash:     %s\n",
				result.DraftPath, result.SnapshotPath, result.DiffHash)
			if len(result.References) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "References:")
				for _, rs := range result.References {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s: %v\n", rs.Type, rs.Names)
				}
			}
			return nil
		},
	}
	return c
}

func newNATRuleDiffCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "diff <name>",
		Short: "Show local diff between snapshot and draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleSvc(d, cat).Diff(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRuleDiffEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if !result.HasChanges {
				fmt.Fprintln(cmd.OutOrStdout(), "no changes")
				return nil
			}
			_, err = cmd.OutOrStdout().Write([]byte(result.UnifiedDiff))
			return err
		},
	}
	return c
}

func newNATRulePushCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	c := &cobra.Command{
		Use:   "push <name>",
		Short: "Validate the NAT rule draft and apply it to the firewall",
		Long:  "Defaults to --dry-run preview. Pass --yes to apply. Use --ignore-diff-hash to skip drift detection.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := natRuleSvc(d, cat).Push(cmd.Context(), profile, args[0], ignoreHash, !yes)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePushEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if result.DryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would push %s\nverbs: %v\n", result.Rule, result.Preview.Verbs)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "applied: %s (newDiffHash: %s)\n", result.Rule, result.NewDiffHash)
			return nil
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection (use with care)")
	return c
}

func newNATRuleDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	var expectedHash string
	c := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a NAT rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			result, err := natRuleSvc(d, cat).Delete(cmd.Context(), profile, args[0], expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.NATRulePushEnvelope(result)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			if result.DryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would delete %s\n", result.Rule)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted: %s\n", result.Rule)
			return nil
		},
	}
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hex hash from a prior `nat rule pull`")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection")
	c.Flags().BoolVar(&yes, "yes", false, "apply the deletion (default is --dry-run)")
	return c
}
```

- [ ] **Step 4: Register the new subcommands**

In `internal/cli/natrule.go`, find where `list` and `show` are registered for `nat rule`. Add:

```go
newNATRulePullCmd(d, cat),
newNATRuleDiffCmd(d, cat),
newNATRulePushCmd(d, cat),
newNATRuleDeleteCmd(d, cat),
```

- [ ] **Step 5: Add migration call to firewallRuleSvc factory for symmetry**

In `internal/cli/firewallrule_mutation.go`, find `firewallRuleSvc(d, cat)`. Add the same migration call at the top:

```go
func firewallRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.FirewallRuleSvc {
	if pname, _, err := d.Config.ActiveProfile(""); err == nil {
		_ = draft.MigrateLegacyLayout(d.BaseDir, pname)
	}
	return &svc.FirewallRuleSvc{
		// ... existing fields ...
	}
}
```

Add `"github.com/iainmoffat/sophosfw/internal/draft"` to that file's imports if not already present.

- [ ] **Step 6: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/cli -run "TestNATRule|TestFwRule" -v
go test ./... -count=1
```

- [ ] **Step 7: Build and verify help text**

```bash
cd /Users/ipm/code/sophosfw && make build && ./bin/sophosfw nat rule --help
```

Should show pull/diff/push/delete alongside the existing list/show.

- [ ] **Step 8: Commit**

```bash
git add internal/cli/natrule.go internal/cli/natrule_mutation.go internal/cli/natrule_mutation_test.go internal/cli/firewallrule_mutation.go
git commit -m "feat(cli): nat rule pull/diff/push/delete + migration wiring"
```

---

## Task 10: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

- [ ] **Step 1: Append integration tests**

Add to `internal/testutil/integration_test.go` (after the existing Phase 7 firewall rule tests):

```go
func newNATRuleSvcForIntegration(t *testing.T) (*svc.NATRuleSvc, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	tmpBase := t.TempDir()
	return &svc.NATRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit:   svc.NewAuditLog(t.TempDir(), true),
		BaseDir: tmpBase,
	}, tmpBase
}

func TestIntegration_NATRulePull_RoundTrips(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_NAT_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_NAT_RULE to a real NAT rule on the testvm")
	}

	svcInst, _ := newNATRuleSvcForIntegration(t)
	out, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)
}

func TestIntegration_NATRulePush_DryRun(t *testing.T) {
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_NAT_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_NAT_RULE")
	}

	svcInst, _ := newNATRuleSvcForIntegration(t)
	_, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)

	out, err := svcInst.Push(context.Background(), profileName, ruleName, false, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
}

func TestIntegration_NATRuleMigration(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "x.yaml")
	require.NoError(t, os.WriteFile(legacy, []byte("# rule: X\n"), 0o600))

	require.NoError(t, draft.MigrateLegacyLayout(tmp, "home"))

	migrated := filepath.Join(dir, "firewall", "x.yaml")
	_, err := os.Stat(migrated)
	require.NoError(t, err)
}
```

Add `"path/filepath"` and `"github.com/iainmoffat/sophosfw/internal/draft"` to imports if not already present.

- [ ] **Step 2: Pick a real NAT rule for SOPHOSFW_TEST_NAT_RULE**

```bash
SOPHOSFW_PROFILE=testvm ./bin/sophosfw nat rule list --json | head -20
```

Pick a rule by name. Example from the testvm: `DNAT to docker01_1721427866174` (or any other DNAT rule).

- [ ] **Step 3: Run integration tests**

```bash
cd /Users/ipm/code/sophosfw && SOPHOSFW_PROFILE=testvm SOPHOSFW_TEST_NAT_RULE='DNAT to docker01_1721427866174' go test -tags=integration ./internal/testutil -run TestIntegration_NATRule -v
```

If the chosen rule name has spaces, quote it correctly.

- [ ] **Step 4: Manual smoke**

```bash
make build
./bin/sophosfw nat rule pull '<real-nat-rule>' --profile testvm
ls ~/.config/sophosfw/profiles/testvm/drafts/nat/
ls ~/.config/sophosfw/profiles/testvm/snapshots/nat/
./bin/sophosfw nat rule diff '<real-nat-rule>' --profile testvm
./bin/sophosfw nat rule push '<real-nat-rule>' --profile testvm --json   # dry-run
tail -5 ~/.config/sophosfw/audit.log
# Verify migration: pre-existing FirewallRule files now under drafts/firewall/
ls ~/.config/sophosfw/profiles/testvm/drafts/firewall/ 2>/dev/null
```

Confirm:
- Files at 0600/0700 in the new `nat/` and `firewall/` subdirs.
- `nat rule diff` shows "no changes" right after pull.
- `nat rule push --json` (dry-run) emits the preview envelope.
- Audit log has `nat_rule_pull` entries.
- Pre-existing FirewallRule drafts (from Phase 7) have been migrated into `drafts/firewall/`.

- [ ] **Step 5: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "test: phase 8 NAT rule integration tests + migration smoke"
```

---

## Task 11: Docs + acceptance + tag v0.7.0-phase8

**Files:**
- Modify: `docs/api-coverage.md`
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update docs/api-coverage.md NATRule row**

Find:
```
| Firewall | NATRule | object list/get NATRule; nat rule list/show | nat_rule_list/show; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |
```

Replace with:
```
| Firewall | NATRule | object list/get NATRule; nat rule list/show/pull/diff/push/delete | nat_rule_list/show; object_list/get/search/usage | yes | Phase 9 | yes (sophosfw nat rule push) | yes (sophosfw nat rule delete) | n/a | Phase 8 |
```

- [ ] **Step 2: Update docs/roadmap.md**

Find:
```markdown
- Phase 7 — FirewallRule draft workflow (complete; v0.6.0-phase7)
- Phase 8 — MCP tools for firewall rules + rule create workflow + extension to NATRule
```

Replace with:
```markdown
- Phase 7 — FirewallRule draft workflow (complete; v0.6.0-phase7)
- Phase 8 — NATRule draft workflow (complete; v0.7.0-phase8)
- Phase 9 — `firewall rule new` and `nat rule new` create workflows
- Phase 10 — MCP-native firewall and NAT rule mutating tools
```

- [ ] **Step 3: Run final test pass**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```
Expected: PASS, no fmt drift.

- [ ] **Step 4: Commit any fmt-induced changes**

```bash
git status
# If clean, skip to step 5.
git add -A
git commit -m "fix: phase 8 acceptance pass formatting"
```

- [ ] **Step 5: Commit docs**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "docs: phase 8 complete in roadmap and api-coverage"
```

- [ ] **Step 6: Tag**

```bash
git tag -a v0.7.0-phase8 -m "Phase 8 complete (NATRule pull/diff/push/delete + per-tag layout migration)"
git tag --list | grep -E "(foundation|phase[3-8])"
```

Expected output:
```
v0.1.0-foundation
v0.2.0-phase3
v0.3.0-phase4
v0.4.0-phase5
v0.5.0-phase6
v0.6.0-phase7
v0.7.0-phase8
```

- [ ] **Step 7: Push to origin**

```bash
git push origin main
git push origin v0.7.0-phase8
```

- [ ] **Step 8: Final sanity**

```bash
git log --oneline -15
```

Expected: 11 task commits + tag.

---

## End of plan

Phase 9 (provisional): `firewall rule new` and `nat rule new` create workflows with template selection. Phase 10 (provisional): MCP-native rule tools.

## Self-review checklist

- ✅ **Spec coverage:** Section 4 (CLI surface) → T9; Section 5 (layout + migration) → T2 + T3; Section 6 (draft format) → unchanged from Phase 7; Section 7 (components) → T4-T9; Section 8 (data flow) → T4-T7; Section 9 (errors) → no new sentinels; Section 10 (audit log) → T4+T6+T7; Section 11 (testing) → T4-T10; Section 12 (acceptance) → T11.
- ✅ **No placeholders.** Every step has actual code or commands.
- ✅ **Type consistency.** `NATRulePullResult`, `NATRuleDiffResult`, `NATRulePushResult`, `NATRuleSvc` defined in T4 and used unchanged in T5-T9. `MigrateLegacyLayout` defined in T3 and called from T9. `marshalNATRule`, `extractNATReferences`, `parseAndValidateNATRuleBody`, `requiredNATRuleFields` all defined in T4-T6.
- ✅ **Tag parameter consistency.** All `draft.DraftPath`/`SnapshotPath`/`ListSnapshots`/`RotateSnapshots` calls use the literal `"firewall"` or `"nat"` string at the cli/svc boundary.
- ✅ **No Co-Authored-By trailer.** Every commit step inherits the project convention.
- ✅ **Single passing commit per task.** Each task's tests pass at commit time.
- ✅ **Acceptance.** T11 covers fmt/vet/race, docs, tag, push.
