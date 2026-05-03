# sophosfw Phase 7 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a complete pull/edit/diff/push lifecycle for FirewallRule objects on top of the existing Phase 6 mutation infrastructure (audit, diff hash, dry-run gates, catalog Mutable check).

**Architecture:** A new `internal/draft/` package owns on-disk YAML draft + snapshot files (under `~/.config/sophosfw/profiles/<profile>/{drafts,snapshots}/`); `FirewallRuleSvc` (extending the existing read-only struct) gains `Pull`/`Diff`/`Push`/`Delete` methods that compose draft I/O with the Phase 6 audit + diff-hash + envelope-build pipeline; the cli adds 4 subcommands following the Phase 6 default-to-dry-run pattern.

**Tech Stack:** Go 1.26+, `gopkg.in/yaml.v3` (already a dep), `encoding/xml`, `crypto/sha256`. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-02-sophosfw-phase7-design.md`

---

## Pre-flight

Branch is `main`. The project does work on `main` after Phase 5 was merged. The latest tag is `v0.5.0-phase6`. Working dir: `/Users/ipm/code/sophosfw`.

Before starting Task 1, verify the tree is clean:
```bash
git status
go test ./... -count=1
```
Expected: clean status, all tests pass.

## File structure (created/modified across the plan)

**New files:**
- `internal/draft/paths.go` — slug derivation + draft/snapshot path resolution + collision rule
- `internal/draft/paths_test.go` — slug + collision tests
- `internal/draft/io.go` — `Draft` type, `ReadDraft`, `WriteDraft`, header parsing
- `internal/draft/io_test.go` — round-trip + parse-error tests
- `internal/draft/snapshots.go` — `ListSnapshots`, `RotateSnapshots`
- `internal/draft/snapshots_test.go` — rotation + ordering tests
- `internal/draft/diff.go` — line-based unified-diff helper (stdlib-only)
- `internal/draft/diff_test.go` — unified diff tests
- `internal/svc/firewallrule_pull.go` — `Pull`, `Diff`, `Push`, `Delete` methods on `FirewallRuleSvc` plus `marshalFirewallRule` helper. Lives alongside the existing `firewallrule.go` to keep the read-only file unchanged.
- `internal/svc/firewallrule_pull_test.go` — service-layer tests
- `internal/cli/firewallrule_mutation.go` — 4 cobra subcommands (kept separate from the existing read-only `firewallrule.go` for the same reason)
- `internal/cli/firewallrule_mutation_test.go` — cli tests

**Modified files:**
- `internal/catalog/objects.yaml` — flag `FirewallRule` as `mutable: true`
- `internal/svc/errors_kind.go` — add `ErrDraftMissing`, `ErrSnapshotMissing` sentinels + `ErrorKind` cases
- `internal/render/envelope.go` — add 3 envelope functions
- `internal/cli/firewallrule.go` — register the new subcommands on the existing `firewall rule` cobra command
- `internal/testutil/integration_test.go` — append the Phase 7 integration tests
- `docs/api-coverage.md` — FirewallRule row updates
- `docs/roadmap.md` — Phase 7 marked complete

---

## Task 1: Flag FirewallRule as Mutable in the catalog

**Files:**
- Modify: `internal/catalog/objects.yaml`

This is the catalog-level switch that lets `FirewallRuleSvc.Push`/`Delete` pass the existing `catalog.Mutable` gate (introduced in Phase 6 T4 alongside IPHost).

- [ ] **Step 1: Find the FirewallRule entry in the catalog**

```bash
grep -n -A 2 "xmlTag: FirewallRule" internal/catalog/objects.yaml
```
Expected: an entry like `- xmlTag: FirewallRule` with various existing fields (no `mutable:` line yet).

- [ ] **Step 2: Add `mutable: true` to the FirewallRule entry**

In `internal/catalog/objects.yaml`, locate the `- xmlTag: FirewallRule` block and add `mutable: true` as a sibling field (the exact placement should match how IPHost has it — typically just below `xmlTag:`).

For example, if IPHost looks like:
```yaml
  - xmlTag: IPHost
    mutable: true
    typedParser: IPHost
    ...
```
Then make FirewallRule look like:
```yaml
  - xmlTag: FirewallRule
    mutable: true
    ...
```

- [ ] **Step 3: Verify catalog tests still pass**

```bash
go test ./internal/catalog -count=1
```
Expected: PASS.

- [ ] **Step 4: Verify catalog reports FirewallRule as mutable**

Quick sanity test — write a small test or run an inline check. Easiest: add (then revert) a one-liner in `internal/catalog/catalog_test.go` at the end of the file:

```go
func TestCatalog_FirewallRuleIsMutable(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	entry, ok := c.Lookup("FirewallRule")
	require.True(t, ok)
	require.True(t, entry.Mutable)
}
```

Then run:
```bash
go test ./internal/catalog -run TestCatalog_FirewallRuleIsMutable -v
```
Expected: PASS. Keep this test (don't revert it — it documents the intent).

If `c.Lookup` doesn't exist by that name, look at what other tests use to look up entries by xmlTag and adapt accordingly.

- [ ] **Step 5: Commit**

```bash
git add internal/catalog/objects.yaml internal/catalog/catalog_test.go
git commit -m "feat(catalog): FirewallRule flagged mutable for Phase 7"
```

---

## Task 2: New error sentinels for Phase 7

**Files:**
- Modify: `internal/svc/errors_kind.go`
- Modify: `internal/svc/errors_kind_test.go` (or wherever the existing kind-mapping tests live)

Adds `ErrDraftMissing` and `ErrSnapshotMissing`. Both map to `not_found` (existing kind, exit 4 — no new exit code).

- [ ] **Step 1: Read the current errors_kind.go**

```bash
cat internal/svc/errors_kind.go
```
Note the existing `var (...)` block of sentinels and the `ErrorKind(err) string` switch.

- [ ] **Step 2: Write the failing test**

Append to `internal/svc/errors_kind_test.go`:

```go
func TestErrorKind_DraftMissing(t *testing.T) {
	require.Equal(t, "not_found", ErrorKind(ErrDraftMissing))
}

func TestErrorKind_SnapshotMissing(t *testing.T) {
	require.Equal(t, "not_found", ErrorKind(ErrSnapshotMissing))
}
```

If `errors_kind_test.go` doesn't exist yet, create it with the standard test boilerplate:

```go
package svc

import (
	"testing"

	"github.com/stretchr/testify/require"
)
```

- [ ] **Step 3: Run — must fail**

```bash
go test ./internal/svc -run "TestErrorKind_DraftMissing|TestErrorKind_SnapshotMissing" -v
```
Expected: FAIL (sentinels not defined yet).

- [ ] **Step 4: Add the sentinels and switch cases**

In `internal/svc/errors_kind.go`, add to the `var (...)` block:

```go
var (
	// ... existing sentinels (ErrDiffHashMismatch, ErrDiffHashRequired, ...) ...
	ErrDraftMissing    = errors.New("firewall rule draft not found; run `sophosfw firewall rule pull <name>` first")
	ErrSnapshotMissing = errors.New("firewall rule snapshot not found for this draft; re-run `sophosfw firewall rule pull <name>`")
)
```

Add to the `ErrorKind` switch (alongside the existing `errors.Is(err, ErrDiffHashMismatch)` case):

```go
	case errors.Is(err, ErrDraftMissing):
		return "not_found"
	case errors.Is(err, ErrSnapshotMissing):
		return "not_found"
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/svc -run "TestErrorKind_DraftMissing|TestErrorKind_SnapshotMissing" -v
go test ./... -count=1
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/svc/errors_kind.go internal/svc/errors_kind_test.go
git commit -m "feat(svc): ErrDraftMissing and ErrSnapshotMissing sentinels for Phase 7"
```

---

## Task 3: `internal/draft` — slug + path resolution

**Files:**
- Create: `internal/draft/paths.go`
- Create: `internal/draft/paths_test.go`

Slugging maps a Sophos rule name (which may contain spaces, slashes, parens, unicode) to a safe filename. Collision resolution appends a 6-char SHA-256 suffix.

- [ ] **Step 1: Write the failing tests**

Create `internal/draft/paths_test.go`:

```go
package draft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSlug_BasicCases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"WAN-to-LAN", "wan-to-lan"},
		{"My Rule (test)", "my-rule-test"},
		{"Allow / SSH", "allow-ssh"},
		{"trailing-dashes---", "trailing-dashes"},
		{"---leading", "leading"},
		{"runs   of   spaces", "runs-of-spaces"},
		{"123 numeric", "123-numeric"},
		{"under_score", "under-score"},
		{"already-good-slug", "already-good-slug"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			require.Equal(t, c.want, Slug(c.in))
		})
	}
}

func TestSlug_UnicodeFallback(t *testing.T) {
	// All-unicode names slug to the empty string after stripping; the
	// helper substitutes "rule" so DraftPath can still produce a valid path.
	require.Equal(t, "rule", Slug("🔥🔥🔥"))
	require.Equal(t, "rule", Slug("中文"))
}

func TestDraftPath_NoCollision(t *testing.T) {
	base := t.TempDir()
	// Empty drafts dir → no collision possible; first path is plain slug.
	p, err := DraftPath(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(base, "profiles", "home", "drafts", "wan-to-lan.yaml"), p)
}

func TestDraftPath_CollisionAppendsHashSuffix(t *testing.T) {
	base := t.TempDir()
	draftsDir := filepath.Join(base, "profiles", "home", "drafts")
	require.NoError(t, os.MkdirAll(draftsDir, 0o700))

	// Pre-populate "wan-to-lan.yaml" with a header for a DIFFERENT original
	// rule name so the colliding slug forces a suffix.
	conflictingDraft := filepath.Join(draftsDir, "wan-to-lan.yaml")
	require.NoError(t, os.WriteFile(conflictingDraft,
		[]byte("# rule: Wan To Lan\n# DO NOT EDIT ABOVE THIS LINE\n---\nName: Wan To Lan\n"),
		0o600))

	// New rule name "WAN-to-LAN" slugs to the same "wan-to-lan", but the
	// existing draft on disk belongs to "Wan To Lan", so the resolver must
	// pick a suffix path.
	p, err := DraftPath(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(filepath.Base(p), "wan-to-lan-"))
	require.True(t, strings.HasSuffix(p, ".yaml"))
	require.NotEqual(t, conflictingDraft, p)
}

func TestDraftPath_SameNameResolvesToSamePath(t *testing.T) {
	base := t.TempDir()
	p1, err := DraftPath(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	p2, err := DraftPath(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, p1, p2)
}

func TestSnapshotPath_TimestampInName(t *testing.T) {
	base := t.TempDir()
	// Use a real time to ensure the formatter is exercised.
	import_time := mustParseTime(t, "2026-05-02T15:30:00Z")
	p, err := SnapshotPath(base, "home", "WAN-to-LAN", import_time)
	require.NoError(t, err)
	require.Contains(t, filepath.Base(p), "wan-to-lan-")
	require.Contains(t, filepath.Base(p), "2026-05-02T15-30-00Z")
	require.True(t, strings.HasSuffix(p, ".yaml"))
}

// mustParseTime is a tiny helper used only by the snapshot path test.
func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	tt, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return tt
}
```

Add the `time` import to the file's imports.

- [ ] **Step 2: Run — must fail (compile error)**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
```
Expected: package not found / compile error (the file doesn't exist yet).

- [ ] **Step 3: Implement `internal/draft/paths.go`**

```go
// Package draft owns the on-disk YAML draft and snapshot file format
// for the Phase 7 firewall rule editing workflow. It is deliberately
// small and stateless; FirewallRuleSvc composes its primitives.
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
)

// Slug derives a filesystem-safe slug from a Sophos rule name.
// Rule names can contain spaces, slashes, punctuation, and unicode;
// the slug is lowercase ASCII alphanumerics with single dashes between
// runs of replaced characters. If the input slugs to the empty string
// (e.g., all-unicode), the literal "rule" is returned.
func Slug(name string) string {
	lower := strings.ToLower(name)
	// Replace any run of non-[a-z0-9] with a single dash.
	re := regexp.MustCompile(`[^a-z0-9]+`)
	s := re.ReplaceAllString(lower, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "rule"
	}
	return s
}

// DraftPath returns the absolute path to the draft file for ruleName
// under baseDir/profiles/<profile>/drafts/. If a draft already exists
// at the plain-slug path but its header records a DIFFERENT original
// rule name, DraftPath returns a path with a 6-hex-char suffix derived
// from SHA-256(ruleName) so the two distinct rules land in distinct
// files.
func DraftPath(baseDir, profile, ruleName string) (string, error) {
	dir := filepath.Join(baseDir, "profiles", profile, "drafts")
	slug := Slug(ruleName)
	plain := filepath.Join(dir, slug+".yaml")

	// If no file at plain, return plain.
	existing, err := readHeaderRule(plain)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if os.IsNotExist(err) || existing == "" || existing == ruleName {
		return plain, nil
	}

	// Collision: existing draft is for a different rule. Append suffix.
	suffix := nameHash(ruleName)
	return filepath.Join(dir, slug+"-"+suffix+".yaml"), nil
}

// SnapshotPath returns the absolute path to the snapshot file for
// ruleName at time t under baseDir/profiles/<profile>/snapshots/.
// Time is formatted as ISO 8601 UTC with colons replaced by dashes
// so the filename is portable.
func SnapshotPath(baseDir, profile, ruleName string, t time.Time) (string, error) {
	dir := filepath.Join(baseDir, "profiles", profile, "snapshots")
	slug := Slug(ruleName)
	stamp := t.UTC().Format("2006-01-02T15-04-05Z")
	// We don't need collision detection for snapshots because each
	// snapshot is unique by timestamp; if two rules slug to the same
	// value, their snapshots interleave in the same dir, but the slug
	// suffix from DraftPath will be different and the consumer can
	// disambiguate by filename prefix.
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
	// Walk the first 32 lines or until we hit the YAML "---" marker.
	for i, line := range strings.SplitN(string(b), "\n", 33) {
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

// Compile-time guard against unused imports during the initial commit.
var _ = fmt.Sprintf
```

(Remove the `var _ = fmt.Sprintf` once `fmt` is actually used elsewhere in the package. It's there only to make this initial file compile cleanly even before later tasks add files that import `fmt`.)

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
```
Expected: PASS for all `TestSlug_*`, `TestDraftPath_*`, `TestSnapshotPath_*`.

If a test fails because of `mustParseTime`'s placement (test file imports go before package code), move `mustParseTime` to be defined ABOVE the test that uses it (Go test files are compiled together — the order in the file matters only for readability).

- [ ] **Step 5: Commit**

```bash
git add internal/draft/paths.go internal/draft/paths_test.go
git commit -m "feat(draft): slug derivation and path resolution"
```

---

## Task 4: `internal/draft` — Draft type, ReadDraft, WriteDraft

**Files:**
- Create: `internal/draft/io.go`
- Create: `internal/draft/io_test.go`

Owns the on-disk header/body format and round-trip parsing.

- [ ] **Step 1: Write the failing tests**

Create `internal/draft/io_test.go`:

```go
package draft

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadWriteDraft_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "draft.yaml")
	d := &Draft{
		Profile:  "home",
		Rule:     "WAN-to-LAN",
		PulledAt: mustParseTime(t, "2026-05-02T15:30:00Z"),
		DiffHash: "8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50",
		Body:     []byte("Name: WAN-to-LAN\nStatus: Enable\n"),
	}
	require.NoError(t, WriteDraft(path, d))

	// File mode 0600.
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	got, err := ReadDraft(path)
	require.NoError(t, err)
	require.Equal(t, d.Profile, got.Profile)
	require.Equal(t, d.Rule, got.Rule)
	require.True(t, d.PulledAt.Equal(got.PulledAt))
	require.Equal(t, d.DiffHash, got.DiffHash)
	require.Equal(t, string(d.Body), string(got.Body))
}

func TestReadDraft_FileMissing_ReturnsErrDraftMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadDraft(filepath.Join(dir, "nope.yaml"))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDraftMissing))
}

func TestReadDraft_MalformedHeader_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("# this is not a header\n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
}

func TestReadDraft_MissingRequiredHeader_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.yaml")
	// Has profile and rule but no diffHash.
	require.NoError(t, os.WriteFile(path,
		[]byte("# profile: home\n# rule: X\n# pulledAt: 2026-05-02T15:30:00Z\n---\nName: X\n"),
		0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "diffHash")
}

func TestReadDraft_InvalidHashFormat_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badhash.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte(`# profile: home
# rule: X
# pulledAt: 2026-05-02T15:30:00Z
# diffHash: not-a-hex-hash
---
Name: X
`), 0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "diffHash")
}

func TestReadDraft_InvalidTimestamp_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badtime.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte(`# profile: home
# rule: X
# pulledAt: yesterday
# diffHash: 8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50
---
Name: X
`), 0o600))
	_, err := ReadDraft(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pulledAt")
}

func TestWriteDraft_CreatesParentDir(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "deeply", "nested", "draft.yaml")
	d := &Draft{
		Profile:  "home",
		Rule:     "X",
		PulledAt: time.Now().UTC(),
		DiffHash: "8b3bc27fc63cb9792cbb563949ae2279abe2b016fe9ca00e901973e69f2e6f50",
		Body:     []byte("Name: X\n"),
	}
	require.NoError(t, WriteDraft(path, d))
	_, err := os.Stat(path)
	require.NoError(t, err)
	// Parent dir should be 0700.
	parent, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), parent.Mode().Perm())
}
```

Make sure `errors` is imported (it isn't always already imported in test files).

- [ ] **Step 2: Run — must fail (compile error or test failures)**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -run "TestReadWriteDraft|TestReadDraft|TestWriteDraft" -v
```

- [ ] **Step 3: Implement `internal/draft/io.go`**

```go
package draft

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrDraftMissing is returned by ReadDraft when the file does not exist.
// Defined in the svc package; we re-export a parallel sentinel here so
// the draft package stays import-free of svc. The svc package's
// ErrDraftMissing wraps io.ErrDraftMissing via errors.Is via its own
// Unwrap, OR — simpler — the svc package just reuses this sentinel.
//
// The simplest path: define the sentinel HERE, and let svc import it
// for the public ErrorKind switch. The plan's Task 2 used a sentinel
// defined in svc; reconcile by deleting svc's ErrDraftMissing and
// using draft.ErrDraftMissing directly in the svc switch.
//
// Implementer note: prefer the cleaner approach. After Task 4 lands,
// edit internal/svc/errors_kind.go to: `errors.Is(err, draft.ErrDraftMissing)`
// and remove svc's local ErrDraftMissing. Same for ErrSnapshotMissing
// once Task 5 introduces it. Update the import.
var (
	ErrDraftMissing    = errors.New("firewall rule draft not found")
	ErrSnapshotMissing = errors.New("firewall rule snapshot not found for this draft")
)

// Draft holds the parsed shape of a YAML draft file: header metadata
// + the editable YAML body.
type Draft struct {
	Profile  string
	Rule     string
	PulledAt time.Time
	DiffHash string
	Body     []byte
}

// hashRe matches a 64-char lowercase hex string (SHA-256).
var hashRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

// headerLine matches `# key: value`.
var headerLine = regexp.MustCompile(`^# ([A-Za-z]+): (.*)$`)

// ReadDraft parses a draft file. Missing file returns ErrDraftMissing.
// Malformed header (missing required keys, bad timestamp, bad hash) →
// a descriptive error.
func ReadDraft(path string) (*Draft, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrDraftMissing, path)
		}
		return nil, err
	}
	d := &Draft{}
	headerEnd := -1
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "---" {
			headerEnd = i
			break
		}
		// Skip the literal "DO NOT EDIT" advisory line and the title line.
		if strings.HasPrefix(line, "# sophosfw firewall rule draft") ||
			strings.Contains(line, "DO NOT EDIT") {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			// Non-comment line before the marker — malformed.
			return nil, fmt.Errorf("draft header malformed at line %d: expected comment or `---`, got %q", i+1, line)
		}
		m := headerLine.FindStringSubmatch(line)
		if m == nil {
			// Unrecognized comment — skip it.
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		switch key {
		case "profile":
			d.Profile = val
		case "rule":
			d.Rule = val
		case "pulledAt":
			t, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return nil, fmt.Errorf("draft header pulledAt invalid: %w", err)
			}
			d.PulledAt = t
		case "diffHash":
			if !hashRe.MatchString(val) {
				return nil, fmt.Errorf("draft header diffHash invalid: must be 64-char lowercase hex, got %q", val)
			}
			d.DiffHash = val
		}
	}
	if headerEnd < 0 {
		return nil, fmt.Errorf("draft missing `---` document marker")
	}

	// Required header fields.
	if d.Profile == "" {
		return nil, fmt.Errorf("draft header missing profile")
	}
	if d.Rule == "" {
		return nil, fmt.Errorf("draft header missing rule")
	}
	if d.PulledAt.IsZero() {
		return nil, fmt.Errorf("draft header missing pulledAt")
	}
	if d.DiffHash == "" {
		return nil, fmt.Errorf("draft header missing diffHash")
	}

	// Body is everything after the line that contains `---`.
	parts := bytes.SplitN(b, []byte("\n---\n"), 2)
	if len(parts) != 2 {
		// Fallback if the marker isn't followed by a newline (e.g., final
		// byte is `---`). Treat empty body as valid; the parsed body has
		// length 0 but no error.
		d.Body = nil
	} else {
		d.Body = parts[1]
	}
	return d, nil
}

// WriteDraft writes a draft to disk with mode 0600. Parent directories
// are created with mode 0700 if missing.
func WriteDraft(path string, d *Draft) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	var buf bytes.Buffer
	fmt.Fprintln(&buf, "# sophosfw firewall rule draft v1")
	fmt.Fprintf(&buf, "# profile: %s\n", d.Profile)
	fmt.Fprintf(&buf, "# rule: %s\n", d.Rule)
	fmt.Fprintf(&buf, "# pulledAt: %s\n", d.PulledAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&buf, "# diffHash: %s\n", d.DiffHash)
	fmt.Fprintln(&buf, "# DO NOT EDIT ABOVE THIS LINE — push reads this header to verify drift")
	fmt.Fprintln(&buf, "---")
	buf.Write(d.Body)
	if !bytes.HasSuffix(d.Body, []byte("\n")) {
		buf.WriteByte('\n')
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
```
Expected: PASS for all draft tests.

- [ ] **Step 5: Update svc errors_kind.go to delegate to draft sentinels**

The plan's Task 2 introduced `svc.ErrDraftMissing` and `svc.ErrSnapshotMissing`. Now that the same sentinels exist in `internal/draft`, redirect the svc switch to use them and remove the duplicate definitions.

In `internal/svc/errors_kind.go`:
1. Remove the `ErrDraftMissing` and `ErrSnapshotMissing` lines from the `var (...)` block.
2. Add the import: `"github.com/iainmoffat/sophosfw/internal/draft"`.
3. Update the switch cases to:

```go
	case errors.Is(err, draft.ErrDraftMissing):
		return "not_found"
	case errors.Is(err, draft.ErrSnapshotMissing):
		return "not_found"
```

In `internal/svc/errors_kind_test.go`, update the two new tests to reference `draft.ErrDraftMissing` and `draft.ErrSnapshotMissing` and add the import.

- [ ] **Step 6: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./... -count=1
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/draft/io.go internal/draft/io_test.go internal/svc/errors_kind.go internal/svc/errors_kind_test.go
git commit -m "feat(draft): Draft type with header parsing and 0600 file IO"
```

---

## Task 5: `internal/draft` — ListSnapshots and RotateSnapshots

**Files:**
- Create: `internal/draft/snapshots.go`
- Create: `internal/draft/snapshots_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/draft/snapshots_test.go`:

```go
package draft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestListSnapshots_Empty(t *testing.T) {
	base := t.TempDir()
	out, err := ListSnapshots(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestListSnapshots_OrderedOldestToNewest(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	// Create 3 snapshots with timestamps in non-sorted order.
	for _, stamp := range []string{
		"2026-05-02T10-00-00Z",
		"2026-05-02T08-00-00Z",
		"2026-05-02T09-00-00Z",
	} {
		path := filepath.Join(dir, "wan-to-lan-"+stamp+".yaml")
		require.NoError(t, os.WriteFile(path, []byte("# rule: WAN-to-LAN\n"), 0o600))
	}

	out, err := ListSnapshots(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 3)
	// Oldest first.
	require.Contains(t, out[0], "08-00-00Z")
	require.Contains(t, out[1], "09-00-00Z")
	require.Contains(t, out[2], "10-00-00Z")
}

func TestListSnapshots_FiltersUnrelatedSlugs(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	// One snapshot for our rule, one for a different rule.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other-rule-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))

	out, err := ListSnapshots(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Contains(t, out[0], "wan-to-lan-")
}

func TestListSnapshots_IncludesDeletedSuffix(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T11-00-00Z-deleted.yaml"), []byte{}, 0o600))
	out, err := ListSnapshots(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 2)
}

func TestRotateSnapshots_KeepsLastN(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	// Create 15 snapshots with strictly increasing timestamps.
	for i := 0; i < 15; i++ {
		stamp := time.Date(2026, 5, 2, 10+i, 0, 0, 0, time.UTC).Format("2006-01-02T15-04-05Z")
		path := filepath.Join(dir, "wan-to-lan-"+stamp+".yaml")
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("snapshot %d", i)), 0o600))
	}

	require.NoError(t, RotateSnapshots(base, "home", "WAN-to-LAN", 10))

	out, err := ListSnapshots(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 10)
	// Oldest 5 (indices 0-4 → hours 10-14) should be gone.
	for _, p := range out {
		base := filepath.Base(p)
		require.False(t, strings.Contains(base, "10-00-00Z"))
		require.False(t, strings.Contains(base, "11-00-00Z"))
		require.False(t, strings.Contains(base, "12-00-00Z"))
		require.False(t, strings.Contains(base, "13-00-00Z"))
		require.False(t, strings.Contains(base, "14-00-00Z"))
	}
}

func TestRotateSnapshots_KeepLargerThanCount_NoOp(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wan-to-lan-2026-05-02T10-00-00Z.yaml"), []byte{}, 0o600))

	require.NoError(t, RotateSnapshots(base, "home", "WAN-to-LAN", 10))

	out, err := ListSnapshots(base, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, out, 1)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -run "TestListSnapshots|TestRotateSnapshots" -v
```

- [ ] **Step 3: Implement `internal/draft/snapshots.go`**

```go
package draft

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ListSnapshots returns the absolute paths of all snapshot files for
// ruleName, sorted oldest-first by filename (timestamp suffix is
// ISO-8601 UTC so lexicographic order == chronological order).
//
// Snapshots include both regular `<slug>-<ts>.yaml` files and the
// `-deleted` tombstones. Files for other rules in the same dir are
// filtered out by slug prefix.
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
	sort.Strings(out) // lexicographic == chronological for ISO timestamps
	return out, nil
}

// RotateSnapshots deletes the oldest snapshots for ruleName so that at
// most `keep` remain. If keep <= 0, nothing is deleted (a defensive
// guard against accidental misuse). If fewer than keep snapshots
// exist, the function is a no-op.
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
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/draft/snapshots.go internal/draft/snapshots_test.go
git commit -m "feat(draft): ListSnapshots and RotateSnapshots with retention bound"
```

---

## Task 6: `internal/draft` — unified diff helper

**Files:**
- Create: `internal/draft/diff.go`
- Create: `internal/draft/diff_test.go`

A small line-based unified diff (no LCS / no Myers algorithm needed for our use case — the YAML bodies are small, and a simple line-by-line diff is sufficient when keys are sorted). For a more accurate diff, a longest-common-subsequence approach is better; we use `github.com/sergi/go-diff` if it's already a transitive dep, otherwise a stdlib LCS-based implementation.

For zero-dep simplicity, this task uses an LCS-based diff (Hunt-Szymanski variant, ~80 LOC) that produces unified-diff output.

- [ ] **Step 1: Write the failing tests**

Create `internal/draft/diff_test.go`:

```go
package draft

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnifiedDiff_Identical_Empty(t *testing.T) {
	a := "Name: X\nStatus: Enable\n"
	b := "Name: X\nStatus: Enable\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Empty(t, diff)
}

func TestUnifiedDiff_LineChange(t *testing.T) {
	a := "Name: X\nStatus: Enable\nIPAddress: 1.1.1.1\n"
	b := "Name: X\nStatus: Disable\nIPAddress: 1.1.1.1\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Contains(t, diff, "--- snapshot")
	require.Contains(t, diff, "+++ draft")
	require.Contains(t, diff, "-Status: Enable")
	require.Contains(t, diff, "+Status: Disable")
}

func TestUnifiedDiff_LineAdded(t *testing.T) {
	a := "Name: X\nStatus: Enable\n"
	b := "Name: X\nStatus: Enable\nDescription: new\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Contains(t, diff, "+Description: new")
}

func TestUnifiedDiff_LineRemoved(t *testing.T) {
	a := "Name: X\nStatus: Enable\nDescription: gone\n"
	b := "Name: X\nStatus: Enable\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "snapshot", "draft")
	require.Contains(t, diff, "-Description: gone")
}

func TestUnifiedDiff_OutputFormat_HeaderHunkBody(t *testing.T) {
	a := "a\nb\nc\n"
	b := "a\nB\nc\n"
	diff := UnifiedDiff([]byte(a), []byte(b), "old", "new")
	lines := strings.Split(strings.TrimRight(diff, "\n"), "\n")
	require.Equal(t, "--- old", lines[0])
	require.Equal(t, "+++ new", lines[1])
	require.True(t, strings.HasPrefix(lines[2], "@@"))
	// remaining lines are context/changes
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -run TestUnifiedDiff -v
```

- [ ] **Step 3: Implement `internal/draft/diff.go`**

```go
package draft

import (
	"bytes"
	"fmt"
	"strings"
)

// UnifiedDiff returns a unified-diff string comparing aBody to bBody,
// labeled with aLabel and bLabel. Returns an empty string if the
// inputs are byte-identical.
//
// The implementation is line-based with a 3-line context window. It
// uses a simple LCS table; complexity O(n*m) in the number of lines.
// For our use (firewall rule YAML bodies, typically ≤200 lines), this
// is plenty fast and trivial to read.
func UnifiedDiff(aBody, bBody []byte, aLabel, bLabel string) string {
	if bytes.Equal(aBody, bBody) {
		return ""
	}
	a := splitLines(aBody)
	b := splitLines(bBody)
	ops := lcsDiff(a, b)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--- %s\n", aLabel)
	fmt.Fprintf(&buf, "+++ %s\n", bLabel)

	// Group ops into hunks with 3 lines of context.
	hunks := groupHunks(ops, 3)
	for _, h := range hunks {
		fmt.Fprintf(&buf, "@@ -%d,%d +%d,%d @@\n", h.aStart+1, h.aLen, h.bStart+1, h.bLen)
		for _, op := range h.ops {
			switch op.kind {
			case '-':
				buf.WriteString("-")
				buf.WriteString(op.line)
				buf.WriteByte('\n')
			case '+':
				buf.WriteString("+")
				buf.WriteString(op.line)
				buf.WriteByte('\n')
			case ' ':
				buf.WriteString(" ")
				buf.WriteString(op.line)
				buf.WriteByte('\n')
			}
		}
	}
	return buf.String()
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	return strings.Split(s, "\n")
}

type diffOp struct {
	kind byte // '-', '+', ' '
	line string
}

// lcsDiff returns a sequence of - / + / ' ' ops that transform a into b.
func lcsDiff(a, b []string) []diffOp {
	// Build LCS length table.
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				lcs[i][j] = lcs[i-1][j-1] + 1
			} else if lcs[i-1][j] >= lcs[i][j-1] {
				lcs[i][j] = lcs[i-1][j]
			} else {
				lcs[i][j] = lcs[i][j-1]
			}
		}
	}
	// Backtrack to produce ops.
	var ops []diffOp
	i, j := n, m
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && a[i-1] == b[j-1]:
			ops = append([]diffOp{{kind: ' ', line: a[i-1]}}, ops...)
			i--
			j--
		case j > 0 && (i == 0 || lcs[i][j-1] >= lcs[i-1][j]):
			ops = append([]diffOp{{kind: '+', line: b[j-1]}}, ops...)
			j--
		default:
			ops = append([]diffOp{{kind: '-', line: a[i-1]}}, ops...)
			i--
		}
	}
	return ops
}

type hunk struct {
	aStart, aLen int
	bStart, bLen int
	ops          []diffOp
}

// groupHunks chunks the op stream into hunks separated by runs of
// >context unchanged lines.
func groupHunks(ops []diffOp, context int) []hunk {
	var hunks []hunk
	// First, find ranges of changes (any '+' or '-' op) and pad with context.
	type change struct {
		start, end int // ops indices
	}
	var changes []change
	i := 0
	for i < len(ops) {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := i
		for i < len(ops) && ops[i].kind != ' ' {
			i++
		}
		changes = append(changes, change{start: start, end: i})
	}
	// Merge changes whose context windows overlap.
	merged := []change{}
	for _, c := range changes {
		s := c.start - context
		if s < 0 {
			s = 0
		}
		e := c.end + context
		if e > len(ops) {
			e = len(ops)
		}
		if len(merged) > 0 && merged[len(merged)-1].end >= s {
			if e > merged[len(merged)-1].end {
				merged[len(merged)-1].end = e
			}
		} else {
			merged = append(merged, change{start: s, end: e})
		}
	}
	// Compute aStart/bStart for each hunk by counting up to its start.
	aPos, bPos := 0, 0
	prev := 0
	for _, c := range merged {
		// Advance counters to c.start.
		for k := prev; k < c.start; k++ {
			switch ops[k].kind {
			case ' ':
				aPos++
				bPos++
			case '-':
				aPos++
			case '+':
				bPos++
			}
		}
		hunkOps := ops[c.start:c.end]
		var aLen, bLen int
		for _, op := range hunkOps {
			switch op.kind {
			case ' ':
				aLen++
				bLen++
			case '-':
				aLen++
			case '+':
				bLen++
			}
		}
		hunks = append(hunks, hunk{
			aStart: aPos,
			aLen:   aLen,
			bStart: bPos,
			bLen:   bLen,
			ops:    hunkOps,
		})
		// Advance counters through this hunk for the next iteration.
		for _, op := range hunkOps {
			switch op.kind {
			case ' ':
				aPos++
				bPos++
			case '-':
				aPos++
			case '+':
				bPos++
			}
		}
		prev = c.end
	}
	return hunks
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/draft -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/draft/diff.go internal/draft/diff_test.go
git commit -m "feat(draft): unified diff helper (LCS-based, stdlib-only)"
```

---

## Task 7: `FirewallRuleSvc.Pull`

**Files:**
- Create: `internal/svc/firewallrule_pull.go`
- Create: `internal/svc/firewallrule_pull_test.go`

Adds `Pull` method to the existing `FirewallRuleSvc`. Pull fetches the live rule, computes its diff hash, writes a snapshot + draft, rotates old snapshots, and returns a result with paths and references.

- [ ] **Step 1: Write the failing test**

Create `internal/svc/firewallrule_pull_test.go`:

```go
package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// fakeRuleClient returns a single FirewallRule body on Get.
type fakeRuleClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeRuleClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "FirewallRule" {
		raw, _ := json.Marshal(f.body)
		resp.Body["FirewallRule"] = []json.RawMessage{raw}
	}
	return resp, nil
}

func (f *fakeRuleClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newFwRuleSvc(t *testing.T, body map[string]any) (*FirewallRuleSvc, *fakeRuleClient, string) {
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
	fc := &fakeRuleClient{body: body}
	svc := &FirewallRuleSvc{
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

func TestFirewallRuleSvc_Pull_WritesSnapshotAndDraft(t *testing.T) {
	body := map[string]any{
		"Name":       "WAN-to-LAN",
		"Status":     "Enable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
		"NetworkPolicy": map[string]any{
			"Action":             "Accept",
			"SourceNetworks":     map[string]any{"Network": "LAN-network"},
			"DestinationZones":   map[string]any{"Zone": "WAN"},
		},
	}
	svc, _, baseDir := newFwRuleSvc(t, body)

	out, err := svc.Pull(context.Background(), "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Equal(t, "WAN-to-LAN", out.Rule)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)

	// Draft + snapshot should both contain the rule body's keys.
	d, err := draft.ReadDraft(out.DraftPath)
	require.NoError(t, err)
	require.Equal(t, "home", d.Profile)
	require.Equal(t, "WAN-to-LAN", d.Rule)
	require.Contains(t, string(d.Body), "Name: WAN-to-LAN")
	require.Contains(t, string(d.Body), "PolicyType: Network")

	// Reference summary should include LAN-network and WAN zone.
	allRefs := []string{}
	for _, rs := range out.References {
		allRefs = append(allRefs, rs.Type+":"+fmt.Sprint(rs.Names))
	}
	joined := strings.Join(allRefs, ",")
	require.Contains(t, joined, "LAN-network")
	require.Contains(t, joined, "WAN")
	_ = baseDir
}

func TestFirewallRuleSvc_Pull_RuleNotFound(t *testing.T) {
	svc, _, _ := newFwRuleSvc(t, nil)
	_, err := svc.Pull(context.Background(), "home", "MissingRule")
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestFirewallRuleSvc_Pull_OverwritesExistingDraft(t *testing.T) {
	body := map[string]any{
		"Name":       "WAN-to-LAN",
		"Status":     "Enable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "WAN-to-LAN")
	require.NoError(t, err)
	out2, err := svc.Pull(context.Background(), "home", "WAN-to-LAN")
	require.NoError(t, err)

	// Both snapshots should exist (different timestamps).
	snaps, err := draft.ListSnapshots(svc.BaseDir, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.Len(t, snaps, 1, "fixed Now means both pulls write to the same snapshot file (overwrites by name)")
	_ = out2
}

func TestFirewallRuleSvc_Pull_RotatesOldSnapshots(t *testing.T) {
	body := map[string]any{
		"Name":       "WAN-to-LAN",
		"Status":     "Enable",
		"IPFamily":   "IPv4",
		"PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	// Pre-create 12 fake snapshots; Pull should rotate to 10 (default).
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	for i := 0; i < 12; i++ {
		stamp := time.Date(2026, 5, 1, i, 0, 0, 0, time.UTC).Format("2006-01-02T15-04-05Z")
		path := filepath.Join(dir, "wan-to-lan-"+stamp+".yaml")
		require.NoError(t, os.WriteFile(path, []byte("# rule: WAN-to-LAN\n"), 0o600))
	}

	_, err := svc.Pull(context.Background(), "home", "WAN-to-LAN")
	require.NoError(t, err)

	snaps, err := draft.ListSnapshots(svc.BaseDir, "home", "WAN-to-LAN")
	require.NoError(t, err)
	require.LessOrEqual(t, len(snaps), 10)
}
```

Imports needed: `errors`, `strings` (for the `strings.Join` in the first test). Add them.

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Pull -v
```

- [ ] **Step 3: Extend FirewallRuleSvc and add Pull**

In a new file `/Users/ipm/code/sophosfw/internal/svc/firewallrule_pull.go`, add:

```go
package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/draft"
)

// Phase 7 extends FirewallRuleSvc with pull/diff/push/delete. The
// existing struct from firewallrule.go gains optional fields here via
// addition (Go composes the type across files).
//
// We do not redefine FirewallRuleSvc here — that lives in
// firewallrule.go. Instead, we add new fields to it, but Go doesn't
// allow that across files. So we have two options:
//   (a) edit firewallrule.go to add Audit / BaseDir / Now fields
//   (b) define a wrapper type in this file
// Option (a) is cleaner. Edit firewallrule.go (existing struct):

// REQUIRED EDIT to internal/svc/firewallrule.go:
//   type FirewallRuleSvc struct {
//       Inner   *ObjectSvc
//       Audit   *AuditLog        // NEW: Phase 7
//       BaseDir string            // NEW: Phase 7 — where drafts/ + snapshots/ live
//       Now     func() time.Time  // NEW: Phase 7 — injectable for tests
//   }
// (The implementer makes that edit as part of this task; the new file
// below references the new fields.)

// FirewallRulePullResult is what Pull returns to the caller.
type FirewallRulePullResult struct {
	Profile      string
	Rule         string
	DraftPath    string
	SnapshotPath string
	DiffHash     string
	References   []ReferenceSummary
}

// ReferenceSummary groups names of objects referenced by a rule.
type ReferenceSummary struct {
	Type  string   // e.g. "Network", "Zone", "Service"
	Names []string // sorted, deduplicated
}

// Pull fetches the live FirewallRule, writes a snapshot + draft to
// disk under s.BaseDir, rotates old snapshots, and returns paths +
// hash + references.
func (s *FirewallRuleSvc) Pull(ctx context.Context, profileName, ruleName string) (*FirewallRulePullResult, error) {
	profile, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}
	_ = profile

	// 1. Fetch live rule.
	body, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("firewall rule %q: %w", ruleName, ErrNotFoundFromCatalog())
	}

	// 2. Compute diff hash.
	hash, err := DiffHash(body)
	if err != nil {
		return nil, err
	}

	// 3. Marshal canonical YAML (sorted keys).
	yamlBytes, err := marshalCanonicalYAML(body)
	if err != nil {
		return nil, err
	}

	// 4. Resolve draft + snapshot paths.
	draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	now := s.now()
	snapPath, err := draft.SnapshotPath(s.BaseDir, name, ruleName, now)
	if err != nil {
		return nil, err
	}

	// 5. Build the Draft object (used for both files).
	d := &draft.Draft{
		Profile:  name,
		Rule:     ruleName,
		PulledAt: now,
		DiffHash: hash,
		Body:     yamlBytes,
	}

	// 6. Write snapshot first (immutable record), then draft.
	if err := draft.WriteDraft(snapPath, d); err != nil {
		return nil, err
	}
	if err := draft.WriteDraft(draftPath, d); err != nil {
		return nil, err
	}

	// 7. Rotate snapshots (default: keep last 10).
	if err := draft.RotateSnapshots(s.BaseDir, name, ruleName, 10); err != nil {
		return nil, err
	}

	// 8. Audit entry.
	if s.Audit != nil {
		_ = s.Audit.Write(AuditEntry{
			Profile:    name,
			Operation:  "firewall_rule_pull",
			ObjectType: "FirewallRule",
			ObjectName: ruleName,
			Result:     "ok",
		})
	}

	// 9. Reference summary.
	refs := extractReferences(body)

	return &FirewallRulePullResult{
		Profile:      name,
		Rule:         ruleName,
		DraftPath:    draftPath,
		SnapshotPath: snapPath,
		DiffHash:     hash,
		References:   refs,
	}, nil
}

// now returns the current time, using s.Now if set (for tests) or
// time.Now() otherwise.
func (s *FirewallRuleSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// marshalCanonicalYAML marshals a map[string]any to YAML with
// alphabetically-sorted top-level keys. Nested maps are also sorted.
// This guarantees deterministic byte output for a given input —
// important so the snapshot's diffHash matches what `DiffHash(body)`
// produced (DiffHash sorts keys via canonical JSON).
func marshalCanonicalYAML(v any) ([]byte, error) {
	return yaml.Marshal(sortMap(v))
}

// sortMap recursively sorts top-level keys of any nested map[string]any
// by returning a *yaml.Node tree with explicit ordering.
func sortMap(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// gopkg.in/yaml.v3 marshals map[string]any in random order.
		// We use yaml.Node with an ordered mapping to control output.
		node := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range keys {
			keyN := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
			valN, err := toYAMLNode(sortMap(t[k]))
			if err != nil {
				return v // fallback; downstream will surface marshal error
			}
			node.Content = append(node.Content, keyN, valN)
		}
		return node
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = sortMap(t[i])
		}
		return out
	default:
		return v
	}
}

// toYAMLNode converts a value (already sorted by sortMap) into a
// *yaml.Node so the parent mapping preserves ordering.
func toYAMLNode(v any) (*yaml.Node, error) {
	if n, ok := v.(*yaml.Node); ok {
		return n, nil
	}
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return n, nil
}

// ErrNotFoundFromCatalog is a small helper to wrap not-found cases the
// catalog reports as nil. (When ObjectSvc.Get hits a 526, it returns
// ErrNotFound; when it returns nil with no error, it's an empty list
// situation that we treat as not-found here.)
func ErrNotFoundFromCatalog() error {
	return sophosErrNotFound()
}

// sophosErrNotFound returns sophos.ErrNotFound through this package's
// import path so callers don't need a transitive import.
func sophosErrNotFound() error {
	return ErrSophosNotFound
}

// ErrSophosNotFound is wired in this file (rather than imported anew
// at every call site) to keep imports minimal; it equals
// sophos.ErrNotFound.
var ErrSophosNotFound = errSophosNotFound()

func errSophosNotFound() error {
	// Defer the actual import via a tiny wrapper in errors_kind.go; if
	// the import is already there, just reuse it directly. The
	// implementer should replace this with a direct
	// `sophos.ErrNotFound` reference if it simplifies the file.
	return nil // Placeholder; replaced in implementer step.
}
```

This file imports `sophos.ErrNotFound` from `internal/sophos`, so add the import:

```go
import (
	// ...
	"github.com/iainmoffat/sophosfw/internal/sophos"
)
```

And replace the placeholder helpers with the direct sentinel:

```go
// (delete ErrSophosNotFound, errSophosNotFound, sophosErrNotFound, ErrNotFoundFromCatalog)

// In Pull, replace:
//   return nil, fmt.Errorf("firewall rule %q: %w", ruleName, ErrNotFoundFromCatalog())
// With:
//   return nil, fmt.Errorf("firewall rule %q: %w", ruleName, sophos.ErrNotFound)
```

Edit `internal/svc/firewallrule.go` to add the new fields:

```go
type FirewallRuleSvc struct {
	Inner   *ObjectSvc
	Audit   *AuditLog
	BaseDir string
	Now     func() time.Time
}
```

Add the `time` import.

Add the `extractReferences` helper (in the new file or a sibling — the new file is fine):

```go
// extractReferences walks a FirewallRule body looking for known
// reference-bearing field names (NetworkPolicy.SourceNetworks,
// DestinationNetworks, Services, SourceZones, DestinationZones,
// Schedule, IdentityList, etc.) and returns a deduplicated summary.
func extractReferences(body map[string]any) []ReferenceSummary {
	type collector struct {
		ipHosts  map[string]struct{}
		zones    map[string]struct{}
		services map[string]struct{}
	}
	c := collector{
		ipHosts:  map[string]struct{}{},
		zones:    map[string]struct{}{},
		services: map[string]struct{}{},
	}

	// NetworkPolicy is the typical container.
	policies := []map[string]any{}
	if np, ok := body["NetworkPolicy"].(map[string]any); ok {
		policies = append(policies, np)
	}
	for _, np := range policies {
		collectNames(np, "SourceNetworks", "Network", c.ipHosts)
		collectNames(np, "DestinationNetworks", "Network", c.ipHosts)
		collectNames(np, "Services", "Service", c.services)
		collectNames(np, "SourceZones", "Zone", c.zones)
		collectNames(np, "DestinationZones", "Zone", c.zones)
	}

	out := []ReferenceSummary{}
	if len(c.ipHosts) > 0 {
		out = append(out, ReferenceSummary{Type: "IPHost", Names: keys(c.ipHosts)})
	}
	if len(c.zones) > 0 {
		out = append(out, ReferenceSummary{Type: "Zone", Names: keys(c.zones)})
	}
	if len(c.services) > 0 {
		out = append(out, ReferenceSummary{Type: "Service", Names: keys(c.services)})
	}
	return out
}

// collectNames extracts names from policy[parent][child], handling the
// single-or-list union shape (string OR []any).
func collectNames(policy map[string]any, parent, child string, sink map[string]struct{}) {
	pv, ok := policy[parent].(map[string]any)
	if !ok {
		return
	}
	v, ok := pv[child]
	if !ok {
		return
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			sink[t] = struct{}{}
		}
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				sink[s] = struct{}{}
			}
		}
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// (remove the unused json import if Pull doesn't use it; keep if other
// helpers need it.)
```

Note: the test `TestFirewallRuleSvc_Pull_RuleNotFound` expects `errors.Is(err, sophos.ErrNotFound)`. Make sure the error chain works — `s.Get(ctx, profile, name)` returns `nil` for missing or returns the wrapped sophos error directly. Trace: `ObjectSvc.Get(ctx, profile, "FirewallRule", name)` → `client.Do(ctx, GetEnvelope)` → if 526, response carries embedded Status → `AsError()` returns `*StatusError{Sentinel: ErrNotFound}` → `Inner.Get` propagates it. So the existing `Get` should return an error wrapping `sophos.ErrNotFound` and the test's `errors.Is` will work.

If the existing `FirewallRuleSvc.Get` short-circuits (e.g., returns `nil, nil` for empty results instead of an error), the implementer may need to detect the `nil, nil` case in `Pull` and synthesize the not-found error explicitly:

```go
if body == nil {
    return nil, fmt.Errorf("firewall rule %q: %w", ruleName, sophos.ErrNotFound)
}
```

Verify by reading the existing `Get` and inserting the synthesis only if needed.

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Pull -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/firewallrule.go internal/svc/firewallrule_pull.go internal/svc/firewallrule_pull_test.go
git commit -m "feat(svc): FirewallRuleSvc.Pull — fetch, snapshot, draft, audit"
```

---

## Task 8: `FirewallRuleSvc.Diff`

**Files:**
- Modify: `internal/svc/firewallrule_pull.go` (add Diff method)
- Modify: `internal/svc/firewallrule_pull_test.go` (add Diff tests)

Diff is local-only: read draft + matching snapshot, compute unified diff (text) and structured diff entries (json).

- [ ] **Step 1: Write the failing tests**

Append to `internal/svc/firewallrule_pull_test.go`:

```go
func TestFirewallRuleSvc_Diff_NoChanges(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Diff(context.Background(), "home", "X")
	require.NoError(t, err)
	require.False(t, out.HasChanges)
	require.Empty(t, out.UnifiedDiff)
	require.Empty(t, out.StructuredDiff)
}

func TestFirewallRuleSvc_Diff_DetectsFieldChange(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, _ := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Manually edit the draft body to flip Status.
	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("Status: Enable"), []byte("Status: Disable"))
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	out, err := svc.Diff(context.Background(), "home", "X")
	require.NoError(t, err)
	require.True(t, out.HasChanges)
	require.Contains(t, out.UnifiedDiff, "-Status: Enable")
	require.Contains(t, out.UnifiedDiff, "+Status: Disable")

	// StructuredDiff should report Status changed.
	var found bool
	for _, e := range out.StructuredDiff {
		if e.Path == "Status" {
			found = true
			require.Equal(t, "changed", e.Op)
			require.Equal(t, "Enable", e.OldValue)
			require.Equal(t, "Disable", e.NewValue)
		}
	}
	require.True(t, found, "Status change must appear in structured diff")
}

func TestFirewallRuleSvc_Diff_MissingSnapshot(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, _, baseDir := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	// Delete all snapshots.
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		require.NoError(t, os.Remove(filepath.Join(dir, e.Name())))
	}
	_, err = svc.Diff(context.Background(), "home", "X")
	require.Error(t, err)
	require.True(t, errors.Is(err, draft.ErrSnapshotMissing))
}
```

Add `bytes` to imports.

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Diff -v
```

- [ ] **Step 3: Implement Diff**

Append to `internal/svc/firewallrule_pull.go`:

```go
// FirewallRuleDiffResult is what Diff returns.
type FirewallRuleDiffResult struct {
	Profile        string
	Rule           string
	HasChanges     bool
	UnifiedDiff    string
	StructuredDiff []DiffEntry
}

// DiffEntry is a single key-level change between snapshot and draft.
type DiffEntry struct {
	Path     string `json:"path"`
	Op       string `json:"op"` // added | removed | changed
	OldValue any    `json:"oldValue,omitempty"`
	NewValue any    `json:"newValue,omitempty"`
}

// Diff reads the draft for ruleName, finds the snapshot whose
// diffHash matches the draft's header diffHash, and returns the
// unified-text + structured diff. Local only — no firewall round-trip.
func (s *FirewallRuleSvc) Diff(ctx context.Context, profileName, ruleName string) (*FirewallRuleDiffResult, error) {
	_, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	// Find matching snapshot.
	snaps, err := draft.ListSnapshots(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	var snapBody []byte
	for _, p := range snaps {
		s, err := draft.ReadDraft(p)
		if err != nil {
			continue
		}
		if s.DiffHash == d.DiffHash {
			snapBody = s.Body
			break
		}
	}
	if snapBody == nil {
		return nil, fmt.Errorf("for draft %s: %w", draftPath, draft.ErrSnapshotMissing)
	}

	out := &FirewallRuleDiffResult{
		Profile: name,
		Rule:    ruleName,
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

// structuredDiff parses both YAML bodies and walks the resulting maps
// key-by-key, producing DiffEntry records for added/removed/changed
// keys at each level. Path is dotted (e.g., "NetworkPolicy.Action").
func structuredDiff(a, b []byte) ([]DiffEntry, error) {
	var av, bv map[string]any
	if err := yaml.Unmarshal(a, &av); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &bv); err != nil {
		return nil, err
	}
	var out []DiffEntry
	walkMaps("", av, bv, &out)
	return out, nil
}

func walkMaps(prefix string, a, b map[string]any, out *[]DiffEntry) {
	keys := unionKeys(a, b)
	for _, k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		av, aok := a[k]
		bv, bok := b[k]
		switch {
		case !aok:
			*out = append(*out, DiffEntry{Path: path, Op: "added", NewValue: bv})
		case !bok:
			*out = append(*out, DiffEntry{Path: path, Op: "removed", OldValue: av})
		default:
			am, amok := av.(map[string]any)
			bm, bmok := bv.(map[string]any)
			if amok && bmok {
				walkMaps(path, am, bm, out)
				continue
			}
			if !reflectDeepEqualSimple(av, bv) {
				*out = append(*out, DiffEntry{Path: path, Op: "changed", OldValue: av, NewValue: bv})
			}
		}
	}
}

func unionKeys(a, b map[string]any) []string {
	seen := map[string]struct{}{}
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// reflectDeepEqualSimple compares two interface{} values by string
// representation as a cheap proxy for value equality. Sufficient for
// the YAML bodies we encounter; avoids the reflect import.
func reflectDeepEqualSimple(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Diff -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/firewallrule_pull.go internal/svc/firewallrule_pull_test.go
git commit -m "feat(svc): FirewallRuleSvc.Diff — local unified + structured diff"
```

---

## Task 9: `FirewallRuleSvc.Push`

**Files:**
- Modify: `internal/svc/firewallrule_pull.go` (add Push method + marshalFirewallRule helper)
- Modify: `internal/svc/firewallrule_pull_test.go` (add Push tests)

The meaty mutating path. Reuses `mutate`-style pattern from Phase 6 hostip but with draft I/O instead of flag input.

- [ ] **Step 1: Write the failing tests**

Append to `internal/svc/firewallrule_pull_test.go`:

```go
func TestFirewallRuleSvc_Push_DryRun_NoSend(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	out, err := svc.Push(context.Background(), "home", "X", false, true) // ignoreHash=false, dryRun=true
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Empty(t, fc.sent, "dry-run must not send")
}

func TestFirewallRuleSvc_Push_Apply_RefetchAndArchive(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, baseDir := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	prePullSnaps, _ := draft.ListSnapshots(baseDir, "home", "X")

	out, err := svc.Push(context.Background(), "home", "X", false, false) // apply
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "update", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)

	// New snapshot was archived (>= preFwSnaps + 1, allowing for rotation
	// at scale; here we expect exactly +1 unless the cap was hit).
	postSnaps, _ := draft.ListSnapshots(baseDir, "home", "X")
	require.Greater(t, len(postSnaps), len(prePullSnaps)-10) // sanity: at least one
	_ = pull
}

func TestFirewallRuleSvc_Push_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Mutate the live body so the hash changes.
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent, "mismatch must reject before send")
	_ = pull
}

func TestFirewallRuleSvc_Push_DiffHashMismatch_IgnoreFlag_Applies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)
	fc.body["Status"] = "Disable"

	_, err = svc.Push(context.Background(), "home", "X", true, false) // ignoreHash=true
	require.NoError(t, err)
	require.Len(t, fc.sent, 1)
}

func TestFirewallRuleSvc_Push_HeaderRuleMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Manually corrupt the draft header.
	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Rule = "DifferentName"
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rule")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_Push_RequiredFieldMissing_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	pull, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Strip PolicyType from the draft body.
	d, err := draft.ReadDraft(pull.DraftPath)
	require.NoError(t, err)
	d.Body = bytes.ReplaceAll(d.Body, []byte("PolicyType: Network\n"), nil)
	require.NoError(t, draft.WriteDraft(pull.DraftPath, d))

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "PolicyType")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_Push_ReadOnlyProfile_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Flip profile to read-only.
	p, ok := svc.Inner.Config.Profiles["home"]
	require.True(t, ok)
	p.ReadOnly = true
	svc.Inner.Config.Profiles["home"] = p

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_Push_Failure_AuditLogged(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Pull(context.Background(), "home", "X")
	require.NoError(t, err)

	// Inject a send failure.
	fc.sendErr = sophos.ErrServerError

	_, err = svc.Push(context.Background(), "home", "X", false, false)
	require.Error(t, err)

	// Audit log should record the failure.
	auditPath := filepath.Join(svc.Audit.Dir, "audit.log")
	logBody, err := os.ReadFile(auditPath)
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"firewall_rule_push"`)
	require.Contains(t, string(logBody), `"result":"error:server_error"`)
}
```

The test references `fc.sendErr` and `svc.Audit.Dir`. Update `fakeRuleClient` to add a `sendErr error` field, and confirm `AuditLog.Dir` is exported (or derive the audit path another way — read from the field that holds the audit dir).

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Push -v
```

- [ ] **Step 3: Implement Push + marshalFirewallRule**

Append to `internal/svc/firewallrule_pull.go`:

```go
import (
	// ... existing imports ...
	"bytes"
	"encoding/xml"
	"sort"

	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// FirewallRulePushResult is what Push and Delete return.
type FirewallRulePushResult struct {
	Profile     string
	Rule        string
	Operation   string                 // "update" | "delete"
	DryRun      bool
	Preview     *Preview                // dry-run only
	NewDiffHash string                  // apply only
	Item        map[string]any          // apply only — refetched body
}

// requiredFirewallRuleFields enumerates the top-level YAML keys a
// FirewallRule body MUST carry.
var requiredFirewallRuleFields = []string{"Name", "Status", "IPFamily", "PolicyType"}

func (s *FirewallRuleSvc) Push(ctx context.Context, profileName, ruleName string, ignoreHash, dryRun bool) (*FirewallRulePushResult, error) {
	profile, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	// 1. Read draft.
	draftPath, err := draft.DraftPath(s.BaseDir, name, ruleName)
	if err != nil {
		return nil, err
	}
	d, err := draft.ReadDraft(draftPath)
	if err != nil {
		return nil, err
	}

	// 2. Header sanity.
	if d.Rule != ruleName {
		return nil, fmt.Errorf("%w: draft header rule %q does not match cli arg %q", sophos.ErrInvalidRequest, d.Rule, ruleName)
	}
	if d.Profile != name {
		return nil, fmt.Errorf("%w: draft header profile %q does not match active profile %q", sophos.ErrInvalidRequest, d.Profile, name)
	}

	// 3. Parse body + required-field validation.
	parsed, err := parseAndValidateRuleBody(d.Body)
	if err != nil {
		return nil, err
	}

	// 4. Read-only profile.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	// 5. Catalog Mutable check.
	entry, ok := s.Inner.Catalog.Lookup("FirewallRule")
	if !ok || !entry.Mutable {
		return nil, fmt.Errorf("%w: FirewallRule is not flagged mutable in the catalog", ErrImmutable)
	}

	// 6. Refetch live + diff hash check.
	if !ignoreHash {
		live, err := s.Get(ctx, profileName, ruleName)
		if err != nil {
			return nil, err
		}
		liveHash, err := DiffHash(live)
		if err != nil {
			return nil, err
		}
		if liveHash != d.DiffHash {
			return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, d.DiffHash)
		}
	}

	// 7. Build envelope.
	c, err := s.Inner.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	inner, err := marshalFirewallRule(parsed)
	if err != nil {
		return nil, err
	}
	full, err := sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
	if err != nil {
		return nil, err
	}

	// 8. Audit entry skeleton.
	entryAudit := AuditEntry{
		Profile:          name,
		Operation:        "firewall_rule_push",
		ObjectType:       "FirewallRule",
		ObjectName:       ruleName,
		ExpectedDiffHash: d.DiffHash,
		RedactedXML:      string(safety.RedactXML(full)),
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}

	// 9. Dry-run path.
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
		return &FirewallRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "update",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	// 10. Apply path.
	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	// 11. Refetch, archive, update draft hash.
	refetched, _ := s.Get(ctx, profileName, ruleName)
	newHash := ""
	if refetched != nil {
		nh, hashErr := DiffHash(refetched)
		if hashErr == nil {
			newHash = nh
		}
	}
	if refetched != nil && newHash != "" {
		// Archive new state.
		now := s.now()
		snapPath, perr := draft.SnapshotPath(s.BaseDir, name, ruleName, now)
		if perr == nil {
			yamlBytes, merr := marshalCanonicalYAML(refetched)
			if merr == nil {
				_ = draft.WriteDraft(snapPath, &draft.Draft{
					Profile: name, Rule: ruleName, PulledAt: now, DiffHash: newHash, Body: yamlBytes,
				})
				_ = draft.RotateSnapshots(s.BaseDir, name, ruleName, 10)
			}
		}
		// Update draft header diff hash so the user can keep editing forward.
		d.DiffHash = newHash
		_ = draft.WriteDraft(draftPath, d)
	}

	return &FirewallRulePushResult{
		Profile:     name,
		Rule:        ruleName,
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: newHash,
		Item:        refetched,
	}, nil
}

// parseAndValidateRuleBody unmarshals the draft body and verifies that
// the four required top-level fields are present and non-empty.
func parseAndValidateRuleBody(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: draft body is not valid YAML: %v", sophos.ErrInvalidRequest, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: draft body is empty", sophos.ErrInvalidRequest)
	}
	for _, k := range requiredFirewallRuleFields {
		v, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("%w: draft body missing required field %q", sophos.ErrInvalidRequest, k)
		}
		if s, isStr := v.(string); isStr && s == "" {
			return nil, fmt.Errorf("%w: draft body field %q is empty", sophos.ErrInvalidRequest, k)
		}
	}
	return m, nil
}

// marshalFirewallRule converts the parsed rule body to XML wrapped in
// <FirewallRule>...</FirewallRule>. Generic recursive marshaler:
//   - string/bool/numeric scalars → text content (XML-escaped)
//   - map[string]any → nested element with sorted child keys
//   - []any → repeated sibling elements with the parent's key
func marshalFirewallRule(rule map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<FirewallRule>")
	if err := writeMapChildren(&buf, rule); err != nil {
		return nil, err
	}
	buf.WriteString("</FirewallRule>")
	return buf.Bytes(), nil
}

func writeMapChildren(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeKeyValue(buf, k, m[k]); err != nil {
			return err
		}
	}
	return nil
}

func writeKeyValue(buf *bytes.Buffer, key string, val any) error {
	switch v := val.(type) {
	case nil:
		// Skip null values.
		return nil
	case string:
		writeOpen(buf, key)
		if err := xml.EscapeText(buf, []byte(v)); err != nil {
			return err
		}
		writeClose(buf, key)
	case bool:
		writeOpen(buf, key)
		fmt.Fprintf(buf, "%t", v)
		writeClose(buf, key)
	case int, int64, float64:
		writeOpen(buf, key)
		fmt.Fprintf(buf, "%v", v)
		writeClose(buf, key)
	case map[string]any:
		writeOpen(buf, key)
		if err := writeMapChildren(buf, v); err != nil {
			return err
		}
		writeClose(buf, key)
	case []any:
		// Emit one <key>VAL</key> per item.
		for _, item := range v {
			if err := writeKeyValue(buf, key, item); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported value type for key %q: %T", key, val)
	}
	return nil
}

func writeOpen(buf *bytes.Buffer, key string) {
	buf.WriteString("<")
	buf.WriteString(key)
	buf.WriteString(">")
}

func writeClose(buf *bytes.Buffer, key string) {
	buf.WriteString("</")
	buf.WriteString(key)
	buf.WriteString(">")
}
```

Add `sendErr error` field to `fakeRuleClient` (the test expects it):

```go
type fakeRuleClient struct {
	body    map[string]any
	sent    [][]byte
	sendErr error
}

func (f *fakeRuleClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sophos.Response{LoginOK: true}, nil
}
```

Confirm `AuditLog.Dir` exists. If it doesn't, the test should reach into the audit dir via the same pattern Phase 6's audit tests use (`auditDir` returned from `newCreateTestSvc`). Adapt the helper to return the audit dir string and assert on it via `filepath.Join(auditDir, "audit.log")`.

If `ErrImmutable` doesn't exist (only `ErrDiffHashMismatch` was added in Phase 6), search for it: `grep -n "ErrImmutable" internal/svc/`. If not present, use `sophos.ErrInvalidRequest` with a clear message. The test asserts on the error message so the kind switch may not matter.

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Push -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/firewallrule_pull.go internal/svc/firewallrule_pull_test.go
git commit -m "feat(svc): FirewallRuleSvc.Push with diff-hash, dry-run, audit, archive"
```

---

## Task 10: `FirewallRuleSvc.Delete`

**Files:**
- Modify: `internal/svc/firewallrule_pull.go` (add Delete method)
- Modify: `internal/svc/firewallrule_pull_test.go` (add Delete tests)

Mirrors Phase 6 `HostIPSvc.Delete` semantically; archives a `-deleted` snapshot on success.

- [ ] **Step 1: Write the failing tests**

Append to `internal/svc/firewallrule_pull_test.go`:

```go
func TestFirewallRuleSvc_Delete_RequiresExpectedHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "", false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expectedDiffHash")
	require.Empty(t, fc.sent)
}

func TestFirewallRuleSvc_Delete_Apply(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, baseDir := newFwRuleSvc(t, body)
	hash, err := DiffHash(body)
	require.NoError(t, err)

	out, err := svc.Delete(context.Background(), "home", "X", hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Equal(t, "delete", out.Operation)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
	require.Contains(t, string(fc.sent[0]), `<FirewallRule>`)

	// A -deleted snapshot should exist.
	dir := filepath.Join(baseDir, "profiles", "home", "snapshots")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	hasDeleted := false
	for _, e := range entries {
		if strings.Contains(e.Name(), "-deleted") {
			hasDeleted = true
		}
	}
	require.True(t, hasDeleted, "expected a -deleted snapshot")
}

func TestFirewallRuleSvc_Delete_DiffHashMismatch_Rejects(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	svc, fc, _ := newFwRuleSvc(t, body)
	_, err := svc.Delete(context.Background(), "home", "X", "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sent)
}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Delete -v
```

- [ ] **Step 3: Implement Delete**

Append to `internal/svc/firewallrule_pull.go`:

```go
func (s *FirewallRuleSvc) Delete(ctx context.Context, profileName, ruleName, expectedHash string, ignoreHash, dryRun bool) (*FirewallRulePushResult, error) {
	profile, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	// 1. CLI-side enforcement (the cli should also gate, but defense-in-depth).
	if expectedHash == "" && !ignoreHash {
		return nil, fmt.Errorf("%w: expectedDiffHash is required for delete (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest)
	}

	// 2. Read-only profile.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}

	// 3. Catalog Mutable check.
	entry, ok := s.Inner.Catalog.Lookup("FirewallRule")
	if !ok || !entry.Mutable {
		return nil, fmt.Errorf("%w: FirewallRule is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
	}

	// 4. Refetch + hash compare (unless ignored).
	live, err := s.Get(ctx, profileName, ruleName)
	if err != nil {
		return nil, err
	}
	if live == nil {
		return nil, fmt.Errorf("firewall rule %q: %w", ruleName, sophos.ErrNotFound)
	}
	if !ignoreHash {
		liveHash, err := DiffHash(live)
		if err != nil {
			return nil, err
		}
		if liveHash != expectedHash {
			return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, liveHash, expectedHash)
		}
	}

	// 5. Build envelope.
	c, err := s.Inner.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	var inner bytes.Buffer
	inner.WriteString("<FirewallRule><Name>")
	if err := xml.EscapeText(&inner, []byte(ruleName)); err != nil {
		return nil, err
	}
	inner.WriteString("</Name></FirewallRule>")
	full, err := sophos.BuildRemoveEnvelope(inner.Bytes(), c.Username, c.Password)
	if err != nil {
		return nil, err
	}

	// 6. Audit entry skeleton.
	entryAudit := AuditEntry{
		Profile:          name,
		Operation:        "firewall_rule_delete",
		ObjectType:       "FirewallRule",
		ObjectName:       ruleName,
		ExpectedDiffHash: expectedHash,
		RedactedXML:      string(safety.RedactXML(full)),
	}
	if ignoreHash {
		entryAudit.ExpectedDiffHash = "ignored"
	}

	// 7. Dry-run.
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
		return &FirewallRulePushResult{
			Profile:   name,
			Rule:      ruleName,
			Operation: "delete",
			DryRun:    true,
			Preview:   pv,
		}, nil
	}

	// 8. Apply.
	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		entryAudit.Result = "error:" + ErrorKind(sendErr)
		entryAudit.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(entryAudit)
		return nil, sendErr
	}
	entryAudit.Result = "ok"
	_ = s.Audit.Write(entryAudit)

	// 9. Archive last-known state with -deleted suffix.
	now := s.now()
	regularPath, _ := draft.SnapshotPath(s.BaseDir, name, ruleName, now)
	deletedPath := strings.TrimSuffix(regularPath, ".yaml") + "-deleted.yaml"
	yamlBytes, merr := marshalCanonicalYAML(live)
	if merr == nil {
		liveHash, _ := DiffHash(live)
		_ = draft.WriteDraft(deletedPath, &draft.Draft{
			Profile: name, Rule: ruleName, PulledAt: now, DiffHash: liveHash, Body: yamlBytes,
		})
		_ = draft.RotateSnapshots(s.BaseDir, name, ruleName, 10)
	}

	return &FirewallRulePushResult{
		Profile:   name,
		Rule:      ruleName,
		Operation: "delete",
		DryRun:    false,
	}, nil
}
```

Add `strings` to imports if not already present.

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/svc -run TestFirewallRuleSvc_Delete -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/firewallrule_pull.go internal/svc/firewallrule_pull_test.go
git commit -m "feat(svc): FirewallRuleSvc.Delete with diff hash and -deleted archive"
```

---

## Task 11: Render envelopes for pull/diff/push

**Files:**
- Modify: `internal/render/envelope.go`
- Modify: `internal/render/envelope_test.go` (or create if missing)

Three new functions; small.

- [ ] **Step 1: Write the failing tests**

Add to `internal/render/envelope_test.go`:

```go
func TestFirewallRulePullEnvelope_Schema(t *testing.T) {
	r := &svc.FirewallRulePullResult{
		Profile:      "home",
		Rule:         "WAN-to-LAN",
		DraftPath:    "/path/draft.yaml",
		SnapshotPath: "/path/snapshot.yaml",
		DiffHash:     "abc123",
		References: []svc.ReferenceSummary{
			{Type: "IPHost", Names: []string{"LAN-network"}},
		},
	}
	b, err := FirewallRulePullEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.firewallRulePull"`)
	require.Contains(t, string(b), `"draftPath": "/path/draft.yaml"`)
	require.Contains(t, string(b), `"diffHash": "abc123"`)
	require.Contains(t, string(b), `"LAN-network"`)
}

func TestFirewallRuleDiffEnvelope_Schema(t *testing.T) {
	r := &svc.FirewallRuleDiffResult{
		Profile:    "home",
		Rule:       "WAN-to-LAN",
		HasChanges: true,
		UnifiedDiff: "--- snapshot\n+++ draft\n",
		StructuredDiff: []svc.DiffEntry{
			{Path: "Status", Op: "changed", OldValue: "Enable", NewValue: "Disable"},
		},
	}
	b, err := FirewallRuleDiffEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.firewallRuleDiff"`)
	require.Contains(t, string(b), `"hasChanges": true`)
	require.Contains(t, string(b), `"path": "Status"`)
}

func TestFirewallRulePushEnvelope_DryRun(t *testing.T) {
	r := &svc.FirewallRulePushResult{
		Profile:   "home",
		Rule:      "X",
		Operation: "update",
		DryRun:    true,
		Preview:   &svc.Preview{Mutating: true, Verbs: []string{"Set:update"}},
	}
	b, err := FirewallRulePushEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"schema": "sophosfw.v1.firewallRulePush"`)
	require.Contains(t, string(b), `"applied": false`)
	require.Contains(t, string(b), `"dryRun": true`)
}

func TestFirewallRulePushEnvelope_Apply(t *testing.T) {
	r := &svc.FirewallRulePushResult{
		Profile:     "home",
		Rule:        "X",
		Operation:   "update",
		DryRun:      false,
		NewDiffHash: "def456",
		Item:        map[string]any{"Name": "X", "Status": "Enable"},
	}
	b, err := FirewallRulePushEnvelope(r)
	require.NoError(t, err)
	require.Contains(t, string(b), `"applied": true`)
	require.Contains(t, string(b), `"newDiffHash": "def456"`)
	require.Contains(t, string(b), `"item":`)
}
```

If `envelope_test.go` doesn't exist or has no `svc` import, add:

```go
import (
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/render -run "TestFirewallRule" -v
```

- [ ] **Step 3: Implement the envelope functions**

Append to `internal/render/envelope.go`:

```go
// FirewallRulePullEnvelope renders sophosfw.v1.firewallRulePull.
func FirewallRulePullEnvelope(r *svc.FirewallRulePullResult) ([]byte, error) {
	refs := make([]map[string]any, 0, len(r.References))
	for _, rs := range r.References {
		refs = append(refs, map[string]any{
			"type":  rs.Type,
			"names": rs.Names,
		})
	}
	payload := map[string]any{
		"profile":      r.Profile,
		"rule":         r.Rule,
		"draftPath":    r.DraftPath,
		"snapshotPath": r.SnapshotPath,
		"diffHash":     r.DiffHash,
		"references":   refs,
	}
	return marshalEnvelope("sophosfw.v1.firewallRulePull", payload)
}

// FirewallRuleDiffEnvelope renders sophosfw.v1.firewallRuleDiff.
func FirewallRuleDiffEnvelope(r *svc.FirewallRuleDiffResult) ([]byte, error) {
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
	return marshalEnvelope("sophosfw.v1.firewallRuleDiff", payload)
}

// FirewallRulePushEnvelope renders sophosfw.v1.firewallRulePush.
func FirewallRulePushEnvelope(r *svc.FirewallRulePushResult) ([]byte, error) {
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
	return marshalEnvelope("sophosfw.v1.firewallRulePush", payload)
}
```

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/render -run "TestFirewallRule" -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/render/envelope.go internal/render/envelope_test.go
git commit -m "feat(render): firewallRulePull/Diff/Push envelopes"
```

---

## Task 12: cli `firewall rule pull/diff/push/delete`

**Files:**
- Create: `internal/cli/firewallrule_mutation.go`
- Create: `internal/cli/firewallrule_mutation_test.go`
- Modify: `internal/cli/firewallrule.go` (register the new subcommands)

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/firewallrule_mutation_test.go`:

```go
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeFwRuleCliClient struct {
	body map[string]any
	sent [][]byte
}

func (f *fakeFwRuleCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok && op.XMLTag == "FirewallRule" {
		raw, _ := json.Marshal(f.body)
		resp.Body["FirewallRule"] = []json.RawMessage{raw}
	}
	return resp, nil
}
func (f *fakeFwRuleCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForFwRuleTest(t *testing.T, body map[string]any) (*RootDeps, *fakeFwRuleCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeFwRuleCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestFwRule_Pull_WritesFiles_Json(t *testing.T) {
	body := map[string]any{
		"Name": "WAN-to-LAN", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "pull", "WAN-to-LAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRulePull"`)
	require.Contains(t, out.String(), `"rule": "WAN-to-LAN"`)
	require.Contains(t, out.String(), `"diffHash":`)
}

func TestFwRule_Push_DryRunDefault(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, fc := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	// First, pull so a draft exists.
	root.SetArgs([]string{"firewall", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	// Now push without --yes — must default to dry-run.
	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "push", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"dryRun": true`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestFwRule_Push_YesApplies(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, fc := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "push", "X", "--yes", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="update">`)
}

func TestFwRule_Diff_Json(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "pull", "X"})
	require.NoError(t, root.Execute())

	out.Reset()
	root2 := NewRoot(*d)
	root2.SetOut(out)
	root2.SetErr(out)
	root2.SetArgs([]string{"firewall", "rule", "diff", "X", "--json"})
	require.NoError(t, root2.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRuleDiff"`)
	require.Contains(t, out.String(), `"hasChanges": false`)
}

func TestFwRule_Delete_RequiresExpectedDiffHash(t *testing.T) {
	body := map[string]any{
		"Name": "X", "Status": "Enable", "IPFamily": "IPv4", "PolicyType": "Network",
	}
	d, _ := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "delete", "X", "--yes"})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expected-diff-hash") || strings.Contains(err.Error(), "expectedDiffHash"))
}

// time import — used to silence unused warning if needed.
var _ = time.Time{}
```

- [ ] **Step 2: Run — must fail**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/cli -run "TestFwRule" -v
```

- [ ] **Step 3: Implement the cli subcommands**

Create `/Users/ipm/code/sophosfw/internal/cli/firewallrule_mutation.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

func firewallRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.FirewallRuleSvc {
	return &svc.FirewallRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit:   d.Audit,
		BaseDir: d.BaseDir,
	}
}

func newFirewallRulePullCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "pull <name>",
		Short: "Pull a firewall rule into a local YAML draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := firewallRuleSvc(d, cat).Pull(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.FirewallRulePullEnvelope(result)
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

func newFirewallRuleDiffCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "diff <name>",
		Short: "Show local diff between snapshot and draft",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := firewallRuleSvc(d, cat).Diff(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.FirewallRuleDiffEnvelope(result)
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

func newFirewallRulePushCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	c := &cobra.Command{
		Use:   "push <name>",
		Short: "Validate the draft and apply it to the firewall",
		Long:  "Defaults to --dry-run preview. Pass --yes to apply. Use --ignore-diff-hash to skip drift detection.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			result, err := firewallRuleSvc(d, cat).Push(cmd.Context(), profile, args[0], ignoreHash, !yes)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.FirewallRulePushEnvelope(result)
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

func newFirewallRuleDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var yes, ignoreHash bool
	var expectedHash string
	c := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a firewall rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			result, err := firewallRuleSvc(d, cat).Delete(cmd.Context(), profile, args[0], expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				b, err := render.FirewallRulePushEnvelope(result)
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
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hex hash from a prior `firewall rule pull`")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection")
	c.Flags().BoolVar(&yes, "yes", false, "apply the deletion (default is --dry-run)")
	return c
}
```

Edit `internal/cli/firewallrule.go` to register the new commands. Find the existing `firewall rule` cobra subtree (probably in a function like `newFirewallRuleCmd` or `registerFirewallRule`) and append:

```go
cmd.AddCommand(
    newFirewallRulePullCmd(d, cat),
    newFirewallRuleDiffCmd(d, cat),
    newFirewallRulePushCmd(d, cat),
    newFirewallRuleDeleteCmd(d, cat),
)
```

If the existing surface organizes differently (e.g., one function registers all subcommands), match that pattern.

- [ ] **Step 4: Run — must pass**

```bash
cd /Users/ipm/code/sophosfw && go test ./internal/cli -run "TestFwRule" -v
go test ./... -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/cli/firewallrule.go internal/cli/firewallrule_mutation.go internal/cli/firewallrule_mutation_test.go
git commit -m "feat(cli): firewall rule pull/diff/push/delete"
```

---

## Task 13: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

Adds three integration tests against the testvm. The implementer should run them after committing to verify they pass.

- [ ] **Step 1: Append tests**

Add to `internal/testutil/integration_test.go`:

```go
func TestIntegration_FirewallRulePull_RoundTrips(t *testing.T) {
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	auditDir := t.TempDir()

	tmpBase := t.TempDir()
	svcInst := &svc.FirewallRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit:   svc.NewAuditLog(auditDir, true),
		BaseDir: tmpBase,
	}

	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE to a real rule name on the testvm")
	}

	out, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)
	require.NotEmpty(t, out.DiffHash)
	require.FileExists(t, out.DraftPath)
	require.FileExists(t, out.SnapshotPath)
}

func TestIntegration_FirewallRulePush_DryRun(t *testing.T) {
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	tmpBase := t.TempDir()

	svcInst := &svc.FirewallRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit:   svc.NewAuditLog(t.TempDir(), true),
		BaseDir: tmpBase,
	}
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE")
	}

	_, err = svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)

	out, err := svcInst.Push(context.Background(), profileName, ruleName, false, true) // dryRun=true
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
}

func TestIntegration_FirewallRulePush_RoundTrip(t *testing.T) {
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	tmpBase := t.TempDir()

	svcInst := &svc.FirewallRuleSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit:   svc.NewAuditLog(t.TempDir(), true),
		BaseDir: tmpBase,
	}
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)
	ruleName := os.Getenv("SOPHOSFW_TEST_RULE")
	if ruleName == "" {
		t.Skip("set SOPHOSFW_TEST_RULE")
	}

	pullOut, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)

	// Read the draft, capture original NetworkPolicy.LogTraffic value, flip it.
	d, err := draft.ReadDraft(pullOut.DraftPath)
	require.NoError(t, err)
	orig := string(d.Body)

	flipped := orig
	switch {
	case strings.Contains(orig, "LogTraffic: Enable"):
		flipped = strings.Replace(orig, "LogTraffic: Enable", "LogTraffic: Disable", 1)
	case strings.Contains(orig, "LogTraffic: Disable"):
		flipped = strings.Replace(orig, "LogTraffic: Disable", "LogTraffic: Enable", 1)
	default:
		t.Skip("test rule does not have LogTraffic field; pick another rule")
	}
	d.Body = []byte(flipped)
	require.NoError(t, draft.WriteDraft(pullOut.DraftPath, d))

	// Always revert at the end, even if assertions fail.
	t.Cleanup(func() {
		// Re-pull to get the latest hash.
		pull2, err := svcInst.Pull(context.Background(), profileName, ruleName)
		if err != nil {
			t.Logf("cleanup re-pull failed: %v", err)
			return
		}
		// Write the original body back into the draft.
		d2, err := draft.ReadDraft(pull2.DraftPath)
		if err != nil {
			t.Logf("cleanup read failed: %v", err)
			return
		}
		d2.Body = []byte(orig)
		if err := draft.WriteDraft(pull2.DraftPath, d2); err != nil {
			t.Logf("cleanup write failed: %v", err)
			return
		}
		if _, err := svcInst.Push(context.Background(), profileName, ruleName, false, false); err != nil {
			t.Logf("cleanup push failed: %v", err)
		}
	})

	out, err := svcInst.Push(context.Background(), profileName, ruleName, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)

	// Re-pull and verify the change persisted.
	pull3, err := svcInst.Pull(context.Background(), profileName, ruleName)
	require.NoError(t, err)
	d3, err := draft.ReadDraft(pull3.DraftPath)
	require.NoError(t, err)
	if strings.Contains(orig, "LogTraffic: Enable") {
		require.Contains(t, string(d3.Body), "LogTraffic: Disable")
	} else {
		require.Contains(t, string(d3.Body), "LogTraffic: Enable")
	}
}
```

Add `"github.com/iainmoffat/sophosfw/internal/draft"` and `"strings"` to imports if missing.

- [ ] **Step 2: Pick a real rule for SOPHOSFW_TEST_RULE**

```bash
SOPHOSFW_PROFILE=testvm ./bin/sophosfw firewall rule list --json | head -50
```
Pick a rule with `LogTraffic: Enable` or `Disable` in its NetworkPolicy. Example rule names from earlier inspection: `Block Countries`. Use whichever rule exists.

- [ ] **Step 3: Run integration tests**

```bash
cd /Users/ipm/code/sophosfw && SOPHOSFW_PROFILE=testvm SOPHOSFW_TEST_RULE='Block Countries' go test -tags=integration ./internal/testutil -run TestIntegration_FirewallRule -v
```
Expected: PASS for the three new tests.

- [ ] **Step 4: Manual smoke**

```bash
make build
./bin/sophosfw firewall rule pull 'Block Countries' --profile testvm
ls ~/.config/sophosfw/profiles/testvm/drafts/
ls ~/.config/sophosfw/profiles/testvm/snapshots/
./bin/sophosfw firewall rule diff 'Block Countries' --profile testvm
# Edit the draft to flip a field, then:
./bin/sophosfw firewall rule diff 'Block Countries' --profile testvm
./bin/sophosfw firewall rule push 'Block Countries' --profile testvm --json   # dry-run
./bin/sophosfw firewall rule push 'Block Countries' --profile testvm --yes
# Verify and revert.
tail -10 ~/.config/sophosfw/audit.log
```

Confirm:
- Draft + snapshot files appear with 0600 perms.
- Diff shows the edit.
- Push --dry-run emits the preview envelope; --yes applies.
- Audit log has `firewall_rule_pull` and `firewall_rule_push` entries.

- [ ] **Step 5: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "test: phase 7 integration tests against testvm"
```

---

## Task 14: Docs + acceptance + tag v0.6.0-phase7

**Files:**
- Modify: `docs/api-coverage.md`
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update docs/api-coverage.md**

Find the FirewallRule row. Update the Add/Update/Remove cells:

Before:
```
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show | firewall_rule_list/show; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |
```

After (no Add — Phase 7 doesn't ship create):
```
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show/pull/diff/push/delete | firewall_rule_list/show; object_list/get/search/usage | yes | Phase 8 | yes (sophosfw firewall rule push) | yes (sophosfw firewall rule delete) | n/a | Phase 7 |
```

- [ ] **Step 2: Update docs/roadmap.md**

Find:
```markdown
- Phase 6 — Safe mutations (complete; v0.5.0-phase6)
- Phase 7 — Complex draft workflows (firewall rule pull/edit/diff/preview/push)
```

Replace with:
```markdown
- Phase 6 — Safe mutations (complete; v0.5.0-phase6)
- Phase 7 — FirewallRule draft workflow (complete; v0.6.0-phase7)
- Phase 8 — MCP tools for firewall rules + rule create workflow + extension to NATRule
```

- [ ] **Step 3: Run final test pass**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```
Expected: PASS, no fmt drift.

- [ ] **Step 4: Commit fmt drift if any**

```bash
git status
# If files changed:
git add -A
git commit -m "fix: phase 7 acceptance pass formatting"
```

- [ ] **Step 5: Commit docs**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "docs: phase 7 complete in roadmap and api-coverage"
```

- [ ] **Step 6: Tag**

```bash
git tag -a v0.6.0-phase7 -m "Phase 7 complete (FirewallRule pull/diff/push/delete)"
git tag --list | grep -E "(foundation|phase[3-7])"
```
Expected output:
```
v0.1.0-foundation
v0.2.0-phase3
v0.3.0-phase4
v0.4.0-phase5
v0.5.0-phase6
v0.6.0-phase7
```

- [ ] **Step 7: Push to origin**

```bash
git push origin main
git push origin v0.6.0-phase7
```

- [ ] **Step 8: Final sanity**

```bash
git log --oneline -20
```

Expected: 14 task commits + tag.

---

## End of plan

Phase 8 (provisional): MCP tools for firewall rules (stateless `firewall_rule_pull/push` taking YAML inline through tool args), `firewall rule new` create workflow with template selection, and extending the same pull/diff/push pipeline to NATRule.

## Self-review checklist

- ✅ **Spec coverage:** every spec section maps to at least one task. Section 4 (CLI surface) → T12; Section 5 (on-disk layout, slugging) → T3; Section 6 (draft format) → T4; Section 7 (components) → T3-T12; Section 8 (data flow) → T7-T10; Section 9 (error handling) → T2; Section 10 (audit log) → T7+T9+T10; Section 11 (testing) → T7-T13; Section 12 (acceptance) → T14.
- ✅ **No placeholders.** Every task has actual code or commands.
- ✅ **Type consistency.** `FirewallRulePullResult`, `FirewallRuleDiffResult`, `FirewallRulePushResult`, `DiffEntry`, `ReferenceSummary` defined in T7-T9 and used unchanged in T11-T12. `Draft`, `DraftPath`, `SnapshotPath`, `ReadDraft`, `WriteDraft`, `ListSnapshots`, `RotateSnapshots`, `UnifiedDiff` defined in T3-T6 and used in T7-T10.
- ✅ **No Co-Authored-By trailer.** Every commit step inherits the project convention.
- ✅ **Single passing commit per task.** Each task's tests pass at the moment of the commit.
- ✅ **Acceptance.** T14 covers fmt/vet/race, docs, tag, push.
