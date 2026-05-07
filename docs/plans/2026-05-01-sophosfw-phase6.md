# sophosfw Phase 6 Implementation Plan — Safe mutations (host ip + raw apply)

**Goal:** Ship the first mutating operations against live firewall infrastructure: 3 cli commands (`host ip create/update/delete`), 3 MCP tools (`host_ip_create/update/delete`), and a real `raw request --yes --confirm-mutating` apply path replacing the foundation's stub. The deliverable is the safety contract (intent flags, drift detection via `expectedDiffHash`, pre-flight read-only-profile rejection, append-only local audit log) — not surface coverage.

**Architecture:** Two new `internal/svc/` files (`audit.go`, `diffhash.go`) hold cross-cutting machinery; the existing `internal/svc/hostip.go` and `internal/svc/raw.go` gain mutation methods; `internal/sophos/request.go` gains `BuildSetEnvelope` / `BuildRemoveEnvelope` helpers; `internal/catalog/catalog.go` gains a `Mutable bool` field; cli/MCP layers add new commands/tools that compose all of the above. The foundation's `IntegrationClient` continues to panic on any mutating envelope sent during standard `make test-int`.

**Tech Stack:** Go 1.26.2, `github.com/iainmoffat/sophosfw` module, cobra, lipgloss, testify, modelcontextprotocol/go-sdk v1.5.0. No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-01-sophosfw-phase6-design.md`](../specs/2026-05-01-sophosfw-phase6-design.md)

**Predecessor:** Phase 5, tagged `v0.4.0-phase5` on `main` (commit `09638d2`).

---

## Conventions

- **Module:** `github.com/iainmoffat/sophosfw`. Working dir: `/Users/ipm/code/sophosfw`.
- **No Co-Authored-By trailer** on any commit (`git log HEAD -1 --pretty=full | grep -i co-auth` should return nothing after each commit).
- **Single passing commit per task**: the test suite (`go test ./... -count=1`) passes at every commit.
- **SDK alias**: `sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"`.
- **Canonical skill files** in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` are NOT committed in the sophosfw repo (foundation T30 pattern). T11 makes those edits but commits only the sophosfw-side changes (skill-doctor expansion).
- Push to origin after the phase tag is set.

---

## Task 1: Audit log

**Files:**
- Create: `internal/svc/audit.go`
- Create: `internal/svc/audit_test.go`
- Modify: `internal/config/config.go` (add `Defaults.AuditLog *bool` + accessor)

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/audit_test.go`:

```go
package svc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditLog_AppendsLine(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, true)
	require.NoError(t, a.Write(AuditEntry{
		Profile:    "home",
		Operation:  "create",
		ObjectType: "IPHost",
		ObjectName: "LAN-network",
		Result:     "ok",
	}))
	body, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(string(body), "\n"))
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	require.Len(t, lines, 1)
	var got AuditEntry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &got))
	require.Equal(t, "home", got.Profile)
	require.Equal(t, "create", got.Operation)
	require.Equal(t, "IPHost", got.ObjectType)
	require.Equal(t, "LAN-network", got.ObjectName)
	require.Equal(t, "ok", got.Result)
	require.NotEmpty(t, got.Timestamp)
}

func TestAuditLog_Disabled(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, false)
	require.NoError(t, a.Write(AuditEntry{Profile: "home", Operation: "create"}))
	_, err := os.Stat(filepath.Join(dir, "audit.log"))
	require.True(t, os.IsNotExist(err), "audit.log must not be created when disabled")
}

func TestAuditLog_FileMode(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, true)
	require.NoError(t, a.Write(AuditEntry{Profile: "home", Operation: "create"}))
	info, err := os.Stat(filepath.Join(dir, "audit.log"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestAuditLog_Concurrent(t *testing.T) {
	dir := t.TempDir()
	a := NewAuditLog(dir, true)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = a.Write(AuditEntry{Profile: "home", Operation: "create"})
		}()
	}
	wg.Wait()
	body, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	require.Len(t, lines, 100)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestAuditLog -v
```
Expected: FAIL — `undefined: NewAuditLog`, `undefined: AuditEntry`.

- [ ] **Step 3: Implement `internal/svc/audit.go`**

```go
package svc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry is one append-only line in ~/.config/sophosfw/audit.log.
// Single line of compact JSON; line-oriented log for grep-ability.
type AuditEntry struct {
	Timestamp        string `json:"timestamp"`
	Profile          string `json:"profile"`
	Operation        string `json:"operation"`        // create | update | delete | raw_apply | raw_apply_mutating
	ObjectType       string `json:"objectType"`       // IPHost | raw
	ObjectName       string `json:"objectName,omitempty"`
	ExpectedDiffHash string `json:"expectedDiffHash,omitempty"`
	RedactedXML      string `json:"redactedXml,omitempty"`
	Result           string `json:"result"`           // ok | error:<kind>
	ErrorMessage     string `json:"errorMessage,omitempty"`
}

// AuditLog is a thread-safe append-only writer to <baseDir>/audit.log
// (mode 0600). Construct via NewAuditLog. When enabled=false, Write is a no-op
// and the file is never created.
type AuditLog struct {
	path    string
	enabled bool
	mu      sync.Mutex
}

func NewAuditLog(baseDir string, enabled bool) *AuditLog {
	return &AuditLog{
		path:    filepath.Join(baseDir, "audit.log"),
		enabled: enabled,
	}
}

func (a *AuditLog) Write(entry AuditEntry) error {
	if a == nil || !a.enabled {
		return nil
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Modify `internal/config/config.go`**

Find the `Defaults` struct:
```go
type Defaults struct {
	Output             string        `yaml:"output"`
	Timeout            time.Duration `yaml:"timeout"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
}
```

Replace with:
```go
type Defaults struct {
	Output             string        `yaml:"output"`
	Timeout            time.Duration `yaml:"timeout"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
	AuditLog           *bool         `yaml:"auditLog,omitempty"` // pointer: nil = default-on
}
```

Add a new accessor at the end of the file (before the `DefaultBaseDir` function or after `ActiveProfile`):
```go
// AuditLogEnabled reports whether mutation audit logging should write to
// ~/.config/sophosfw/audit.log. Default: true. Set defaults.auditLog: false
// in config.yaml to disable.
func (c *Config) AuditLogEnabled() bool {
	if c == nil || c.Defaults.AuditLog == nil {
		return true
	}
	return *c.Defaults.AuditLog
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/svc -run TestAuditLog -v
go test ./... -count=1
```
Expected: PASS for the 4 audit tests + all existing tests still passing.

- [ ] **Step 6: Commit**

```bash
git add internal/svc/audit.go internal/svc/audit_test.go internal/config/config.go
git commit -m "feat(svc): append-only audit log for mutating operations"
```

Verify no Co-Authored-By:
```bash
git log HEAD -1 --pretty=full | grep -i co-auth || echo "ok"
```

---

## Task 2: Diff hash

**Files:**
- Create: `internal/svc/diffhash.go`
- Create: `internal/svc/diffhash_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/diffhash_test.go`:

```go
package svc

import (
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/stretchr/testify/require"
)

func TestDiffHash_StableForSameInput(t *testing.T) {
	h1 := catalog.IPHost{
		Name: "LAN-network", IPFamily: "IPv4", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}
	h2 := catalog.IPHost{
		Name: "LAN-network", IPFamily: "IPv4", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}
	got1, err := DiffHash(h1)
	require.NoError(t, err)
	got2, err := DiffHash(h2)
	require.NoError(t, err)
	require.Equal(t, got1, got2)
	require.Len(t, got1, 64) // hex-encoded SHA-256
}

func TestDiffHash_DifferentForDifferentInput(t *testing.T) {
	h1 := catalog.IPHost{Name: "A", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	h2 := catalog.IPHost{Name: "A", IPFamily: "IPv4", HostType: "IP", IPAddress: "2.2.2.2"}
	got1, _ := DiffHash(h1)
	got2, _ := DiffHash(h2)
	require.NotEqual(t, got1, got2)
}

func TestDiffHash_KeyOrderingInvariant(t *testing.T) {
	// Two map[string]any with identical content but different insertion order
	// must produce the same hash.
	a := map[string]any{"Name": "X", "IPAddress": "1.1.1.1", "HostType": "IP"}
	b := map[string]any{"HostType": "IP", "IPAddress": "1.1.1.1", "Name": "X"}
	ha, _ := DiffHash(a)
	hb, _ := DiffHash(b)
	require.Equal(t, ha, hb)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestDiffHash -v
```
Expected: FAIL — `undefined: DiffHash`.

- [ ] **Step 3: Implement `internal/svc/diffhash.go`**

```go
package svc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// DiffHash returns a stable hex-encoded SHA-256 over the canonical JSON
// serialization of the given typed record. Used by host_ip_update / delete
// (and future mutation paths) to detect concurrent firewall drift between
// the agent's read and the agent's write.
//
// Stability: keys are sorted alphabetically; values are encoded with
// json.Marshal (Go's default). Adding a new field to a typed record
// changes the hash for all existing records — that's intentional;
// callers re-fetch and recompute when the schema evolves.
func DiffHash(record any) (string, error) {
	canonical, err := canonicalize(record)
	if err != nil {
		return "", fmt.Errorf("diffhash: canonicalize: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalize(record any) ([]byte, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return marshalSorted(m)
}

func marshalSorted(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		kb, _ := json.Marshal(k)
		out = append(out, kb...)
		out = append(out, ':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		out = append(out, vb...)
	}
	out = append(out, '}')
	return out, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run TestDiffHash -v
go test ./... -count=1
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/svc/diffhash.go internal/svc/diffhash_test.go
git commit -m "feat(svc): DiffHash for optimistic-concurrency drift detection"
```

---

## Task 3: Sophos envelope builders

**Files:**
- Modify: `internal/sophos/request.go` (append `BuildSetEnvelope` and `BuildRemoveEnvelope`)
- Create: `internal/sophos/request_set_remove_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sophos/request_set_remove_test.go`:

```go
package sophos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildSetEnvelope_AddOperation(t *testing.T) {
	inner := []byte(`<IPHost><Name>X</Name><HostType>IP</HostType><IPAddress>1.1.1.1</IPAddress></IPHost>`)
	out, err := BuildSetEnvelope("add", inner, "u", "p")
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "<Request>")
	require.Contains(t, s, "<Login>")
	require.Contains(t, s, "<Username>u</Username>")
	require.Contains(t, s, `<Set operation="add">`)
	require.Contains(t, s, "<IPHost>")
	require.Contains(t, s, "<Name>X</Name>")
	require.Contains(t, s, "</Set>")
	require.True(t, strings.HasSuffix(strings.TrimSpace(s), "</Request>"))
}

func TestBuildSetEnvelope_UpdateOperation(t *testing.T) {
	inner := []byte(`<IPHost><Name>X</Name></IPHost>`)
	out, err := BuildSetEnvelope("update", inner, "u", "p")
	require.NoError(t, err)
	require.Contains(t, string(out), `<Set operation="update">`)
}

func TestBuildSetEnvelope_RejectsUnknownOperation(t *testing.T) {
	_, err := BuildSetEnvelope("delete", []byte(`<IPHost/>`), "u", "p")
	require.Error(t, err)
}

func TestBuildRemoveEnvelope_WrapsInner(t *testing.T) {
	inner := []byte(`<IPHost><Name>X</Name></IPHost>`)
	out, err := BuildRemoveEnvelope(inner, "u", "p")
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "<Request>")
	require.Contains(t, s, "<Remove>")
	require.Contains(t, s, "<IPHost>")
	require.Contains(t, s, "<Name>X</Name>")
	require.Contains(t, s, "</Remove>")
	require.True(t, strings.HasSuffix(strings.TrimSpace(s), "</Request>"))
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/sophos -run "TestBuildSetEnvelope|TestBuildRemoveEnvelope" -v
```

- [ ] **Step 3: Append to `internal/sophos/request.go`**

Append (after the existing `BuildRawEnvelope` function, before `writeLogin`):

```go
// BuildSetEnvelope wraps inner XML in a <Set operation="add|update"> within
// the standard Sophos <Request><Login>...</Login>...</Request> envelope.
// `operation` must be "add" or "update". `inner` is the body that goes
// inside <Set>...</Set>, e.g. `<IPHost>...</IPHost>`.
func BuildSetEnvelope(operation string, inner []byte, username, password string) ([]byte, error) {
	if operation != "add" && operation != "update" {
		return nil, fmt.Errorf("BuildSetEnvelope: operation must be \"add\" or \"update\", got %q", operation)
	}
	var buf bytes.Buffer
	buf.WriteString("<Request>")
	if err := writeLogin(&buf, username, password); err != nil {
		return nil, err
	}
	buf.WriteString(`<Set operation="`)
	buf.WriteString(operation)
	buf.WriteString(`">`)
	buf.Write(inner)
	buf.WriteString("</Set>")
	buf.WriteString("</Request>")
	return buf.Bytes(), nil
}

// BuildRemoveEnvelope wraps inner XML in a <Remove>...</Remove>.
func BuildRemoveEnvelope(inner []byte, username, password string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<Request>")
	if err := writeLogin(&buf, username, password); err != nil {
		return nil, err
	}
	buf.WriteString("<Remove>")
	buf.Write(inner)
	buf.WriteString("</Remove>")
	buf.WriteString("</Request>")
	return buf.Bytes(), nil
}
```

(The file already imports `bytes` and `fmt` for the existing helpers; no new imports needed.)

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/sophos -count=1
```
Expected: PASS for the 4 new tests + all existing sophos tests.

- [ ] **Step 5: Commit**

```bash
git add internal/sophos/request.go internal/sophos/request_set_remove_test.go
git commit -m "feat(sophos): BuildSetEnvelope and BuildRemoveEnvelope for mutation paths"
```

---

## Task 4: Catalog `Mutable` field

**Files:**
- Modify: `internal/catalog/catalog.go` (add `Mutable bool` to `Entry`)
- Modify: `internal/catalog/objects.yaml` (add `mutable: true` to IPHost)
- Modify: `internal/render/envelope.go` (`ObjectSchemaEnvelope` includes `mutable`)
- Modify: `internal/catalog/catalog_test.go` (one test for the new field)

- [ ] **Step 1: Add `Mutable` to the Entry struct**

In `internal/catalog/catalog.go`, find the `Entry` struct:

```go
type Entry struct {
	Tag         string   `yaml:"tag"`
	Aliases     []string `yaml:"aliases,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Columns     []string `yaml:"columns,omitempty"`
	Filterable  []string `yaml:"filterable,omitempty"`
	UsageTag    string   `yaml:"usageTag,omitempty"`
	TypedParser string   `yaml:"typedParser,omitempty"`
}
```

Append the field:

```go
type Entry struct {
	Tag         string   `yaml:"tag"`
	Aliases     []string `yaml:"aliases,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Columns     []string `yaml:"columns,omitempty"`
	Filterable  []string `yaml:"filterable,omitempty"`
	UsageTag    string   `yaml:"usageTag,omitempty"`
	TypedParser string   `yaml:"typedParser,omitempty"`
	Mutable     bool     `yaml:"mutable,omitempty"` // Phase 6: only IPHost; defaults false
}
```

- [ ] **Step 2: Update `internal/catalog/objects.yaml` IPHost entry**

Find:
```yaml
  - tag: IPHost
    aliases: [host-ip, ip-host]
    description: "IP host objects (single addresses, ranges, networks)"
    columns: [Name, IPFamily, HostType, IPAddress, Subnet]
    filterable: [Name, IPAddress, IPFamily, HostType]
    usageTag: IPHostStatistics
    typedParser: iphost
```

Append one line:
```yaml
  - tag: IPHost
    aliases: [host-ip, ip-host]
    description: "IP host objects (single addresses, ranges, networks)"
    columns: [Name, IPFamily, HostType, IPAddress, Subnet]
    filterable: [Name, IPAddress, IPFamily, HostType]
    usageTag: IPHostStatistics
    typedParser: iphost
    mutable: true
```

- [ ] **Step 3: Update `internal/render/envelope.go` `ObjectSchemaEnvelope`**

Find this function:
```go
func ObjectSchemaEnvelope(e *catalog.Entry) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.objectSchema", map[string]any{
		"tag":         e.Tag,
		"aliases":     e.Aliases,
		"description": e.Description,
		"columns":     e.Columns,
		"filterable":  e.Filterable,
		"usageTag":    e.UsageTag,
		"typedParser": e.TypedParser,
	})
}
```

Add `mutable` key:
```go
func ObjectSchemaEnvelope(e *catalog.Entry) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.objectSchema", map[string]any{
		"tag":         e.Tag,
		"aliases":     e.Aliases,
		"description": e.Description,
		"columns":     e.Columns,
		"filterable":  e.Filterable,
		"usageTag":    e.UsageTag,
		"typedParser": e.TypedParser,
		"mutable":     e.Mutable,
	})
}
```

- [ ] **Step 4: Add a catalog test**

Append to `internal/catalog/catalog_test.go`:

```go
func TestCatalog_IPHostMutable(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	entry, ok := c.Resolve("IPHost")
	require.True(t, ok)
	require.True(t, entry.Mutable, "IPHost should be marked mutable in Phase 6")
}

func TestCatalog_OtherEntriesNotMutable(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	for _, tag := range []string{"FQDNHost", "MACHost", "Zone", "FirewallRule", "NATRule", "Services"} {
		entry, ok := c.Resolve(tag)
		require.True(t, ok, "tag %q should exist", tag)
		require.False(t, entry.Mutable, "tag %q must NOT be mutable in Phase 6", tag)
	}
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/catalog ./internal/render -count=1 -v
go test ./... -count=1
```
Expected: PASS. Existing render tests are byte-exact assertions on JSON output; the new `mutable` field is included in `ObjectSchemaEnvelope` so any existing test that asserts on its output may need a one-line update. If the existing `TestObjectSchemaEnvelope` test (if present) fails because of the new field, update its expected substring assertion to include `"mutable": false` or `"mutable": true` as appropriate.

- [ ] **Step 6: Commit**

```bash
git add internal/catalog/catalog.go internal/catalog/objects.yaml internal/catalog/catalog_test.go internal/render/envelope.go
git commit -m "feat(catalog): Mutable field; IPHost flagged mutable for Phase 6"
```

---

## Task 5: `HostIPSvc.Create` (validate, pre-flight, dry-run, apply, audit)

**Files:**
- Modify: `internal/svc/hostip.go` (add `HostIPCreateInput`, `HostIPMutationResult`, `validateHostIPCreate`, `marshalIPHost`, `Create` method, `Audit` field)
- Create: `internal/svc/hostip_create_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/hostip_create_test.go`:

```go
package svc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// fakeMutClient records sent envelopes and returns a canned response.
type fakeMutClient struct {
	sentEnvelopes [][]byte
	body          map[string][]json.RawMessage
}

func (f *fakeMutClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	// Build a placeholder envelope so tests can verify Set/Remove was attempted.
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		// Mutation path uses DoRaw, not Do. Refetch path uses Do.
		// Refetch returns the canned body keyed by "IPHost".
		if recs, ok := f.body["IPHost"]; ok {
			resp.Body["IPHost"] = recs
		}
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (f *fakeMutClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sentEnvelopes = append(f.sentEnvelopes, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newCreateTestSvc(t *testing.T, readOnly bool, refetched []json.RawMessage) (*HostIPSvc, *fakeMutClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444", ReadOnly: readOnly})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	body := map[string][]json.RawMessage{"IPHost": refetched}
	fc := &fakeMutClient{body: body}
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
	}
	return &HostIPSvc{Inner: inner, Audit: audit}, fc, auditDir
}

func TestHostIPSvc_Create_DryRun(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, false, nil)
	out, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}, true)
	require.NoError(t, err)
	require.True(t, out.DryRun)
	require.NotNil(t, out.Preview)
	require.True(t, out.Preview.Mutating)
	require.Contains(t, out.Preview.Verbs, "Set:add")
	require.Empty(t, fc.sentEnvelopes, "dry-run must not send the envelope")
}

func TestHostIPSvc_Create_Apply(t *testing.T) {
	refetched := []json.RawMessage{json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)}
	s, fc, auditDir := newCreateTestSvc(t, false, refetched)
	out, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	}, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.NotNil(t, out.Item)
	require.Equal(t, "LAN-network", out.Item.Name)
	require.Len(t, fc.sentEnvelopes, 1)
	require.Contains(t, string(fc.sentEnvelopes[0]), `<Set operation="add">`)

	// Audit log entry written
	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"create"`)
	require.Contains(t, string(body), `"objectName":"LAN-network"`)
	require.Contains(t, string(body), `"result":"ok"`)
}

func TestHostIPSvc_Create_RejectedOnReadOnlyProfile(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, true, nil)
	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "IP", IPAddress: "1.1.1.1",
	}, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation), "expected ErrReadOnlyViolation, got %v", err)
	require.Empty(t, fc.sentEnvelopes, "read-only pre-flight must reject before any send")
}

func TestHostIPSvc_Create_ValidationFailure_NetworkMissingSubnet(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, false, nil)
	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "Network", IPAddress: "10.0.0.0",
		// Subnet missing
	}, true)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
	require.True(t, strings.Contains(err.Error(), "Subnet"))
	require.Empty(t, fc.sentEnvelopes)
}

func TestHostIPSvc_Create_ValidationFailure_BadHostType(t *testing.T) {
	s, _, _ := newCreateTestSvc(t, false, nil)
	_, err := s.Create(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "Bogus",
	}, true)
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestHostIPSvc_Create -v
```
Expected: FAIL — `undefined: HostIPCreateInput`, `Create` method missing, `Audit` field missing.

- [ ] **Step 3: Modify `internal/svc/hostip.go` — add types, Audit field, methods**

Find the existing `HostIPSvc` struct:
```go
type HostIPSvc struct {
	Inner *ObjectSvc
}
```

Replace with:
```go
type HostIPSvc struct {
	Inner *ObjectSvc
	Audit *AuditLog // optional; nil = no audit logging (Write is a no-op anyway)
}
```

At the end of the file, append:

```go
// HostIPCreateInput is the validated input for HostIPSvc.Create / Update.
type HostIPCreateInput struct {
	Name           string
	IPFamily       string // "IPv4" or "IPv6"; default "IPv4" if empty
	HostType       string // "Network" | "IP" | "IPRange" | "IPList"
	IPAddress      string
	Subnet         string
	StartIPAddress string
	EndIPAddress   string
	IPAddressList  string
}

// HostIPMutationResult is the render-friendly result of a successful
// mutation (or the dry-run preview of one).
type HostIPMutationResult struct {
	Profile   string
	Operation string // "create" | "update" | "delete"
	Name      string
	DryRun    bool
	Preview   *Preview // populated when DryRun=true
	Item      *HostIP  // populated when applied; re-fetched post-write
}

// validateHostIPCreate checks per-HostType required fields. Server-side
// semantics (e.g. CIDR validity, IP range ordering) are NOT checked here;
// Sophos rejects those. We only catch missing-required-field cases.
func validateHostIPCreate(in HostIPCreateInput) error {
	if in.Name == "" {
		return fmt.Errorf("%w: --name is required", sophos.ErrInvalidRequest)
	}
	switch in.HostType {
	case "Network":
		if in.IPAddress == "" || in.Subnet == "" {
			return fmt.Errorf("%w: HostType=Network requires --ip-address and --subnet", sophos.ErrInvalidRequest)
		}
	case "IP":
		if in.IPAddress == "" {
			return fmt.Errorf("%w: HostType=IP requires --ip-address", sophos.ErrInvalidRequest)
		}
	case "IPRange":
		if in.StartIPAddress == "" || in.EndIPAddress == "" {
			return fmt.Errorf("%w: HostType=IPRange requires --start-ip and --end-ip", sophos.ErrInvalidRequest)
		}
	case "IPList":
		if in.IPAddressList == "" {
			return fmt.Errorf("%w: HostType=IPList requires --ip-list", sophos.ErrInvalidRequest)
		}
	default:
		return fmt.Errorf("%w: unknown HostType %q (expected Network|IP|IPRange|IPList)", sophos.ErrInvalidRequest, in.HostType)
	}
	if in.IPFamily != "" && in.IPFamily != "IPv4" && in.IPFamily != "IPv6" {
		return fmt.Errorf("%w: IPFamily must be IPv4 or IPv6", sophos.ErrInvalidRequest)
	}
	return nil
}

// marshalIPHost emits the inner XML for a Set/Remove envelope. Fields are
// emitted only when non-empty. The order matches Sophos's typical
// representation (Name first, then HostType, IPFamily, then type-specific
// fields).
func marshalIPHost(in HostIPCreateInput) []byte {
	family := in.IPFamily
	if family == "" {
		family = "IPv4"
	}
	var b strings.Builder
	b.WriteString("<IPHost>")
	b.WriteString("<Name>")
	xml.EscapeText(&b, []byte(in.Name))
	b.WriteString("</Name>")
	b.WriteString("<HostType>")
	xml.EscapeText(&b, []byte(in.HostType))
	b.WriteString("</HostType>")
	b.WriteString("<IPFamily>")
	xml.EscapeText(&b, []byte(family))
	b.WriteString("</IPFamily>")
	if in.IPAddress != "" {
		b.WriteString("<IPAddress>")
		xml.EscapeText(&b, []byte(in.IPAddress))
		b.WriteString("</IPAddress>")
	}
	if in.Subnet != "" {
		b.WriteString("<Subnet>")
		xml.EscapeText(&b, []byte(in.Subnet))
		b.WriteString("</Subnet>")
	}
	if in.StartIPAddress != "" {
		b.WriteString("<StartIPAddress>")
		xml.EscapeText(&b, []byte(in.StartIPAddress))
		b.WriteString("</StartIPAddress>")
	}
	if in.EndIPAddress != "" {
		b.WriteString("<EndIPAddress>")
		xml.EscapeText(&b, []byte(in.EndIPAddress))
		b.WriteString("</EndIPAddress>")
	}
	if in.IPAddressList != "" {
		b.WriteString("<IPAddressList>")
		xml.EscapeText(&b, []byte(in.IPAddressList))
		b.WriteString("</IPAddressList>")
	}
	b.WriteString("</IPHost>")
	return []byte(b.String())
}

// Create issues <Set operation="add"><IPHost>...</IPHost></Set>.
//   - dryRun=true: validate, build envelope, return Preview, NO wire call.
//   - dryRun=false: validate, pre-flight read-only check, build, send,
//     audit-log, refetch (one Do call to get the post-write state).
func (s *HostIPSvc) Create(ctx context.Context, profileName string, input HostIPCreateInput, dryRun bool) (*HostIPMutationResult, error) {
	return s.mutate(ctx, profileName, "create", input.Name, input, "", false, dryRun)
}

// mutate is the shared implementation of Create/Update/Delete. operation is
// "create"|"update"|"delete". For delete, input is zeroed (only Name used).
// expectedHash and ignoreHash apply only to update/delete.
func (s *HostIPSvc) mutate(
	ctx context.Context,
	profileName, operation, name string,
	input HostIPCreateInput,
	expectedHash string,
	ignoreHash bool,
	dryRun bool,
) (*HostIPMutationResult, error) {
	// 1. Resolve profile + read-only pre-flight check.
	profile, profName, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, profName)
	}

	// 2. Catalog mutable check.
	entry, ok := s.Inner.Catalog.Resolve("IPHost")
	if !ok || !entry.Mutable {
		return nil, fmt.Errorf("%w: IPHost is not marked mutable in the catalog", ErrUnsupportedInPhase)
	}

	// 3. For create/update, validate the input.
	if operation != "delete" {
		if err := validateHostIPCreate(input); err != nil {
			return nil, err
		}
	} else if name == "" {
		return nil, fmt.Errorf("%w: --name is required for delete", sophos.ErrInvalidRequest)
	}

	// 4. For update/delete, fetch and check diff hash.
	if operation == "update" || operation == "delete" {
		if expectedHash == "" && !ignoreHash {
			return nil, fmt.Errorf("%w: expectedDiffHash is required for %s (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest, operation)
		}
		if !ignoreHash {
			current, getErr := s.Get(ctx, profileName, name)
			if getErr != nil {
				return nil, getErr
			}
			gotHash, hashErr := DiffHash(current.IPHost) // hash the raw catalog.IPHost, not svc.HostIP
			if hashErr != nil {
				return nil, hashErr
			}
			if gotHash != expectedHash {
				return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, gotHash, expectedHash)
			}
		}
	}

	// 5. Build the envelope.
	c, credsErr := s.Inner.Creds.Load(profName)
	if credsErr != nil {
		return nil, credsErr
	}
	var (
		full     []byte
		envelopeErr error
	)
	switch operation {
	case "create":
		full, envelopeErr = sophos.BuildSetEnvelope("add", marshalIPHost(input), c.Username, c.Password)
	case "update":
		full, envelopeErr = sophos.BuildSetEnvelope("update", marshalIPHost(input), c.Username, c.Password)
	case "delete":
		inner := []byte("<IPHost><Name>" + name + "</Name></IPHost>")
		full, envelopeErr = sophos.BuildRemoveEnvelope(inner, c.Username, c.Password)
	}
	if envelopeErr != nil {
		return nil, envelopeErr
	}

	// 6. Compute audit-log fields used by both branches.
	auditEntry := AuditEntry{
		Profile:     profName,
		Operation:   operation,
		ObjectType:  "IPHost",
		ObjectName:  name,
		RedactedXML: string(safetyRedact(full)),
	}
	if expectedHash != "" {
		auditEntry.ExpectedDiffHash = expectedHash
	}
	if ignoreHash {
		auditEntry.ExpectedDiffHash = "ignored"
	}

	// 7. Dry-run path.
	if dryRun {
		mutating, verbs := safetyIsMutating(full)
		pv := &Preview{
			Profile:        profName,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    auditEntry.RedactedXML,
			WouldSendBytes: len(full),
		}
		auditEntry.Result = "ok (dry-run)"
		_ = s.Audit.Write(auditEntry)
		return &HostIPMutationResult{
			Profile: profName, Operation: operation, Name: name,
			DryRun: true, Preview: pv,
		}, nil
	}

	// 8. Apply path: send the envelope.
	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		auditEntry.Result = "error:" + ErrorKind(sendErr)
		auditEntry.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(auditEntry)
		return nil, sendErr
	}
	auditEntry.Result = "ok"
	_ = s.Audit.Write(auditEntry)

	// 9. For create/update, re-fetch to return the post-write state.
	if operation == "delete" {
		return &HostIPMutationResult{
			Profile: profName, Operation: operation, Name: name, DryRun: false,
		}, nil
	}
	item, fetchErr := s.Get(ctx, profileName, name)
	if fetchErr != nil {
		// Mutation succeeded but re-fetch failed; return success with no Item.
		return &HostIPMutationResult{
			Profile: profName, Operation: operation, Name: name, DryRun: false,
		}, nil
	}
	return &HostIPMutationResult{
		Profile: profName, Operation: operation, Name: name, DryRun: false,
		Item: item,
	}, nil
}

// safetyIsMutating and safetyRedact are tiny indirections so this file
// doesn't need to import the safety package directly. They forward to the
// real helpers; if the implementer prefers a direct import they can
// inline these.
func safetyIsMutating(xml []byte) (bool, []string) { return safety.IsMutating(xml) }
func safetyRedact(xml []byte) []byte               { return safety.RedactXML(xml) }
```

Update the existing imports at the top of `internal/cli/hostip.go`... wait, that's the cli file. The svc file. Update imports at the top of `internal/svc/hostip.go`:

```go
import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)
```

(`encoding/xml`, `safety` are new. `errors`, `net` may already be present from earlier work.)

The plan adds a new sentinel `ErrDiffHashMismatch` and `ErrDiffHashRequired`. Add to the same file (or a sibling errors_kind.go file — pick whichever the implementer thinks cleaner; this plan assumes svc/errors_kind.go from Phase 4 T2 already exists):

In `internal/svc/errors_kind.go`, add new sentinels and update the switch:

```go
// New sentinels for Phase 6 mutation paths.
var (
	ErrDiffHashMismatch = errors.New("diff hash mismatch: object has changed since you last read it")
	ErrDiffHashRequired = errors.New("expectedDiffHash is required for update/delete")
)
```

In the `ErrorKind` switch, add cases:

```go
	case errors.Is(err, ErrDiffHashMismatch):
		return "diff_hash_mismatch"
	case errors.Is(err, ErrDiffHashRequired):
		return "invalid_request"
```

Also update `internal/cli/errors.go` `ExitCodeFor`:

```go
case "diff_hash_mismatch":
	return 7
```

(Foundation defines exit codes 0-6; Phase 6 adds 7.)

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run TestHostIPSvc_Create -v
go test ./... -count=1
```
Expected: PASS for the 5 Create tests. Existing tests stay green.

- [ ] **Step 5: Commit**

```bash
git add internal/svc/hostip.go internal/svc/hostip_create_test.go internal/svc/errors_kind.go internal/cli/errors.go
git commit -m "feat(svc): HostIPSvc.Create with validation, pre-flight, dry-run, audit"
```

---

## Task 6: `HostIPSvc.Update` and `Delete` (with diff hash)

**Files:**
- Modify: `internal/svc/hostip.go` (add Update, Delete public methods that delegate to mutate)
- Create: `internal/svc/hostip_update_delete_test.go`

T5's `mutate` helper already supports update and delete via the `operation` parameter. T6 adds the public methods plus the test cases that exercise the diff-hash paths.

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/hostip_update_delete_test.go`:

```go
package svc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/stretchr/testify/require"
)

func TestHostIPSvc_Update_DiffHashMatch_Applies(t *testing.T) {
	current := json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)
	s, fc, auditDir := newCreateTestSvc(t, false, []json.RawMessage{current})

	// Compute the expected hash from the same record shape.
	hash, err := DiffHash(catalog.IPHost{
		Name: "LAN-network", IPFamily: "IPv4", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.255.0",
	})
	require.NoError(t, err)

	out, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.252.0", // changed mask
	}, hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Len(t, fc.sentEnvelopes, 1)
	require.Contains(t, string(fc.sentEnvelopes[0]), `<Set operation="update">`)

	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"update"`)
	require.Contains(t, string(body), `"expectedDiffHash":"`+hash+`"`)
	require.Contains(t, string(body), `"result":"ok"`)
}

func TestHostIPSvc_Update_DiffHashMismatch(t *testing.T) {
	current := json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)
	s, fc, _ := newCreateTestSvc(t, false, []json.RawMessage{current})
	_, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "LAN-network", HostType: "Network",
		IPAddress: "10.0.0.0", Subnet: "255.255.252.0",
	}, "definitely-wrong-hash-0000000000000000000000000000000000000000", false, false)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrDiffHashMismatch))
	require.Empty(t, fc.sentEnvelopes, "mismatch must reject before any send")
}

func TestHostIPSvc_Update_RequiresExpectedHash_WhenNotIgnored(t *testing.T) {
	current := json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)
	s, fc, _ := newCreateTestSvc(t, false, []json.RawMessage{current})
	_, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "IP", IPAddress: "1.1.1.1",
	}, "", false, false) // empty hash, ignore=false
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expectedDiffHash"))
	require.Empty(t, fc.sentEnvelopes)
}

func TestHostIPSvc_Update_IgnoreHash_AppliesWithoutFetch(t *testing.T) {
	s, fc, auditDir := newCreateTestSvc(t, false, []json.RawMessage{
		json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`),
	})
	_, err := s.Update(context.Background(), "home", HostIPCreateInput{
		Name: "X", HostType: "IP", IPAddress: "9.9.9.9",
	}, "", true, false) // ignoreHash=true
	require.NoError(t, err)
	require.Len(t, fc.sentEnvelopes, 1)

	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"expectedDiffHash":"ignored"`)
}

func TestHostIPSvc_Delete_DiffHashRequired(t *testing.T) {
	s, fc, _ := newCreateTestSvc(t, false, []json.RawMessage{
		json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`),
	})
	_, err := s.Delete(context.Background(), "home", "X", "", false, false)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expectedDiffHash"))
	require.Empty(t, fc.sentEnvelopes)
}

func TestHostIPSvc_Delete_Apply(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, err := DiffHash(current)
	require.NoError(t, err)
	s, fc, auditDir := newCreateTestSvc(t, false, []json.RawMessage{
		json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`),
	})
	out, err := s.Delete(context.Background(), "home", "X", hash, false, false)
	require.NoError(t, err)
	require.False(t, out.DryRun)
	require.Len(t, fc.sentEnvelopes, 1)
	require.Contains(t, string(fc.sentEnvelopes[0]), `<Remove>`)

	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"delete"`)
	require.Contains(t, string(body), `"objectName":"X"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run "TestHostIPSvc_Update|TestHostIPSvc_Delete" -v
```

- [ ] **Step 3: Add `Update` and `Delete` public methods to `internal/svc/hostip.go`**

Append to the bottom of `internal/svc/hostip.go`:

```go
// Update issues <Set operation="update"><IPHost>...</IPHost></Set>. Requires
// expectedHash unless ignoreHash=true. Compares against the current record's
// hash; mismatch returns ErrDiffHashMismatch.
func (s *HostIPSvc) Update(
	ctx context.Context,
	profileName string,
	input HostIPCreateInput,
	expectedHash string,
	ignoreHash bool,
	dryRun bool,
) (*HostIPMutationResult, error) {
	return s.mutate(ctx, profileName, "update", input.Name, input, expectedHash, ignoreHash, dryRun)
}

// Delete issues <Remove><IPHost><Name>X</Name></IPHost></Remove>. Same hash
// semantics as Update.
func (s *HostIPSvc) Delete(
	ctx context.Context,
	profileName, name, expectedHash string,
	ignoreHash, dryRun bool,
) (*HostIPMutationResult, error) {
	return s.mutate(ctx, profileName, "delete", name, HostIPCreateInput{Name: name}, expectedHash, ignoreHash, dryRun)
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run "TestHostIPSvc_Update|TestHostIPSvc_Delete" -v
go test ./... -count=1
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/svc/hostip.go internal/svc/hostip_update_delete_test.go
git commit -m "feat(svc): HostIPSvc.Update and Delete with diff hash check"
```

---

## Task 7: `RawSvc.Apply` real implementation

**Files:**
- Modify: `internal/svc/raw.go` (replace ErrUnsupportedInPhase stub with real impl; add Audit field)
- Create: `internal/svc/raw_apply_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/raw_apply_test.go`:

```go
package svc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func newRawApplyTestSvc(t *testing.T, readOnly bool, sendErr error) (*RawSvc, *fakeMutClient, string) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444", ReadOnly: readOnly})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	auditDir := t.TempDir()
	audit := NewAuditLog(auditDir, true)
	fc := &fakeMutClient{}
	if sendErr != nil {
		fc.sendErr = sendErr
	}
	_ = cat
	return &RawSvc{
		Config: cfg, Creds: store,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fc },
		Audit:     audit,
	}, fc, auditDir
}

func TestRawSvc_Apply_Success(t *testing.T) {
	s, fc, auditDir := newRawApplyTestSvc(t, false, nil)
	body := []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`)
	require.NoError(t, s.Apply(context.Background(), "home", body))
	require.Len(t, fc.sentEnvelopes, 1)

	logBody, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(logBody), `"operation":"raw_apply_mutating"`)
	require.Contains(t, string(logBody), `"result":"ok"`)
}

func TestRawSvc_Apply_NonMutating_LogsRawApply(t *testing.T) {
	s, _, auditDir := newRawApplyTestSvc(t, false, nil)
	body := []byte(`<Get><IPHost></IPHost></Get>`)
	require.NoError(t, s.Apply(context.Background(), "home", body))
	logBody, _ := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.Contains(t, string(logBody), `"operation":"raw_apply"`)
}

func TestRawSvc_Apply_RejectedOnReadOnlyProfile(t *testing.T) {
	s, fc, _ := newRawApplyTestSvc(t, true, nil)
	err := s.Apply(context.Background(), "home", []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`))
	require.Error(t, err)
	require.True(t, errors.Is(err, sophos.ErrReadOnlyViolation))
	require.Empty(t, fc.sentEnvelopes)
}

func TestRawSvc_Apply_AuditLoggedOnFailure(t *testing.T) {
	s, _, auditDir := newRawApplyTestSvc(t, false, sophos.ErrServerError)
	body := []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`)
	err := s.Apply(context.Background(), "home", body)
	require.Error(t, err)
	logBody, _ := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.Contains(t, string(logBody), `"result":"error:server_error"`)
}
```

The `fakeMutClient` type from T5's test file gets a `sendErr error` field; if non-nil, `DoRaw` returns it. Add this field by editing the existing struct in `internal/svc/hostip_create_test.go`:

```go
type fakeMutClient struct {
	sentEnvelopes [][]byte
	body          map[string][]json.RawMessage
	sendErr       error // NEW: simulate a send failure
}

func (f *fakeMutClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sentEnvelopes = append(f.sentEnvelopes, raw)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sophos.Response{LoginOK: true}, nil
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestRawSvc_Apply -v
```

- [ ] **Step 3: Modify `internal/svc/raw.go`**

Find `RawSvc`:
```go
type RawSvc struct {
	Config    *config.Config
	Creds     creds.Store
	NewClient ClientFactory
}
```

Replace with:
```go
type RawSvc struct {
	Config    *config.Config
	Creds     creds.Store
	NewClient ClientFactory
	Audit     *AuditLog // optional; nil = no audit
}
```

Find the foundation stub:
```go
// Apply always returns ErrUnsupportedInPhase in foundation. Phase 6 will
// implement the real apply path.
func (s *RawSvc) Apply(ctx context.Context, profileName string, body []byte) error {
	return ErrUnsupportedInPhase
}
```

Replace with:
```go
// Apply sends a user-supplied raw envelope. The body is wrapped in a Sophos
// <Request><Login>...</Login>BODY</Request> wrapper, sent, and audit-logged.
// Pre-flight: read-only-profile rejection. The cli is expected to enforce
// the --confirm-mutating intent gate before calling this method when the
// envelope contains mutating verbs.
func (s *RawSvc) Apply(ctx context.Context, profileName string, body []byte) error {
	profile, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return err
	}
	if profile.ReadOnly {
		return fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return err
	}
	full, err := sophos.BuildRawEnvelope(body, c.Username, c.Password)
	if err != nil {
		return err
	}

	cl := s.NewClient(profile, c)
	_, sendErr := cl.DoRaw(ctx, full)

	mutating, _ := safety.IsMutating(full)
	op := "raw_apply"
	if mutating {
		op = "raw_apply_mutating"
	}
	entry := AuditEntry{
		Profile:     name,
		Operation:   op,
		ObjectType:  "raw",
		RedactedXML: string(safety.RedactXML(full)),
	}
	if sendErr != nil {
		entry.Result = "error:" + ErrorKind(sendErr)
		entry.ErrorMessage = sendErr.Error()
	} else {
		entry.Result = "ok"
	}
	_ = s.Audit.Write(entry)

	return sendErr
}
```

Add imports if not already present: `"fmt"`, `"github.com/iainmoffat/sophosfw/internal/safety"`. The `sophos` import already exists.

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run TestRawSvc_Apply -v
go test ./... -count=1
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/svc/raw.go internal/svc/raw_apply_test.go internal/svc/hostip_create_test.go
git commit -m "feat(svc): RawSvc.Apply real implementation with audit log"
```

---

## Task 8: cli `host ip create/update/delete` + `host ip show --include-diff-hash`

**Files:**
- Modify: `internal/cli/hostip.go` (add 3 mutation subcommands; add --include-diff-hash to show; new render helper)
- Modify: `internal/cli/root.go` (thread d.Audit through RootDeps if needed)
- Modify: `cmd/sophosfw/main.go` (construct AuditLog, pass into RootDeps and HostIPSvc)
- Modify: `internal/render/envelope.go` (add `HostIpMutationEnvelope`)
- Create: `internal/cli/hostip_mutation_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/hostip_mutation_test.go`:

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

type fakeMutCliClient struct {
	sent [][]byte
	body map[string][]json.RawMessage
}

func (f *fakeMutCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (f *fakeMutCliClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForHostIpMutTest(t *testing.T, body map[string][]json.RawMessage) (*RootDeps, *fakeMutCliClient) {
	t.Helper()
	d, _ := newRootForTest(t)
	fc := &fakeMutCliClient{body: body}
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return fc }
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d, fc
}

func TestHostIp_Create_DryRunDefault(t *testing.T) {
	d, fc := newRootForHostIpMutTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "create",
		"--name", "LAN-network", "--host-type", "Network",
		"--ip-address", "10.0.0.0", "--subnet", "255.255.255.0",
		"--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.preview"`)
	require.Contains(t, out.String(), `"mutating": true`)
	require.Empty(t, fc.sent, "default --dry-run must not send")
}

func TestHostIp_Create_YesApplies(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d, fc := newRootForHostIpMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "create",
		"--name", "LAN-network", "--host-type", "Network",
		"--ip-address", "10.0.0.0", "--subnet", "255.255.255.0",
		"--yes", "--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, out.String(), `"applied": true`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Set operation="add">`)
}

func TestHostIp_Update_RequiresExpectedDiffHash(t *testing.T) {
	d, _ := newRootForHostIpMutTest(t, nil)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "update",
		"--name", "X", "--host-type", "IP", "--ip-address", "1.1.1.1",
		"--yes",
	})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "expectedDiffHash") || strings.Contains(err.Error(), "expected-diff-hash"))
}

func TestHostIp_Delete_PositionalArg(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	d, fc := newRootForHostIpMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	hash, _ := svc.DiffHash(struct {
		Name      string `json:"Name"`
		IPFamily  string `json:"IPFamily"`
		HostType  string `json:"HostType"`
		IPAddress string `json:"IPAddress"`
	}{"X", "IPv4", "IP", "1.1.1.1"})
	root.SetArgs([]string{"host", "ip", "delete", "X",
		"--expected-diff-hash", hash, "--yes", "--json",
	})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, out.String(), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
	require.Contains(t, string(fc.sent[0]), `<Remove>`)
}

func TestHostIp_Show_IncludesDiffHashByDefault(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	d, _ := newRootForHostIpMutTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "show", "X", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"_diffHash":`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run "TestHostIp_Create|TestHostIp_Update|TestHostIp_Delete|TestHostIp_Show_IncludesDiffHash" -v
```

- [ ] **Step 3: Add `Audit` field to `RootDeps`**

In `internal/cli/root.go`, find `RootDeps` and add a field:
```go
type RootDeps struct {
	Version  string
	BaseDir  string
	SkillDir string
	Config   *config.Config
	Creds    creds.Store
	NewClient svc.ClientFactory
	Audit    *svc.AuditLog // NEW: Phase 6
}
```

Add `"github.com/iainmoffat/sophosfw/internal/svc"` to imports if not already present. Existing `svc.ClientFactory` reference confirms it is.

- [ ] **Step 4: Wire AuditLog in `cmd/sophosfw/main.go`**

In `main.go`, after the existing `creds.New(baseDir)` line, add:
```go
audit := svc.NewAuditLog(baseDir, cfg.AuditLogEnabled())
```

Pass it into `cli.RootDeps`:
```go
root := cli.NewRoot(cli.RootDeps{
	Version:   version,
	BaseDir:   baseDir,
	SkillDir:  filepath.Join(".claude", "skills", "sophos-firewall"),
	Config:    cfg,
	Creds:     store,
	NewClient: ...,
	Audit:     audit,  // NEW
})
```

Add `"github.com/iainmoffat/sophosfw/internal/svc"` to imports if missing.

- [ ] **Step 5: Update `internal/cli/hostip.go` `hostIpSvc` factory**

Find:
```go
func hostIpSvc(d RootDeps, cat *catalog.Catalog) *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}
```

Replace with:
```go
func hostIpSvc(d RootDeps, cat *catalog.Catalog) *svc.HostIPSvc {
	return &svc.HostIPSvc{
		Inner: &svc.ObjectSvc{
			Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
		},
		Audit: d.Audit,
	}
}
```

- [ ] **Step 6: Add `--include-diff-hash` flag to `host ip show`**

Find `newHostIpShowCmd` and add the flag + post-process the JSON output to include `_diffHash`. The cleanest path: after `hostIpSvc(d, cat).Get(...)` returns the `*svc.HostIP`, compute the hash and append it to the JSON via a wrapper struct OR by emitting a separate JSON object that wraps the HostIP plus the hash. Simplest: render with a wrapper map.

Replace `newHostIpShowCmd` body:

```go
func newHostIpShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var includeHash bool
	c := &cobra.Command{
		Use:   "show <name>",
		Short: "Show one IP host object by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			h, err := hostIpSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				if includeHash {
					hash, hashErr := svc.DiffHash(h.IPHost)
					if hashErr != nil {
						return hashErr
					}
					b, err := render.HostIPEnvelopeWithDiffHash(h, hash)
					if err != nil {
						return err
					}
					_, err = cmd.OutOrStdout().Write(b)
					return err
				}
				b, err := render.HostIPEnvelope(h)
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n  IPAddress: %s\n  Subnet:    %s\n  Derived:   kind=%s cidr=%s\n",
				h.Name, h.HostType, h.IPAddress, h.Subnet, h.Derived.Kind, h.Derived.CIDR)
			return nil
		},
	}
	c.Flags().BoolVar(&includeHash, "include-diff-hash", true, "include _diffHash field in JSON output")
	return c
}
```

`render.HostIPEnvelopeWithDiffHash` is a new helper added in step 8.

- [ ] **Step 7: Add `host ip create/update/delete` subcommands**

In `internal/cli/hostip.go`, find `newHostIpCmd`:
```go
func newHostIpCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "ip", Short: "IPHost first-class commands"}
	cmd.AddCommand(
		newHostIpListCmd(d, cat),
		newHostIpShowCmd(d, cat),
		newHostIpSearchCmd(d, cat),
		newHostIpUsageCmd(d, cat),
	)
	return cmd
}
```

Replace with:
```go
func newHostIpCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "ip", Short: "IPHost first-class commands"}
	cmd.AddCommand(
		newHostIpListCmd(d, cat),
		newHostIpShowCmd(d, cat),
		newHostIpSearchCmd(d, cat),
		newHostIpUsageCmd(d, cat),
		newHostIpCreateCmd(d, cat),
		newHostIpUpdateCmd(d, cat),
		newHostIpDeleteCmd(d, cat),
	)
	return cmd
}
```

Append three new command builders at the end of the file:

```go
func newHostIpCreateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var name, ipFamily, hostType, ipAddr, subnet, startIp, endIp, ipList string
	var yes bool
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a new IP host object",
		Long:  "Defaults to --dry-run preview. Pass --yes to apply.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			input := svc.HostIPCreateInput{
				Name: name, IPFamily: ipFamily, HostType: hostType,
				IPAddress: ipAddr, Subnet: subnet,
				StartIPAddress: startIp, EndIPAddress: endIp,
				IPAddressList: ipList,
			}
			result, err := hostIpSvc(d, cat).Create(cmd.Context(), profile, input, !yes)
			if err != nil {
				return err
			}
			return renderHostIpMutation(cmd, result)
		},
	}
	c.Flags().StringVar(&name, "name", "", "object name (required)")
	c.Flags().StringVar(&ipFamily, "ip-family", "IPv4", "IPv4 or IPv6")
	c.Flags().StringVar(&hostType, "host-type", "Network", "Network|IP|IPRange|IPList")
	c.Flags().StringVar(&ipAddr, "ip-address", "", "IP address (required for Network and IP)")
	c.Flags().StringVar(&subnet, "subnet", "", "subnet mask in dotted-quad form (required for Network)")
	c.Flags().StringVar(&startIp, "start-ip", "", "start of IP range (required for IPRange)")
	c.Flags().StringVar(&endIp, "end-ip", "", "end of IP range (required for IPRange)")
	c.Flags().StringVar(&ipList, "ip-list", "", "comma-separated IP list (required for IPList)")
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	_ = c.MarkFlagRequired("name")
	return c
}

func newHostIpUpdateCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var name, ipFamily, hostType, ipAddr, subnet, startIp, endIp, ipList, expectedHash string
	var yes, ignoreHash bool
	c := &cobra.Command{
		Use:   "update",
		Short: "Update an existing IP host object",
		Long:  "Requires --expected-diff-hash from a prior `host ip show`. Use --ignore-diff-hash to override (with --yes only).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for update --yes (or pass --ignore-diff-hash)")
			}
			input := svc.HostIPCreateInput{
				Name: name, IPFamily: ipFamily, HostType: hostType,
				IPAddress: ipAddr, Subnet: subnet,
				StartIPAddress: startIp, EndIPAddress: endIp,
				IPAddressList: ipList,
			}
			result, err := hostIpSvc(d, cat).Update(cmd.Context(), profile, input, expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			return renderHostIpMutation(cmd, result)
		},
	}
	c.Flags().StringVar(&name, "name", "", "object name (required)")
	c.Flags().StringVar(&ipFamily, "ip-family", "IPv4", "IPv4 or IPv6")
	c.Flags().StringVar(&hostType, "host-type", "Network", "Network|IP|IPRange|IPList")
	c.Flags().StringVar(&ipAddr, "ip-address", "", "IP address")
	c.Flags().StringVar(&subnet, "subnet", "", "subnet mask in dotted-quad form")
	c.Flags().StringVar(&startIp, "start-ip", "", "start of IP range")
	c.Flags().StringVar(&endIp, "end-ip", "", "end of IP range")
	c.Flags().StringVar(&ipList, "ip-list", "", "comma-separated IP list")
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hex hash from a prior `host ip show --include-diff-hash`")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection (use with care)")
	c.Flags().BoolVar(&yes, "yes", false, "apply the change (default is --dry-run)")
	_ = c.MarkFlagRequired("name")
	return c
}

func newHostIpDeleteCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var expectedHash string
	var yes, ignoreHash bool
	c := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an IP host object by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			if yes && expectedHash == "" && !ignoreHash {
				return fmt.Errorf("expected-diff-hash is required for delete --yes (or pass --ignore-diff-hash)")
			}
			result, err := hostIpSvc(d, cat).Delete(cmd.Context(), profile, args[0], expectedHash, ignoreHash, !yes)
			if err != nil {
				return err
			}
			return renderHostIpMutation(cmd, result)
		},
	}
	c.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hex hash from a prior `host ip show --include-diff-hash`")
	c.Flags().BoolVar(&ignoreHash, "ignore-diff-hash", false, "skip drift detection (use with care)")
	c.Flags().BoolVar(&yes, "yes", false, "apply the deletion (default is --dry-run)")
	return c
}

// renderHostIpMutation renders the result of a Create/Update/Delete call.
// Dry-run path emits sophosfw.v1.preview; apply path emits
// sophosfw.v1.hostIpMutation.
func renderHostIpMutation(cmd *cobra.Command, result *svc.HostIPMutationResult) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if !jsonMode {
		// Plain-text rendering for human eyes.
		if result.DryRun {
			fmt.Fprintf(cmd.OutOrStdout(), "DRY RUN: would %s %s\nverbs: %v\n", result.Operation, result.Name, result.Preview.Verbs)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s applied: %s\n", result.Operation, result.Name)
		return nil
	}
	if result.DryRun {
		// Reuse the existing PreviewEnvelope from foundation T1 phase 4.
		b, err := render.PreviewEnvelope(result.Preview)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(b)
		return err
	}
	b, err := render.HostIpMutationEnvelope(result)
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(b)
	return err
}
```

- [ ] **Step 8: Add render helpers**

In `internal/render/envelope.go`, add two new functions:

```go
// HostIPEnvelopeWithDiffHash renders sophosfw.v1.hostIp with a top-level
// _diffHash field. Used when the user passes --include-diff-hash (default
// true) on `host ip show`.
func HostIPEnvelopeWithDiffHash(h *svc.HostIP, diffHash string) ([]byte, error) {
	// Marshal the HostIP, then re-parse + add _diffHash, then re-marshal.
	raw, err := marshalEnvelope("sophosfw.v1.hostIp", h)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["_diffHash"] = diffHash
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// HostIpMutationEnvelope renders sophosfw.v1.hostIpMutation.
func HostIpMutationEnvelope(r *svc.HostIPMutationResult) ([]byte, error) {
	payload := map[string]any{
		"profile":   r.Profile,
		"operation": r.Operation,
		"name":      r.Name,
		"applied":   !r.DryRun,
	}
	if r.Item != nil {
		// Compute diff hash for the post-write state to make the result
		// directly chainable into a follow-up update/delete.
		hash, _ := svc.DiffHash(r.Item.IPHost)
		raw, err := json.Marshal(r.Item)
		if err == nil {
			var itemMap map[string]any
			if err := json.Unmarshal(raw, &itemMap); err == nil {
				itemMap["_diffHash"] = hash
				payload["item"] = itemMap
			}
		}
	}
	return marshalEnvelope("sophosfw.v1.hostIpMutation", payload)
}
```

Add `"encoding/json"` to the imports if not already present.

- [ ] **Step 9: Run — must pass**

```bash
go test ./internal/cli -run "TestHostIp" -v
go test ./... -count=1
```
Expected: PASS for new tests + existing host_ip tests still passing.

- [ ] **Step 10: Commit**

```bash
git add internal/cli/hostip.go internal/cli/hostip_mutation_test.go internal/cli/root.go cmd/sophosfw/main.go internal/render/envelope.go
git commit -m "feat(cli): host ip create/update/delete + show --include-diff-hash"
```

---

## Task 9: cli `raw request --yes --confirm-mutating`

**Files:**
- Modify: `internal/cli/raw.go` (add --confirm-mutating flag, route through Apply when --yes)
- Modify: `cmd/sophosfw/main.go` (no further wiring; RawSvc factory in cli already gets Audit)
- Create: `internal/cli/raw_apply_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/raw_apply_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestRaw_Request_Yes_RequiresConfirmMutating(t *testing.T) {
	d, _ := newRootForTest(t)
	d.Audit = svc.NewAuditLog(t.TempDir(), true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return rawFakeClient{} }

	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "mut.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--yes"})
	err := root.Execute()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "--confirm-mutating"))
}

func TestRaw_Request_Yes_ConfirmMutating_Applies(t *testing.T) {
	d, _ := newRootForTest(t)
	auditDir := t.TempDir()
	d.Audit = svc.NewAuditLog(auditDir, true)
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return rawFakeClient{} }

	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "mut.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"><IPHost><Name>X</Name></IPHost></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--yes", "--confirm-mutating"})
	require.NoError(t, root.Execute())

	// Audit log was written
	body, err := os.ReadFile(filepath.Join(auditDir, "audit.log"))
	require.NoError(t, err)
	require.Contains(t, string(body), `"operation":"raw_apply_mutating"`)
}
```

(The `rawFakeClient` is from foundation T27's `internal/cli/raw_test.go`; reuse it. Tests in the same package can access it.)

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestRaw_Request_Yes -v
```

- [ ] **Step 3: Modify `internal/cli/raw.go` `newRawRequestCmd`**

Find the existing function. Replace its full body with:

```go
func newRawRequestCmd(d RootDeps) *cobra.Command {
	var dryRun, yes, confirmMutating bool
	c := &cobra.Command{
		Use:   "request <file|->",
		Short: "Send (preview) a hand-authored Sophos XML envelope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")

			var (
				body []byte
				err  error
			)
			if args[0] == "-" {
				body, err = io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
			} else {
				body, err = os.ReadFile(args[0])
				if err != nil {
					return err
				}
			}

			s := &svc.RawSvc{Config: d.Config, Creds: d.Creds, NewClient: d.NewClient, Audit: d.Audit}

			if !dryRun && !yes {
				dryRun = true // default to safety
			}

			if yes {
				// Pre-flight: detect mutating verbs and require --confirm-mutating.
				if mutating, _ := safety.IsMutating(body); mutating && !confirmMutating {
					return fmt.Errorf("raw request: envelope contains mutating verbs (Set/Remove); pass --confirm-mutating to acknowledge intent (with --yes)")
				}
				if err := s.Apply(cmd.Context(), profile, body); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "ok")
				return nil
			}

			pv, err := s.Preview(cmd.Context(), profile, body)
			if err != nil {
				return err
			}
			b, err := render.PreviewEnvelope(pv)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview only (default in foundation phase)")
	c.Flags().BoolVar(&yes, "yes", false, "send the envelope to the firewall")
	c.Flags().BoolVar(&confirmMutating, "confirm-mutating", false, "required when --yes is used and the envelope contains Set/Remove verbs")
	return c
}
```

Add imports if missing: `"github.com/iainmoffat/sophosfw/internal/safety"`. The `render` import should already exist; if not, `"github.com/iainmoffat/sophosfw/internal/render"`.

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/cli -run TestRaw -v
go test ./... -count=1
```
Expected: PASS for the new tests + existing raw tests still passing.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/raw.go internal/cli/raw_apply_test.go
git commit -m "feat(cli): raw request --yes --confirm-mutating apply path"
```

---

## Task 10: MCP `host_ip_create/update/delete`

**Files:**
- Modify: `internal/mcp/hostip.go` (add 3 mutation tools + handlers + input types)
- Modify: `internal/mcp/server.go` (Audit field on Deps if needed)
- Modify: `internal/mcp/server_test.go` (count 21 → 24)
- Create: `internal/mcp/hostip_mutation_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/hostip_mutation_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeMcpMutClient struct {
	sent [][]byte
	body map[string][]json.RawMessage
}

func (f *fakeMcpMutClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (f *fakeMcpMutClient) DoRaw(_ context.Context, raw []byte) (*sophos.Response, error) {
	f.sent = append(f.sent, raw)
	return &sophos.Response{LoginOK: true}, nil
}

func newMutMcpServer(t *testing.T, body map[string][]json.RawMessage) (*Server, *fakeMcpMutClient) {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	fc := &fakeMcpMutClient{body: body}
	audit := svc.NewAuditLog(t.TempDir(), true)
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fc },
		DefaultProfile: "home",
		Audit:          audit,
	}), fc
}

func TestHostIpCreate_Handler_RequiresConfirm(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleHostIpCreate(context.Background(), nil, HostIpCreateInput{
		Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
		Confirm: false, // <-- the rejection trigger
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestHostIpCreate_Handler_DryRun(t *testing.T) {
	s, fc := newMutMcpServer(t, nil)
	out, _, err := s.handleHostIpCreate(context.Background(), nil, HostIpCreateInput{
		Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
		Confirm: true, DryRun: true,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.preview"`)
	require.Empty(t, fc.sent)
}

func TestHostIpCreate_Handler_Apply(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	}
	s, fc := newMutMcpServer(t, body)
	out, _, err := s.handleHostIpCreate(context.Background(), nil, HostIpCreateInput{
		Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
		Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, textOf(out), `"applied": true`)
	require.Len(t, fc.sent, 1)
}

func TestHostIpUpdate_Handler_RequiresExpectedDiffHash(t *testing.T) {
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	})
	out, _, err := s.handleHostIpUpdate(context.Background(), nil, HostIpUpdateInput{
		HostIpCreateInput: HostIpCreateInput{
			Name: "X", HostType: "IP", IpAddress: "1.1.1.1",
			Confirm: true, DryRun: false,
		},
		// ExpectedDiffHash empty, IgnoreExpectedDiffHash false
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.error"`)
	require.Contains(t, textOf(out), `"kind": "invalid_request"`)
	require.Empty(t, fc.sent)
}

func TestHostIpDelete_Handler_DiffHashMatch_Applies(t *testing.T) {
	current := catalog.IPHost{Name: "X", IPFamily: "IPv4", HostType: "IP", IPAddress: "1.1.1.1"}
	hash, _ := svc.DiffHash(current)
	s, fc := newMutMcpServer(t, map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
	})
	out, _, err := s.handleHostIpDelete(context.Background(), nil, HostIpDeleteInput{
		Name: "X", ExpectedDiffHash: hash,
		Confirm: true, DryRun: false,
	})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIpMutation"`)
	require.Contains(t, textOf(out), `"operation": "delete"`)
	require.Len(t, fc.sent, 1)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/mcp -run "TestHostIpCreate_Handler|TestHostIpUpdate_Handler|TestHostIpDelete_Handler" -v
```

- [ ] **Step 3: Add `Audit` field to `Deps` and thread through**

In `internal/mcp/server.go`, find `Deps`:
```go
type Deps struct {
	Config         *config.Config
	Creds          creds.Store
	Catalog        *catalog.Catalog
	NewClient      svc.ClientFactory
	DefaultProfile string
}
```

Add the field:
```go
type Deps struct {
	Config         *config.Config
	Creds          creds.Store
	Catalog        *catalog.Catalog
	NewClient      svc.ClientFactory
	DefaultProfile string
	Audit          *svc.AuditLog // NEW: Phase 6
}
```

In `internal/cli/mcp.go`, where `mcp.NewServer` is called, add `Audit: d.Audit` to the `Deps{...}` literal.

- [ ] **Step 4: Update `hostIpSvc` factory in `internal/mcp/hostip.go`**

Find:
```go
func (s *Server) hostIpSvc() *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: s.objectSvc()}
}
```

Replace with:
```go
func (s *Server) hostIpSvc() *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: s.objectSvc(), Audit: s.deps.Audit}
}
```

- [ ] **Step 5: Add the 3 mutating tools to `internal/mcp/hostip.go`**

Append to the file:

```go
// HostIpCreateInput is shared by host_ip_create and host_ip_update handlers
// (Update embeds it).
type HostIpCreateInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required" jsonschema_description:"object name"`
	IpFamily       string `json:"ipFamily,omitempty"`
	HostType       string `json:"hostType" jsonschema:"required" jsonschema_description:"Network|IP|IPRange|IPList"`
	IpAddress      string `json:"ipAddress,omitempty"`
	Subnet         string `json:"subnet,omitempty"`
	StartIpAddress string `json:"startIpAddress,omitempty"`
	EndIpAddress   string `json:"endIpAddress,omitempty"`
	IpAddressList  string `json:"ipAddressList,omitempty"`
	Confirm        bool   `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun         bool   `json:"dryRun,omitempty"`
}

type HostIpUpdateInput struct {
	HostIpCreateInput
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior host_ip_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
}

type HostIpDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

func (s *Server) handleHostIpCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	input := svc.HostIPCreateInput{
		Name: in.Name, IPFamily: in.IpFamily, HostType: in.HostType,
		IPAddress: in.IpAddress, Subnet: in.Subnet,
		StartIPAddress: in.StartIpAddress, EndIPAddress: in.EndIpAddress,
		IPAddressList: in.IpAddressList,
	}
	result, err := s.hostIpSvc().Create(ctx, profile, input, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpHostIpMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleHostIpUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpUpdateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	input := svc.HostIPCreateInput{
		Name: in.Name, IPFamily: in.IpFamily, HostType: in.HostType,
		IPAddress: in.IpAddress, Subnet: in.Subnet,
		StartIPAddress: in.StartIpAddress, EndIPAddress: in.EndIpAddress,
		IPAddressList: in.IpAddressList,
	}
	result, err := s.hostIpSvc().Update(ctx, profile, input, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpHostIpMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleHostIpDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	result, err := s.hostIpSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpHostIpMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

// renderMcpHostIpMutation picks the right envelope based on whether the
// result was a dry-run preview or an applied mutation.
func renderMcpHostIpMutation(r *svc.HostIPMutationResult) ([]byte, error) {
	if r.DryRun {
		return render.PreviewEnvelope(r.Preview)
	}
	return render.HostIpMutationEnvelope(r)
}
```

Update the `registerHostIP` function to add the 3 new tools:

Find the existing `registerHostIP`:
```go
func (s *Server) registerHostIP() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "host_ip_list", ...
	}, s.handleHostIpList)
	// ... 3 more existing AddTool calls ...
}
```

Append after the 4th existing AddTool:
```go
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_create",
		Description: "Create a new IPHost. Requires confirm: true. Use dryRun: true to preview without applying. Returns sophosfw.v1.hostIpMutation on apply or sophosfw.v1.preview on dry-run.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create IP host"},
	}, s.handleHostIpCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_update",
		Description: "Update an existing IPHost. Requires confirm: true AND expectedDiffHash from a prior host_ip_show. Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update IP host"},
	}, s.handleHostIpUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_delete",
		Description: "Delete an IPHost by name. Requires confirm: true AND expectedDiffHash from a prior host_ip_show.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: true, Title: "Delete IP host"},
	}, s.handleHostIpDelete)
```

(`DestructiveHint` is part of `sdkmcp.ToolAnnotations`; if the SDK version doesn't expose it, omit that one field.)

- [ ] **Step 6: Update `internal/mcp/server_test.go` tool count**

Find the assertion:
```go
require.Len(t, result.Tools, 21, ...)
```

Change to:
```go
require.Len(t, result.Tools, 24, ...)
```

Add the 3 new names to the expected-name list:
```go
for _, want := range []string{
    // ... existing 21 ...
    "host_ip_create",
    "host_ip_update",
    "host_ip_delete",
} {
    require.Contains(t, names, want)
}
```

- [ ] **Step 7: Update `host_ip_show` MCP tool to include `_diffHash`**

The MCP `host_ip_show` envelope renders `*svc.HostIP` directly. Update to include the diff hash. In `internal/mcp/hostip.go` `handleHostIpShow`:

Find:
```go
body, err := render.HostIPEnvelope(h)
```

Replace with:
```go
hash, hashErr := svc.DiffHash(h.IPHost)
if hashErr != nil {
    return s.errorEnvelopeResult(hashErr, profile)
}
body, err := render.HostIPEnvelopeWithDiffHash(h, hash)
```

- [ ] **Step 8: Run — must pass**

```bash
go test ./internal/mcp -count=1 -v
go test ./... -count=1
```
Expected: PASS for new tests + 24-tool registration assertion + existing tests.

- [ ] **Step 9: Commit**

```bash
git add internal/mcp/hostip.go internal/mcp/hostip_mutation_test.go internal/mcp/server.go internal/mcp/server_test.go internal/cli/mcp.go
git commit -m "feat(mcp): host_ip_create/update/delete tools (24 total)"
```

---

## Task 11: Agent skill content updates + skill-doctor expansion

**Files:**
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md`
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md`
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/safety-checklist.md`
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/audit-template.md`
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md`
- Modify: `internal/cli/skill.go` (add 3 required strings)
- Modify: `internal/cli/skill_test.go` (update stub skills to include the new strings)

**Note**: canonical skill files in skillshare are NOT committed in the sophosfw repo (foundation T30 pattern). The sophosfw-repo commit only includes `internal/cli/skill.go` + `internal/cli/skill_test.go`.

- [ ] **Step 1: Update SKILL.md "Common Change Workflows"**

Find the existing section in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md`:
```markdown
## Common Change Workflows

**Not implemented in Phase 5.** Phase 6 will land mutating workflows
following this shape:

- **CLI:** `sophosfw host ip create --dry-run --name X --ip ...` will
  preview the envelope; the human reviews; `--yes` (separately) will
  apply. Same pattern for `update` and `delete`.
- **MCP:** mutating tools will require `confirm: true` as an explicit
  argument; some operations may also require `expectedDiffHash` for
  optimistic-concurrency safety.

Until Phase 6 ships:
- If the user asks to change something, summarize what would need to
  change and tell them apply isn't supported yet.
- An `unsupported_in_phase` error means stop. Do not retry, do not
  suggest workarounds with `raw request --yes`.
- `sophosfw raw request <file> --dry-run` is the only preview path
  available; it shows what WOULD be sent without sending. Use only
  when the user explicitly asks to see a preview.
```

Replace with:
```markdown
## Common Change Workflows

Phase 6 ships mutating workflows for IPHost objects. The pattern is:

**CLI:**
1. `sophosfw host ip show LAN-network --json` → captures `_diffHash`.
2. `sophosfw host ip update --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0` (default --dry-run; preview the envelope).
3. Review the redacted XML and verbs.
4. `sophosfw host ip update --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0 --expected-diff-hash <hex> --yes` to apply.

**MCP:**
1. `host_ip_show {name: LAN-network}` → `_diffHash` in response.
2. `host_ip_update {name, hostType, ipAddress, subnet, expectedDiffHash, confirm: true, dryRun: true}` → preview.
3. `host_ip_update {... confirm: true}` (omit dryRun) → apply.

Mutations are recorded in `~/.config/sophosfw/audit.log` (one JSON line per attempt, including failures). Disabled per-config via `defaults.auditLog: false`.

The Phase 6 surface is intentionally limited to IPHost. Service / firewall rule / nat rule mutations defer to a later phase. The `raw request --yes --confirm-mutating` cli path is the escape hatch for any tag without a first-class mutating verb.
```

- [ ] **Step 2: Update mcp-tools.md — add `host_ip` mutating tools section**

Find the existing `## host_ip — IPHost objects` section. AFTER its example block (the `host_ip_usage` YAML), insert a new section:

```markdown
---

## host_ip mutating tools

| Tool | Purpose |
|---|---|
| `host_ip_create` | Create a new IPHost (requires confirm: true) |
| `host_ip_update` | Update an existing IPHost (requires confirm: true AND expectedDiffHash) |
| `host_ip_delete` | Delete an IPHost (requires confirm: true AND expectedDiffHash) |

**When to use**
- The user explicitly asks to add/change/remove a host.

**Gotchas**
- ALL THREE require `confirm: true` to apply. Without it: error envelope
  with `kind: invalid_request`.
- `host_ip_update` and `host_ip_delete` require `expectedDiffHash` from
  a prior `host_ip_show`. If the firewall state has drifted since you
  read it, you get `kind: diff_hash_mismatch`. Re-fetch and re-evaluate
  before retrying — do NOT add `ignoreExpectedDiffHash: true` reflexively.
- `dryRun: true` returns the preview envelope without applying. Use this
  to show the user what WILL be sent, then call again with
  `dryRun: false` (or omit).
- Audit log entries land in `~/.config/sophosfw/audit.log`.

**Example (create, dry-run then apply)**
```yaml
host_ip_create:
  name: LAN-network
  hostType: Network
  ipAddress: 10.0.0.0
  subnet: 255.255.255.0
  confirm: true
  dryRun: true   # preview; remove for apply
```

**Example (update with hash)**
```yaml
host_ip_update:
  name: LAN-network
  hostType: Network
  ipAddress: 10.0.0.0
  subnet: 255.255.255.0
  expectedDiffHash: abc123...
  confirm: true
```
```

(Use real triple-backticks for the YAML fences.)

- [ ] **Step 3: Update safety-checklist.md — add items #13 and #14**

Open `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/safety-checklist.md` and append after item #12:

```markdown
13. ☐ When mutating: ALWAYS run `--dry-run` (CLI) or `dryRun: true` (MCP) first. Show the user the redacted XML and the verbs detected. Wait for explicit confirmation before re-running with `--yes` (CLI) or omitting `dryRun` (MCP).
14. ☐ When `expectedDiffHash` mismatch errors (`kind: diff_hash_mismatch`): do NOT add `--ignore-diff-hash` reflexively. Re-fetch the current object, re-evaluate whether the proposed change is still desired, ASK THE USER what to do.
```

- [ ] **Step 4: Update audit-template.md — add a third example**

Open `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/audit-template.md` and append after the existing examples (and the explanatory paragraph from Phase 5):

```markdown

Example (mutation, from audit.log):

```
{"timestamp":"2026-05-15T14:23:11.234567890Z","profile":"home","operation":"create","objectType":"IPHost","objectName":"LAN-network","redactedXml":"<Request><Login><Username>admin</Username><Password>***REDACTED***</Password></Login><Set operation=\"add\"><IPHost><Name>LAN-network</Name>...</IPHost></Set></Request>","result":"ok"}
```

Mutating operations (host ip create/update/delete; raw request --yes --confirm-mutating) write one JSON line per attempt to `~/.config/sophosfw/audit.log` (mode 0600). The Operation field uses `create`/`update`/`delete` for typed mutations or `raw_apply_mutating`/`raw_apply` for the raw escape hatch. Disabled per-config via `defaults.auditLog: false`.
```

- [ ] **Step 5: Update examples.md — add "Mutating IP host objects" section**

Append to `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md`:

```markdown

## Mutating IP host objects

```bash
# Create (preview):
sophosfw host ip create --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0

# Create (apply):
sophosfw host ip create --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0 --yes

# Show (capture diff hash for next operation):
sophosfw host ip show LAN-network --json | jq -r ._diffHash

# Update (preview):
sophosfw host ip update --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0 --expected-diff-hash <hex>

# Update (apply):
sophosfw host ip update --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0 --expected-diff-hash <hex> --yes

# Delete:
sophosfw host ip delete LAN-network --expected-diff-hash <hex> --yes
```

```yaml
host_ip_create:
  name: LAN-network
  hostType: Network
  ipAddress: 10.0.0.0
  subnet: 255.255.255.0
  confirm: true
  dryRun: true   # preview; remove for apply

host_ip_update:
  name: LAN-network
  hostType: Network
  ipAddress: 10.0.0.0
  subnet: 255.255.255.0
  expectedDiffHash: abc123...
  confirm: true
```
```

(Real triple-backticks throughout.)

- [ ] **Step 6: Update `internal/cli/skill.go` `requiredCommandsInExamples`**

Find the const slice (Phase 5 left it at 9 entries). Append 3 new strings:

```go
var requiredCommandsInExamples = []string{
	"sophosfw auth status",
	"sophosfw object list",
	"sophosfw raw get",
	"sophosfw mcp serve",
	"sophosfw host ip list",
	"sophosfw service list",
	"sophosfw firewall rule list",
	"sophosfw nat rule list",
	"host_ip_list",
	// Phase 6 additions:
	"sophosfw host ip create",
	"sophosfw host ip delete",
	"host_ip_create", // MCP sentinel for mutating tools
}
```

- [ ] **Step 7: Update `internal/cli/skill_test.go` stub skills**

The 5 existing tests (TestSkillDoctor_*) write synthetic skill content. Each pass-case test that writes `examples.md` and `mcp-tools.md` must include the new required strings.

In `TestSkillDoctor_PassesWhenSkillExists`: extend the `examples.md` byte-string to include `sophosfw host ip create` and `sophosfw host ip delete`. Extend the `mcp-tools.md` byte-string to include `host_ip_create`.

In `TestSkillDoctor_FindsRequiredInMcpTools`: same extensions.

In `TestSkillDoctor_FailsIfRequiredCommandMissingFromExamples`: this test asserts a missing-string failure; its synthetic content stays sparse on purpose — no change needed.

In `TestSkillDoctor_FailsWhenMcpToolsMissing`: same — stub content stays as-is.

- [ ] **Step 8: Run — must pass**

```bash
go test ./internal/cli -run TestSkillDoctor -v
make skill-doctor
```
Expected: 5 doctor tests PASS; `make skill-doctor` outputs `skill ok` against the live (T1-T5 of this task) updated canonical skill content.

- [ ] **Step 9: Run full suite**

```bash
go test ./... -count=1
```

- [ ] **Step 10: Commit (sophosfw-repo only — skillshare changes stay untracked there)**

```bash
git add internal/cli/skill.go internal/cli/skill_test.go
git commit -m "feat(cli): expand skill doctor for Phase 6 mutating surface"
```

The 5 canonical-skill-content edits (SKILL.md, mcp-tools.md, safety-checklist.md, audit-template.md, examples.md in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/`) remain as untracked working-tree changes in the skillshare repo for the user to commit there separately.

---

## Task 12: Integration smoke + docs + acceptance + tag

**Files:**
- Modify: `internal/testutil/integration_test.go` (append host ip create --dry-run smoke)
- Modify: `docs/api-coverage.md` (IPHost row reflects new mutating commands)
- Modify: `docs/roadmap.md` (Phase 6 status complete)

- [ ] **Step 1: Append integration smoke test**

In `internal/testutil/integration_test.go` (build-tagged `integration`), append:

```go
func TestIntegration_HostIPCreate_DryRun(t *testing.T) {
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	audit := svc.NewAuditLog(t.TempDir(), false) // disabled for tests

	hostIp := &svc.HostIPSvc{
		Inner: &svc.ObjectSvc{
			Config: cfg, Creds: store, Catalog: cat,
			NewClient: svc.DefaultClientFactory(false),
		},
		Audit: audit,
	}

	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName)

	// Dry-run only — must not send. The IntegrationClient (foundation T32)
	// would panic if any mutating envelope were actually sent during this
	// test — that's the safety net.
	result, err := hostIp.Create(context.Background(), profileName, svc.HostIPCreateInput{
		Name: "sophosfw-test-do-not-create", HostType: "IP", IPAddress: "192.0.2.1",
	}, true) // dryRun=true
	require.NoError(t, err)
	require.True(t, result.DryRun)
	require.NotNil(t, result.Preview)
	require.True(t, result.Preview.Mutating)
	require.Contains(t, result.Preview.Verbs, "Set:add")
}
```

(The test does NOT use the full IntegrationClient — that wrapper would panic on mutating envelopes. This test calls HostIPSvc directly with `DefaultClientFactory(false)` and dryRun=true; no mutating envelope is built and sent. The `integration` build tag still gates it from standard test runs.)

- [ ] **Step 2: Update `docs/api-coverage.md`**

Find the IPHost row. Update Add/Update/Remove cells. Example before:
```
| Host | IPHost | object list/get IPHost; host ip list/show/search/usage | host_ip_list/show/search/usage; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
```

After:
```
| Host | IPHost | object list/get IPHost; host ip list/show/search/usage/create/update/delete | host_ip_list/show/search/usage/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host ip create; host_ip_create) | yes (sophosfw host ip update; host_ip_update) | yes (sophosfw host ip delete; host_ip_delete) | yes (with --with-references) | Phase 6 |
```

- [ ] **Step 3: Update `docs/roadmap.md`**

Find:
```markdown
- Phase 5 — Agent skill completion (complete; v0.4.0-phase5)
- Phase 6 — Safe mutations (host ip create/update/delete + MCP equivalents)
```

Replace with:
```markdown
- Phase 5 — Agent skill completion (complete; v0.4.0-phase5)
- Phase 6 — Safe mutations (complete; v0.5.0-phase6)
```

(Phase 7 unchanged.)

- [ ] **Step 4: Run the full test suite with race detector**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```
Expected: PASS, no fmt drift.

- [ ] **Step 5: Build and inspect the binary**

```bash
make build
./bin/sophosfw version
./bin/sophosfw host ip --help
./bin/sophosfw raw request --help
```
Expected: help text shows `create`, `update`, `delete` under `host ip`. `raw request` help shows `--yes` and `--confirm-mutating`.

- [ ] **Step 6: Smoke test the dry-run path**

```bash
TMPHOME=$(mktemp -d) XDG_CONFIG_HOME=$TMPHOME ./bin/sophosfw auth profile add home --url https://example.invalid:4444
TMPHOME=$(mktemp -d) XDG_CONFIG_HOME=$TMPHOME ./bin/sophosfw host ip create --name X --host-type IP --ip-address 1.2.3.4 --json 2>&1 | head -20
```
Expected: profile add succeeds; host ip create (no `--yes`) errors at the auth step (no creds saved) but importantly does NOT panic and does NOT crash. Acceptable if the error mentions `auth_failed` or `not_logged_in` style — the dry-run wire-format will short-circuit on missing creds.

(More thorough smoke would require a real test firewall; this just verifies the cli wiring works.)

- [ ] **Step 7: Run `make skill-doctor`**

```bash
make skill-doctor
```
Expected: `skill ok`.

- [ ] **Step 8: Commit any fmt-induced changes**

```bash
git status
# If clean, skip to step 9.
git add -A
git commit -m "fix: phase 6 acceptance pass adjustments"
```

- [ ] **Step 9: Commit the docs and integration test**

```bash
git add internal/testutil/integration_test.go docs/api-coverage.md docs/roadmap.md
git commit -m "docs+test: phase 6 integration smoke and api-coverage / roadmap updates"
```

- [ ] **Step 10: Tag the milestone**

```bash
git tag -a v0.5.0-phase6 -m "Phase 6 complete (safe mutations: host ip + raw apply)"
git tag --list | grep -E "(foundation|phase3|phase4|phase5|phase6)"
```

- [ ] **Step 11: Push to origin**

```bash
git push origin main
git push origin v0.5.0-phase6
```

- [ ] **Step 12: Final sanity**

```bash
git log --oneline -15
```
Expected: linear history with Phase 6 commits + Phase 5 + earlier history below.

---

## End of plan

This concludes Phase 6. Phase 7 (complex draft workflows) is the next phase — `firewall rule pull --draft` → edit → diff → preview → push, with snapshots at `~/.config/sophosfw/profiles/<name>/snapshots/`. Each future phase gets its own brainstorm → spec → plan → implementation cycle.

---

## Self-review checklist

- ✅ **Spec coverage:** every spec section maps to at least one task. Sections 3 (audit log) → T1; 4 (diff hash) → T2; 10 (envelope builders) → T3; 9 (catalog Mutable) → T4; 5 (HostIPSvc Create) → T5; 5 (Update/Delete) → T6; 8 (RawSvc.Apply) → T7; 6 (cli mutations) → T8; 8.2 (cli raw) → T9; 7 (MCP tools) → T10; 12 (skill) and 13 (skill-doctor) → T11; 14 (testing) and 15 (acceptance) → T12.
- ✅ **No placeholders.** Every step has actual code or commands. Markdown updates show full before/after blocks.
- ✅ **Type consistency.** `HostIPCreateInput` declared in T5; T6 reuses it. `HostIPMutationResult` declared in T5; T8/T10 render it. `AuditLog`/`AuditEntry` from T1 used by T5/T6/T7. `DiffHash` from T2 used by T6/T8.
- ✅ **No Co-Authored-By guard.** Every commit step explicitly verifies the trailer's absence (or provides the verification command).
- ✅ **Single passing commit per task.** T5 commits errors_kind.go + cli/errors.go (the new error sentinel and exit code) in the SAME commit as hostip.go, so no intermediate broken state.
- ⚠️ **Triple-backtick escaping.** T1-T11 markdown rewrites have a few code blocks. The plan inlines real triple-backticks (not escape placeholders) where possible; in a few nested cases (T2 Step 1's mcp-tools.md update) the implementer should double-check the live file rendering.
- ✅ **Acceptance criteria mapping.** All 11 spec section-15 acceptance items are verified by T12 steps 4-7 plus the per-task tests.
