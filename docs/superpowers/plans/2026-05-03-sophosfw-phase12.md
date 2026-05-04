# sophosfw Phase 12 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add create/update/delete coverage (CLI + MCP) for the six object types currently flagged "partial" in `docs/api-coverage.md` — IPHostGroup, FQDNHost, FQDNHostGroup, MACHost, Services, ServiceGroup. Body-as-map pattern (mirror firewall_rule/nat_rule). Ship as `v0.10.0`.

**Architecture:** Body-as-map svc methods (`Create`/`Update`/`Delete`) per type; one CLI subtree per type extending the existing `host` and `service` parents; 18 new MCP tools (30 → 48 total). One generic `marshalObjectBody` helper used across firewall_rule/nat_rule (refactored) and the 6 new types. Generic `object_get` (svc + MCP) injects `_diffHash` for catalog-mutable types so update/delete callers can fetch the hash.

**Tech Stack:** Go 1.26+, gopkg.in/yaml.v3, github.com/modelcontextprotocol/go-sdk v1.5.0. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-03-sophosfw-phase12-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.9.1`. Working dir: `/Users/ipm/code/sophosfw`.

```bash
git status
go test ./... -count=1 -race
golangci-lint run ./...
```

Expected: clean status, all tests pass, lint clean.

## File structure

**New files (per the foundation tasks):**
- `internal/svc/marshal.go` — generic `marshalObjectBody(tag, body)` helper.
- `internal/svc/object_mutation.go` — `ObjectMutationResult` struct + shared validation helpers.
- `internal/render/object_mutation.go` — render envelope for object mutations.
- `internal/cli/bodyflag.go` — `LoadBody(source)` helper.
- `internal/cli/bodyflag_test.go` — tests for body-flag helper.

**New files (per type, ×6):**
- `internal/svc/<type>.go` — Create/Update/Delete + required-fields constant. (`type` lowercased: iphostgroup, fqdnhost, fqdnhostgroup, machost, services, servicegroup)
- `internal/svc/<type>_test.go` — ~12 unit tests.
- `internal/cli/<type>_mutation.go` — 3 cobra commands.
- `internal/cli/<type>_mutation_test.go` — CLI tests (table-driven where possible).
- `internal/mcp/<type>_mutation.go` — 3 MCP handlers + 3 input types + render helper.
- `internal/mcp/<type>_mutation_test.go` — 8 handler tests.

**Modified files:**
- `internal/catalog/objects.yaml` — 6 entries gain `mutable: true`.
- `internal/catalog/catalog_test.go` — update `TestCatalog_OtherEntriesNotMutable`.
- `internal/svc/firewallrule_create.go` — replace local `marshalFirewallRule` with call to `marshalObjectBody("FirewallRule", body)`.
- `internal/svc/natrule_create.go` — same for `marshalNATRule`.
- `internal/svc/object.go` — `Get` injects `_diffHash` when catalog entry is Mutable.
- `internal/cli/host.go` — register host group / host fqdn / host fqdn-group / host mac sub-parents and command wiring.
- `internal/cli/service.go` — register service group sub-parent + service create/update/delete command wiring.
- `internal/mcp/server.go` — register 18 new tools (or per-type files do their own registration via factory pattern matching firewallrule.go).
- `internal/mcp/server_test.go` — tool count assertion 30 → 48 with the 18 new names listed.
- `docs/api-coverage.md` — 6 partial cells become "Phase 12" complete.
- `docs/roadmap.md` — Phase 12 marked complete (final task).

---

## Task 1: Catalog mutable flags

**Files:**
- Modify: `internal/catalog/objects.yaml`
- Modify: `internal/catalog/catalog_test.go`

- [ ] **Step 1: Set `mutable: true` on six entries**

Read current `internal/catalog/objects.yaml`. For each of these tags, append (or insert before the next `- tag:` line) `mutable: true` indented to match `typedParser`:

- `IPHostGroup`
- `FQDNHost`
- `FQDNHostGroup`
- `MACHost`
- `Services`
- `ServiceGroup`

Verification:

```bash
grep -A 1 "tag: IPHostGroup\|tag: FQDNHost\|tag: FQDNHostGroup\|tag: MACHost\|tag: Services\|tag: ServiceGroup" internal/catalog/objects.yaml | grep -c mutable
```

Expected: `6`.

- [ ] **Step 2: Update catalog test**

Read `internal/catalog/catalog_test.go`. Find:

```go
func TestCatalog_OtherEntriesNotMutable(t *testing.T) {
    c, err := NewDefault()
    require.NoError(t, err)
    for _, tag := range []string{"FQDNHost", "MACHost", "Zone", "Services"} {
        entry, ok := c.Resolve(tag)
        require.True(t, ok, "tag %q should exist", tag)
        require.False(t, entry.Mutable, "tag %q must NOT be mutable in Phase 7", tag)
    }
}
```

Replace with:

```go
func TestCatalog_Phase12NewlyMutable(t *testing.T) {
    c, err := NewDefault()
    require.NoError(t, err)
    for _, tag := range []string{"IPHostGroup", "FQDNHost", "FQDNHostGroup", "MACHost", "Services", "ServiceGroup"} {
        entry, ok := c.Resolve(tag)
        require.True(t, ok, "tag %q should exist", tag)
        require.True(t, entry.Mutable, "tag %q must be mutable as of Phase 12", tag)
    }
}

func TestCatalog_NetworkTypesStillImmutable(t *testing.T) {
    c, err := NewDefault()
    require.NoError(t, err)
    for _, tag := range []string{"Zone", "Interface", "GatewayConfiguration"} {
        entry, ok := c.Resolve(tag)
        require.True(t, ok, "tag %q should exist", tag)
        require.False(t, entry.Mutable, "tag %q must NOT be mutable (network types deferred)", tag)
    }
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/catalog -count=1 -race -v
```

Expected: PASS for all tests.

- [ ] **Step 4: Commit (do NOT push yet)**

```bash
git add internal/catalog/objects.yaml internal/catalog/catalog_test.go
git commit -m "$(cat <<'EOF'
catalog: mark six types mutable for phase 12

IPHostGroup, FQDNHost, FQDNHostGroup, MACHost, Services, ServiceGroup
gain mutable: true. Test renamed and split into a Phase 12 newly-mutable
assertion plus a network-types-still-immutable assertion (Zone,
Interface, GatewayConfiguration are deferred per the Phase 12 spec).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Unified `marshalObjectBody` + refactor firewall/nat

**Files:**
- Create: `internal/svc/marshal.go`
- Create: `internal/svc/marshal_test.go`
- Modify: `internal/svc/firewallrule_create.go`
- Modify: `internal/svc/natrule_create.go`

- [ ] **Step 1: Find the existing `marshalFirewallRule` and `marshalNATRule` implementations**

```bash
grep -A 30 "^func marshalFirewallRule" internal/svc/firewallrule_create.go
grep -A 30 "^func marshalNATRule" internal/svc/natrule_create.go
```

These two are near-identical except for the outer XML tag name. Confirm before proceeding. If the bodies have diverged in a non-trivial way, STOP and report — the unification needs more thought than this task allows.

- [ ] **Step 2: Write `internal/svc/marshal.go`**

Extract the shared logic into a single helper. The signature:

```go
package svc

import (
    "bytes"
    "fmt"
    "strings"

    "github.com/iainmoffat/sophosfw/internal/sophos"
)

// marshalObjectBody emits the Sophos inner XML element for a single object body.
// tag is the outer element name (e.g. "FirewallRule", "IPHostGroup"). body is
// the parsed YAML/JSON map. Element names are validated via validateXMLName so
// caller-controlled keys cannot inject XML.
func marshalObjectBody(tag string, body map[string]any) ([]byte, error) {
    if !validateXMLName(tag) {
        return nil, fmt.Errorf("%w: invalid xml tag %q", sophos.ErrInvalidRequest, tag)
    }
    var buf bytes.Buffer
    buf.WriteString("<")
    buf.WriteString(tag)
    buf.WriteString(">")
    if err := writeMap(&buf, body); err != nil {
        return nil, err
    }
    buf.WriteString("</")
    buf.WriteString(tag)
    buf.WriteString(">")
    return buf.Bytes(), nil
}
```

Move the existing recursive `writeMap` / `writeKeyValue` / `validateXMLName` / `xmlEscape` helpers from `firewallrule_create.go` into `marshal.go` (they should be unexported and shared). If they're already shared via another file, point `marshalObjectBody` at them.

Concrete steps:

```bash
# Find current homes of the helpers
grep -ln "func writeKeyValue\|func validateXMLName\|func writeMap\|func xmlEscape" internal/svc/*.go
```

Move them to `marshal.go`. Adjust callers.

- [ ] **Step 3: Write `internal/svc/marshal_test.go`**

```go
package svc

import (
    "testing"

    "github.com/stretchr/testify/require"
)

func TestMarshalObjectBody_SimpleScalars(t *testing.T) {
    out, err := marshalObjectBody("Foo", map[string]any{"Name": "x", "Count": 3})
    require.NoError(t, err)
    s := string(out)
    require.Contains(t, s, "<Foo>")
    require.Contains(t, s, "<Name>x</Name>")
    require.Contains(t, s, "<Count>3</Count>")
    require.Contains(t, s, "</Foo>")
}

func TestMarshalObjectBody_NestedMap(t *testing.T) {
    out, err := marshalObjectBody("Foo", map[string]any{
        "Name": "x",
        "Inner": map[string]any{"K": "v"},
    })
    require.NoError(t, err)
    require.Contains(t, string(out), "<Inner><K>v</K></Inner>")
}

func TestMarshalObjectBody_StringList(t *testing.T) {
    // Sophos uses <Foo>x</Foo><Foo>y</Foo> for lists, NOT a wrapping element.
    out, err := marshalObjectBody("Group", map[string]any{
        "Name":     "g",
        "HostList": map[string]any{"Host": []any{"a", "b"}},
    })
    require.NoError(t, err)
    s := string(out)
    require.Contains(t, s, "<Host>a</Host>")
    require.Contains(t, s, "<Host>b</Host>")
}

func TestMarshalObjectBody_RejectsInvalidTag(t *testing.T) {
    _, err := marshalObjectBody("Foo<Bar>", map[string]any{"Name": "x"})
    require.Error(t, err)
}

func TestMarshalObjectBody_EscapesValues(t *testing.T) {
    out, err := marshalObjectBody("Foo", map[string]any{"Name": "a&b<c>"})
    require.NoError(t, err)
    require.Contains(t, string(out), "&amp;")
    require.NotContains(t, string(out), "a&b<c>")
}
```

Run:

```bash
go test ./internal/svc -run TestMarshalObjectBody -v -count=1
```

Expected: all 5 pass.

- [ ] **Step 4: Refactor firewall_rule + nat_rule to use the helper**

In `internal/svc/firewallrule_create.go`, find the call to `marshalFirewallRule(body)` and replace with `marshalObjectBody("FirewallRule", body)`. Delete the now-unused `marshalFirewallRule` function.

Same in `internal/svc/firewallrule_pull.go` (Update path uses it too — check with `grep -n marshalFirewallRule internal/svc/`).

Same in `internal/svc/natrule_create.go` and `internal/svc/natrule_pull.go` for `marshalNATRule`.

Verification:

```bash
grep -rn "marshalFirewallRule\|marshalNATRule" internal/svc/
```

Expected: no results (both functions removed).

- [ ] **Step 5: Run full test suite — must pass**

```bash
go test ./... -count=1 -race
```

If firewall_rule or nat_rule tests fail, the unified helper diverged from the per-type behavior in some edge case. Compare the diff and fix. Common pitfalls: list element naming (the existing helpers may use a per-type wrap like `<HostList><Host>...</Host></HostList>` — preserve that exactly).

- [ ] **Step 6: Run lint**

```bash
golangci-lint run ./...
```

Expected: 0 issues.

- [ ] **Step 7: Commit**

```bash
git add internal/svc/marshal.go internal/svc/marshal_test.go internal/svc/firewallrule_create.go internal/svc/firewallrule_pull.go internal/svc/natrule_create.go internal/svc/natrule_pull.go
git commit -m "$(cat <<'EOF'
svc: unify marshalFirewallRule and marshalNATRule into marshalObjectBody

Phase 12 introduces six new types using the same body-as-map pattern.
Rather than copy the per-type marshal helpers six more times,
consolidate the existing two into a single marshalObjectBody(tag, body)
helper in marshal.go. firewall_rule and nat_rule now call it with the
appropriate XML tag name; per-type marshal functions are removed.

writeMap, writeKeyValue, validateXMLName, and xmlEscape move to
marshal.go where they belong. Behavior preserved — all firewall_rule
and nat_rule tests pass.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Body-flag loader

**Files:**
- Create: `internal/cli/bodyflag.go`
- Create: `internal/cli/bodyflag_test.go`

- [ ] **Step 1: Write `internal/cli/bodyflag.go`**

```go
package cli

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "strings"

    "gopkg.in/yaml.v3"

    "github.com/iainmoffat/sophosfw/internal/sophos"
)

// LoadBody resolves --body input into a map[string]any.
//
// Source forms:
//
//   - "@/path/to/file" → read file contents
//   - "-"              → read stdin
//   - other            → treat as inline JSON or YAML string
//
// Format auto-detection: try JSON first (cheaper to fail), then YAML.
// Returns ErrInvalidRequest on parse failure or empty input.
func LoadBody(source string) (map[string]any, error) {
    var raw []byte
    var err error
    switch {
    case source == "":
        return nil, fmt.Errorf("%w: --body is required", sophos.ErrInvalidRequest)
    case source == "-":
        raw, err = io.ReadAll(os.Stdin)
    case strings.HasPrefix(source, "@"):
        raw, err = os.ReadFile(source[1:])
    default:
        raw = []byte(source)
    }
    if err != nil {
        return nil, fmt.Errorf("%w: read body: %v", sophos.ErrInvalidRequest, err)
    }
    if len(bytes.TrimSpace(raw)) == 0 {
        return nil, fmt.Errorf("%w: body is empty", sophos.ErrInvalidRequest)
    }
    var body map[string]any
    if jerr := json.Unmarshal(raw, &body); jerr == nil {
        return body, nil
    }
    if yerr := yaml.Unmarshal(raw, &body); yerr == nil {
        return body, nil
    }
    return nil, fmt.Errorf("%w: body is neither valid JSON nor YAML", sophos.ErrInvalidRequest)
}
```

- [ ] **Step 2: Write `internal/cli/bodyflag_test.go`**

```go
package cli

import (
    "errors"
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/require"

    "github.com/iainmoffat/sophosfw/internal/sophos"
)

func TestLoadBody_EmptyArg(t *testing.T) {
    _, err := LoadBody("")
    require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}

func TestLoadBody_InlineJSON(t *testing.T) {
    body, err := LoadBody(`{"Name":"x"}`)
    require.NoError(t, err)
    require.Equal(t, "x", body["Name"])
}

func TestLoadBody_InlineYAML(t *testing.T) {
    body, err := LoadBody(`Name: x
IPFamily: IPv4`)
    require.NoError(t, err)
    require.Equal(t, "x", body["Name"])
    require.Equal(t, "IPv4", body["IPFamily"])
}

func TestLoadBody_FromFile(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "body.yaml")
    require.NoError(t, os.WriteFile(path, []byte("Name: x\n"), 0o600))
    body, err := LoadBody("@" + path)
    require.NoError(t, err)
    require.Equal(t, "x", body["Name"])
}

func TestLoadBody_MissingFile(t *testing.T) {
    _, err := LoadBody("@/no/such/path")
    require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}

func TestLoadBody_Garbage(t *testing.T) {
    _, err := LoadBody("not json or yaml: : :")
    require.True(t, errors.Is(err, sophos.ErrInvalidRequest))
}
```

- [ ] **Step 3: Run**

```bash
go test ./internal/cli -run TestLoadBody -v -count=1
```

Expected: all 6 pass.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/bodyflag.go internal/cli/bodyflag_test.go
git commit -m "$(cat <<'EOF'
cli: add LoadBody helper for --body @file / stdin / inline

Phase 12 adds create/update/delete commands for six object types using
a body-as-map pattern. LoadBody resolves --body input from a file
(@path), stdin (-), or inline string, auto-detecting JSON vs YAML.
Returns ErrInvalidRequest on parse failure or empty input.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: ObjectMutationResult + render helper

**Files:**
- Create: `internal/svc/object_mutation.go`
- Create: `internal/render/object_mutation.go`
- Create: `internal/render/object_mutation_test.go`

- [ ] **Step 1: Write `internal/svc/object_mutation.go`**

```go
package svc

// ObjectMutationResult is the shared result type for the body-as-map
// mutating workflows added in Phase 12 (IPHostGroup, FQDNHost,
// FQDNHostGroup, MACHost, Services, ServiceGroup). Structurally identical
// to FirewallRulePushResult but kept separate to avoid churning the
// existing firewall_rule/nat_rule code paths.
type ObjectMutationResult struct {
    Profile     string
    ObjectType  string
    Name        string
    Operation   string // "create" | "update" | "delete"
    DryRun      bool
    Preview     *Preview
    NewDiffHash string
    Item        map[string]any
}
```

- [ ] **Step 2: Write `internal/render/object_mutation.go`**

```go
package render

import (
    "encoding/json"

    "github.com/iainmoffat/sophosfw/internal/svc"
)

// ObjectMutationEnvelope is the JSON envelope shape for the Phase 12
// mutating workflows. Schema name is per-type to give grep-friendly
// uniqueness — e.g. "sophosfw.v1.ipHostGroupMutation".
func ObjectMutationEnvelope(r *svc.ObjectMutationResult) ([]byte, error) {
    schema := schemaForObjectType(r.ObjectType)
    env := map[string]any{
        "schema":     schema,
        "profile":    r.Profile,
        "objectType": r.ObjectType,
        "name":       r.Name,
        "operation":  r.Operation,
        "applied":    !r.DryRun,
    }
    if r.DryRun && r.Preview != nil {
        env["preview"] = r.Preview
    }
    if !r.DryRun {
        if r.Item != nil {
            env["item"] = r.Item
        }
        if r.NewDiffHash != "" {
            env["newDiffHash"] = r.NewDiffHash
        }
    }
    return json.MarshalIndent(env, "", "  ")
}

// schemaForObjectType returns the per-type envelope schema name.
// Maps XML tag → camelCase short name.
func schemaForObjectType(t string) string {
    switch t {
    case "IPHostGroup":
        return "sophosfw.v1.ipHostGroupMutation"
    case "FQDNHost":
        return "sophosfw.v1.fqdnHostMutation"
    case "FQDNHostGroup":
        return "sophosfw.v1.fqdnHostGroupMutation"
    case "MACHost":
        return "sophosfw.v1.macHostMutation"
    case "Services":
        return "sophosfw.v1.servicesMutation"
    case "ServiceGroup":
        return "sophosfw.v1.serviceGroupMutation"
    }
    return "sophosfw.v1.objectMutation"
}
```

- [ ] **Step 3: Write `internal/render/object_mutation_test.go`**

```go
package render

import (
    "encoding/json"
    "testing"

    "github.com/stretchr/testify/require"

    "github.com/iainmoffat/sophosfw/internal/svc"
)

func TestObjectMutationEnvelope_DryRun(t *testing.T) {
    r := &svc.ObjectMutationResult{
        Profile:    "home",
        ObjectType: "IPHostGroup",
        Name:       "g1",
        Operation:  "create",
        DryRun:     true,
        Preview:    &svc.Preview{Profile: "home", Mutating: true, RedactedXML: "<Set ...>"},
    }
    b, err := ObjectMutationEnvelope(r)
    require.NoError(t, err)
    var env map[string]any
    require.NoError(t, json.Unmarshal(b, &env))
    require.Equal(t, "sophosfw.v1.ipHostGroupMutation", env["schema"])
    require.Equal(t, false, env["applied"])
    require.NotNil(t, env["preview"])
}

func TestObjectMutationEnvelope_Apply(t *testing.T) {
    r := &svc.ObjectMutationResult{
        Profile:     "home",
        ObjectType:  "Services",
        Name:        "ssh",
        Operation:   "update",
        DryRun:      false,
        NewDiffHash: "abc",
        Item:        map[string]any{"Name": "ssh"},
    }
    b, err := ObjectMutationEnvelope(r)
    require.NoError(t, err)
    var env map[string]any
    require.NoError(t, json.Unmarshal(b, &env))
    require.Equal(t, "sophosfw.v1.servicesMutation", env["schema"])
    require.Equal(t, true, env["applied"])
    require.Equal(t, "abc", env["newDiffHash"])
    require.NotNil(t, env["item"])
}

func TestObjectMutationEnvelope_UnknownType_FallbackSchema(t *testing.T) {
    r := &svc.ObjectMutationResult{Profile: "home", ObjectType: "Mystery", Name: "x", Operation: "create", DryRun: false}
    b, err := ObjectMutationEnvelope(r)
    require.NoError(t, err)
    var env map[string]any
    require.NoError(t, json.Unmarshal(b, &env))
    require.Equal(t, "sophosfw.v1.objectMutation", env["schema"])
}
```

- [ ] **Step 4: Run**

```bash
go test ./internal/render -run TestObjectMutationEnvelope -v -count=1
```

Expected: all 3 pass.

- [ ] **Step 5: Commit**

```bash
git add internal/svc/object_mutation.go internal/render/object_mutation.go internal/render/object_mutation_test.go
git commit -m "$(cat <<'EOF'
svc/render: ObjectMutationResult + ObjectMutationEnvelope helper

Phase 12 introduces shared types for the body-as-map create/update/
delete pattern across six object types. ObjectMutationResult is
structurally identical to FirewallRulePushResult but kept separate to
avoid churning firewall_rule/nat_rule. Per-type envelope schema names
give grep-friendly uniqueness (sophosfw.v1.ipHostGroupMutation,
sophosfw.v1.fqdnHostMutation, etc.).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Generic `object_get` `_diffHash` injection

**Files:**
- Modify: `internal/svc/object.go`
- Modify: `internal/svc/object_test.go`
- Modify: `internal/mcp/object.go` (if MCP handler doesn't already pass-through)
- Modify: `internal/mcp/object_test.go` if needed

- [ ] **Step 1: Find the `Get` method**

```bash
grep -n "^func.*ObjectSvc.*Get\b" internal/svc/object.go
```

Read the function. Identify where the parsed body is returned.

- [ ] **Step 2: Inject `_diffHash` for mutable types**

After the response is parsed but before returning, look up the catalog entry for the type. If `entry.Mutable` is true, compute `DiffHash(record)` and set `record["_diffHash"] = hash`.

Concrete sketch (adapt to actual Get signature):

```go
// after: record, err := s.parseGet(...)
if entry, ok := s.Catalog.Resolve(objectType); ok && entry.Mutable && record != nil {
    if hash, hashErr := DiffHash(record); hashErr == nil {
        record["_diffHash"] = hash
    }
}
return record, nil
```

(If `DiffHash` lives elsewhere, locate it: `grep -n "^func DiffHash" internal/svc/`.)

- [ ] **Step 3: Write `TestObjectSvc_Get_InjectsDiffHashForMutableTypes`**

Add to `internal/svc/object_test.go`:

```go
func TestObjectSvc_Get_InjectsDiffHashForMutableTypes(t *testing.T) {
    // Use an existing test fixture or build a minimal fake client returning
    // an IPHost record. Then call Get and assert _diffHash is present.
    // Pattern mirrors existing TestObjectSvc_Get_* tests in this file.
    s, fc := newTestObjectSvc(t)  // existing helper
    fc.body = map[string][]json.RawMessage{
        "IPHost": {json.RawMessage(`{"Name":"x","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
    }
    record, err := s.Get(context.Background(), "home", "IPHost", "Name", "x")
    require.NoError(t, err)
    require.NotNil(t, record)
    require.NotEmpty(t, record["_diffHash"])
}

func TestObjectSvc_Get_DoesNotInjectDiffHashForImmutableTypes(t *testing.T) {
    s, fc := newTestObjectSvc(t)
    fc.body = map[string][]json.RawMessage{
        "Zone": {json.RawMessage(`{"Name":"LAN","Type":"LAN"}`)},
    }
    record, err := s.Get(context.Background(), "home", "Zone", "Name", "LAN")
    require.NoError(t, err)
    require.NotNil(t, record)
    _, has := record["_diffHash"]
    require.False(t, has, "Zone is immutable; _diffHash should not be injected")
}
```

If `newTestObjectSvc` does not exist, look at how existing tests in `object_test.go` build the svc and follow the same pattern. The point is to fake a `Client` that returns the body for a given tag.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/svc -run "TestObjectSvc_Get" -v -count=1
```

Expected: pre-existing tests still pass; two new tests pass.

If pre-existing tests now fail because they assert exact returned-body shape, update those assertions to either ignore `_diffHash` or to check it explicitly. Document the fixes inline.

- [ ] **Step 5: Verify MCP `object_get` returns the injected hash**

The MCP `object_get` handler likely just calls `ObjectSvc.Get` and returns the result. If so, no changes needed. Verify:

```bash
grep -n "object_get\|handleObjectGet\|ObjectGet" internal/mcp/object.go
```

If the handler does any post-processing of the returned body, ensure `_diffHash` is preserved.

Add a single MCP test:

```go
// internal/mcp/object_test.go
func TestMcpObjectGet_PassesDiffHashThrough(t *testing.T) {
    s, fc := newTestMcpServer(t)  // existing helper
    fc.body = map[string][]json.RawMessage{
        "IPHost": {json.RawMessage(`{"Name":"x","IPFamily":"IPv4","HostType":"IP","IPAddress":"1.1.1.1"}`)},
    }
    out, _, err := s.handleObjectGet(context.Background(), nil, ObjectGetInput{
        ObjectType: "IPHost", Filter: "Name:eq:x",
    })
    require.NoError(t, err)
    require.Contains(t, textOf(out), `"_diffHash"`)
}
```

If `newTestMcpServer` and helper names differ, look at neighboring tests in `internal/mcp/object_test.go` to find the actual fixtures.

- [ ] **Step 6: Run full test suite**

```bash
go test ./... -count=1 -race
golangci-lint run ./...
```

Expected: green.

- [ ] **Step 7: Commit**

```bash
git add internal/svc/object.go internal/svc/object_test.go internal/mcp/object.go internal/mcp/object_test.go
git commit -m "$(cat <<'EOF'
svc/mcp: inject _diffHash into object_get for catalog-mutable types

Phase 12 update/delete callers need a way to obtain the diff hash for
their expectedDiffHash arg. Generalize the firewall_rule_show /
nat_rule_show pattern: ObjectSvc.Get now injects _diffHash when the
catalog entry is Mutable. CLI object get -o json / -o yaml and MCP
object_get both surface the hash. Immutable types (Zone, Interface,
GatewayConfiguration) are unaffected.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Per-type tasks template

Tasks 6-11 each implement one type. Task 6 (IPHostGroup) is fully spec'd as the **template**. Tasks 7-11 follow the same shape with the substitutions in the table below.

### Per-type substitution table

| Field | IPHostGroup | FQDNHost | FQDNHostGroup | MACHost | Services | ServiceGroup |
|---|---|---|---|---|---|---|
| XML tag | `IPHostGroup` | `FQDNHost` | `FQDNHostGroup` | `MACHost` | `Services` | `ServiceGroup` |
| Required keys | `Name`, `IPFamily` | `Name`, `FQDN`, `IPFamily` | `Name`, `IPFamily` | `Name`, `Type` (+ MAC XOR — see note) | `Name`, `Type`, `ServiceDetails` | `Name` |
| svc file | `iphostgroup.go` | `fqdnhost.go` | `fqdnhostgroup.go` | `machost.go` | `services.go` | `servicegroup.go` |
| svc type | `IPHostGroupSvc` | `FQDNHostSvc` | `FQDNHostGroupSvc` | `MACHostSvc` | `ServicesSvc` | `ServiceGroupSvc` |
| CLI parent | `host` | `host` | `host` | `host` | `service` | `service` |
| CLI sub-name | `group` | `fqdn` | `fqdn-group` | `mac` | (root verbs added to existing `service`) | `group` |
| MCP tool prefix | `host_group_` | `host_fqdn_` | `host_fqdn_group_` | `host_mac_` | `service_` | `service_group_` |
| Audit op prefix | `ip_host_group_` | `fqdn_host_` | `fqdn_host_group_` | `mac_host_` | `services_` | `service_group_` |
| Envelope schema | `ipHostGroup` | `fqdnHost` | `fqdnHostGroup` | `macHost` | `services` | `serviceGroup` |

**MAC XOR note (MACHost only):** the `Create` / `Update` validators for MACHost must additionally check that exactly one of `MACAddress` (string) or `MACAddressList` (list) is set in the body, returning `ErrInvalidRequest` if both or neither. Sophos error messages here are unhelpful. See Task 9 step 2 for the validator code.

---

## Task 6: IPHostGroup mutating surface (template)

**Files:**
- Create: `internal/svc/iphostgroup.go`
- Create: `internal/svc/iphostgroup_test.go`
- Create: `internal/cli/iphostgroup_mutation.go`
- Create: `internal/cli/iphostgroup_mutation_test.go`
- Create: `internal/mcp/iphostgroup_mutation.go`
- Create: `internal/mcp/iphostgroup_mutation_test.go`
- Modify: `internal/cli/host.go` (register `host group` sub-parent)
- Modify: `internal/mcp/server.go` or per-type registration (matching firewallrule.go factory pattern)
- Modify: `internal/mcp/server_test.go` (tool count 30 → 33; add 3 names)

- [ ] **Step 1: Write `internal/svc/iphostgroup.go`**

```go
package svc

import (
    "context"
    "fmt"
    "time"

    "github.com/iainmoffat/sophosfw/internal/safety"
    "github.com/iainmoffat/sophosfw/internal/sophos"
)

type IPHostGroupSvc struct {
    Inner *ObjectSvc
    Audit *AuditLog
    Now   func() time.Time
}

func (s *IPHostGroupSvc) now() time.Time {
    if s.Now != nil {
        return s.Now()
    }
    return time.Now().UTC()
}

var requiredIPHostGroupFields = []string{"Name", "IPFamily"}

func (s *IPHostGroupSvc) Create(ctx context.Context, profileName, name string, body map[string]any, dryRun bool) (out *ObjectMutationResult, err error) {
    return s.mutate(ctx, profileName, name, body, "create", "", false, dryRun)
}

func (s *IPHostGroupSvc) Update(ctx context.Context, profileName, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (out *ObjectMutationResult, err error) {
    return s.mutate(ctx, profileName, name, body, "update", expectedHash, ignoreHash, dryRun)
}

func (s *IPHostGroupSvc) Delete(ctx context.Context, profileName, name string, expectedHash string, ignoreHash, dryRun bool) (out *ObjectMutationResult, err error) {
    return s.mutate(ctx, profileName, name, nil, "delete", expectedHash, ignoreHash, dryRun)
}

func (s *IPHostGroupSvc) mutate(ctx context.Context, profileName, name string, body map[string]any, op string, expectedHash string, ignoreHash, dryRun bool) (out *ObjectMutationResult, err error) {
    profile, resolvedName, perr := s.Inner.Config.ActiveProfile(profileName)
    if perr != nil {
        return nil, perr
    }

    entryAudit := AuditEntry{
        Profile:    resolvedName,
        Operation:  "ip_host_group_" + op,
        ObjectType: "IPHostGroup",
        ObjectName: name,
    }
    defer func() {
        if err != nil && s.Audit != nil && entryAudit.Result == "" {
            entryAudit.Result = "error:" + ErrorKind(err)
            entryAudit.ErrorMessage = err.Error()
            _ = s.Audit.Write(entryAudit)
        }
    }()

    if profile.ReadOnly {
        return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, resolvedName)
    }

    catEntry, ok := s.Inner.Catalog.Resolve("IPHostGroup")
    if !ok || !catEntry.Mutable {
        return nil, fmt.Errorf("%w: IPHostGroup is not flagged mutable in the catalog", sophos.ErrInvalidRequest)
    }

    if op != "delete" {
        for _, k := range requiredIPHostGroupFields {
            v, ok := body[k]
            if !ok {
                return nil, fmt.Errorf("%w: body missing required field %q", sophos.ErrInvalidRequest, k)
            }
            if str, isStr := v.(string); isStr && str == "" {
                return nil, fmt.Errorf("%w: body field %q is empty", sophos.ErrInvalidRequest, k)
            }
        }
    }

    if op != "create" {
        live, gerr := s.Inner.Get(ctx, profileName, "IPHostGroup", "Name", name)
        if gerr != nil {
            return nil, gerr
        }
        if live == nil {
            return nil, fmt.Errorf("IPHostGroup %q: %w", name, sophos.ErrNotFound)
        }
        if !ignoreHash {
            delete(live, "_diffHash")
            currentHash, herr := DiffHash(live)
            if herr != nil {
                return nil, herr
            }
            if expectedHash == "" {
                return nil, fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest)
            }
            if currentHash != expectedHash {
                return nil, fmt.Errorf("%w: expected hash %s but live state has %s", sophos.ErrConcurrentModification, expectedHash, currentHash)
            }
        }
    }

    c, perr := s.Inner.Creds.Load(resolvedName)
    if perr != nil {
        return nil, perr
    }

    var full []byte
    switch op {
    case "create":
        inner, merr := marshalObjectBody("IPHostGroup", body)
        if merr != nil {
            return nil, merr
        }
        full, perr = sophos.BuildSetEnvelope("add", inner, c.Username, c.Password)
    case "update":
        inner, merr := marshalObjectBody("IPHostGroup", body)
        if merr != nil {
            return nil, merr
        }
        full, perr = sophos.BuildSetEnvelope("update", inner, c.Username, c.Password)
    case "delete":
        full, perr = sophos.BuildRemoveEnvelope("IPHostGroup", name, c.Username, c.Password)
    }
    if perr != nil {
        return nil, perr
    }
    entryAudit.RedactedXML = string(safety.RedactXML(full))

    if dryRun {
        mutating, verbs := safety.IsMutating(full)
        pv := &Preview{
            Profile:        resolvedName,
            Mutating:       mutating,
            Verbs:          verbs,
            RedactedXML:    entryAudit.RedactedXML,
            WouldSendBytes: len(full),
        }
        entryAudit.Result = "ok (dry-run)"
        if s.Audit != nil {
            _ = s.Audit.Write(entryAudit)
        }
        return &ObjectMutationResult{
            Profile:    resolvedName,
            ObjectType: "IPHostGroup",
            Name:       name,
            Operation:  op,
            DryRun:     true,
            Preview:    pv,
        }, nil
    }

    cl := s.Inner.NewClient(profile, c)
    if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
        entryAudit.Result = "error:" + ErrorKind(sendErr)
        entryAudit.ErrorMessage = sendErr.Error()
        if s.Audit != nil {
            _ = s.Audit.Write(entryAudit)
        }
        return nil, sendErr
    }
    entryAudit.Result = "ok"
    if s.Audit != nil {
        _ = s.Audit.Write(entryAudit)
    }

    result := &ObjectMutationResult{
        Profile:    resolvedName,
        ObjectType: "IPHostGroup",
        Name:       name,
        Operation:  op,
        DryRun:     false,
    }
    if op != "delete" {
        refetched, _ := s.Inner.Get(ctx, profileName, "IPHostGroup", "Name", name)
        if refetched != nil {
            delete(refetched, "_diffHash")
            if newHash, herr := DiffHash(refetched); herr == nil {
                result.NewDiffHash = newHash
                result.Item = refetched
            }
        }
    }
    return result, nil
}
```

- [ ] **Step 2: Write `internal/svc/iphostgroup_test.go`**

Mirror the firewall_rule create/update/delete tests. Fixtures use the test-helper pattern (`newTestObjectSvc` or whatever exists in `internal/svc/object_test.go`). Test names:

```
TestIPHostGroup_Create_RejectsMissingRequiredField
TestIPHostGroup_Create_RejectsReadOnlyProfile
TestIPHostGroup_Create_DryRun_EmitsPreview
TestIPHostGroup_Create_Apply_SendsAddEnvelope
TestIPHostGroup_Update_RejectsMissingExpectedDiffHash
TestIPHostGroup_Update_RejectsHashMismatch
TestIPHostGroup_Update_DryRun_EmitsPreview
TestIPHostGroup_Update_Apply_SendsUpdateEnvelope
TestIPHostGroup_Delete_RejectsMissingExpectedDiffHash
TestIPHostGroup_Delete_RejectsHashMismatch
TestIPHostGroup_Delete_Apply_SendsRemoveEnvelope
TestIPHostGroup_Delete_OnMissing_ReturnsNotFound
```

Each test ~10-15 lines following the existing firewall_rule test patterns. Look at `internal/svc/firewallrule_create_test.go` for templates.

Run:
```bash
go test ./internal/svc -run TestIPHostGroup -v -count=1
```

Expected: 12 pass.

- [ ] **Step 3: Write `internal/cli/iphostgroup_mutation.go`**

```go
package cli

import (
    "encoding/json"
    "fmt"

    "github.com/spf13/cobra"

    "github.com/iainmoffat/sophosfw/internal/render"
    "github.com/iainmoffat/sophosfw/internal/svc"
)

func newIPHostGroupCreateCmd(d RootDeps) *cobra.Command {
    var bodyArg string
    var dryRun bool
    cmd := &cobra.Command{
        Use:   "create <name>",
        Short: "Create a new IPHostGroup",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            name := args[0]
            body, err := LoadBody(bodyArg)
            if err != nil {
                return err
            }
            // Force-set Name to match the positional arg.
            if bn, _ := body["Name"].(string); bn != "" && bn != name {
                return fmt.Errorf("body Name %q does not match positional arg %q", bn, name)
            }
            body["Name"] = name

            result, err := iphostGroupSvc(d).Create(cmd.Context(), profileFromFlags(cmd), name, body, dryRun)
            if err != nil {
                return err
            }
            return printObjectMutation(cmd, result)
        },
    }
    cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path (file), - (stdin), or inline JSON/YAML")
    cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview without sending")
    _ = cmd.MarkFlagRequired("body")
    return cmd
}

func newIPHostGroupUpdateCmd(d RootDeps) *cobra.Command {
    var bodyArg, expectedHash string
    var dryRun, ignoreHash bool
    cmd := &cobra.Command{
        Use:   "update <name>",
        Short: "Update an existing IPHostGroup",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            name := args[0]
            body, err := LoadBody(bodyArg)
            if err != nil {
                return err
            }
            if bn, _ := body["Name"].(string); bn != "" && bn != name {
                return fmt.Errorf("body Name %q does not match positional arg %q", bn, name)
            }
            body["Name"] = name
            result, err := iphostGroupSvc(d).Update(cmd.Context(), profileFromFlags(cmd), name, body, expectedHash, ignoreHash, dryRun)
            if err != nil {
                return err
            }
            return printObjectMutation(cmd, result)
        },
    }
    cmd.Flags().StringVar(&bodyArg, "body", "", "body source: @path / - / inline")
    cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required unless --ignore-hash")
    cmd.Flags().BoolVar(&ignoreHash, "ignore-hash", false, "skip the diff-hash check (dangerous)")
    cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview without sending")
    _ = cmd.MarkFlagRequired("body")
    return cmd
}

func newIPHostGroupDeleteCmd(d RootDeps) *cobra.Command {
    var expectedHash string
    var dryRun, ignoreHash bool
    cmd := &cobra.Command{
        Use:   "delete <name>",
        Short: "Delete an IPHostGroup",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            name := args[0]
            result, err := iphostGroupSvc(d).Delete(cmd.Context(), profileFromFlags(cmd), name, expectedHash, ignoreHash, dryRun)
            if err != nil {
                return err
            }
            return printObjectMutation(cmd, result)
        },
    }
    cmd.Flags().StringVar(&expectedHash, "expected-diff-hash", "", "hash from a prior object get; required unless --ignore-hash")
    cmd.Flags().BoolVar(&ignoreHash, "ignore-hash", false, "skip the diff-hash check (dangerous)")
    cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview without sending")
    return cmd
}

func newIPHostGroupCmd(d RootDeps) *cobra.Command {
    cmd := &cobra.Command{Use: "group", Short: "IPHostGroup commands"}
    cmd.AddCommand(newIPHostGroupCreateCmd(d), newIPHostGroupUpdateCmd(d), newIPHostGroupDeleteCmd(d))
    return cmd
}

func iphostGroupSvc(d RootDeps) *svc.IPHostGroupSvc {
    return &svc.IPHostGroupSvc{Inner: objectSvc(d), Audit: d.Audit}
}

func printObjectMutation(cmd *cobra.Command, r *svc.ObjectMutationResult) error {
    body, err := render.ObjectMutationEnvelope(r)
    if err != nil {
        return err
    }
    var pretty any
    _ = json.Unmarshal(body, &pretty)
    out := cmd.OutOrStdout()
    enc := json.NewEncoder(out)
    enc.SetIndent("", "  ")
    return enc.Encode(pretty)
}
```

If `objectSvc(d)` doesn't exist, look at how `firewallRuleSvc(d)` is constructed and follow the same pattern. The helper builds the inner `*ObjectSvc` from `RootDeps`.

If `profileFromFlags(cmd)` doesn't exist, look at how existing CLI mutation commands resolve the profile flag and follow the same pattern.

`printObjectMutation` is shared across all 6 types — define it once here, then per-type CLI files just call it. (It might already exist elsewhere; grep first: `grep -n "printObjectMutation" internal/cli/`. If found, drop the local definition.)

- [ ] **Step 4: Write `internal/cli/iphostgroup_mutation_test.go`**

Mirror existing `internal/cli/firewallrule_*_test.go`. At minimum:

```go
TestCmd_HostGroupCreate_DryRun_Smoke
TestCmd_HostGroupCreate_RejectsBodyNameMismatch
TestCmd_HostGroupUpdate_DryRun_Smoke
TestCmd_HostGroupDelete_DryRun_Smoke
```

Use the existing fake-client + fixture fakes from neighbor tests.

- [ ] **Step 5: Wire `host group` into the host parent**

Read `internal/cli/host.go`. The current parent registers `host ip`. Append:

```go
cmd.AddCommand(newIPHostGroupCmd(d))
```

so the tree becomes:

```
host
├── ip
│   ├── create / update / delete / list / show / search / usage
└── group
    ├── create
    ├── update
    └── delete
```

Run:
```bash
go run ./cmd/sophosfw host group create --help
```

Expected: cobra help with `--body` flag visible.

- [ ] **Step 6: Write `internal/mcp/iphostgroup_mutation.go`**

Mirror `internal/mcp/firewallrule_mutation.go` exactly with substitutions. Input types `IPHostGroupCreateInput`, `IPHostGroupUpdateInput`, `IPHostGroupDeleteInput`; handlers `handleIPHostGroupCreate`, etc.; tool registrations in a factory `iphostGroupSvc(s.deps)` (mirror `firewallRuleSvc(s.deps)`).

Tool descriptions:

```
host_group_create:
  Create a new IPHostGroup. Requires confirm: true. Use dryRun: true to preview.
  Required body keys: Name, IPFamily. The body Name must match the name argument.

host_group_update:
  Update an existing IPHostGroup. Requires confirm: true AND expectedDiffHash from
  a prior object_get of IPHostGroup. Use dryRun: true to preview.

host_group_delete:
  Delete an IPHostGroup by name. Requires confirm: true AND expectedDiffHash from
  a prior object_get of IPHostGroup.
```

Annotations: create + update get `ReadOnlyHint: false`; delete adds `DestructiveHint: ptrBool(true)`.

- [ ] **Step 7: Write `internal/mcp/iphostgroup_mutation_test.go`**

8 tests mirroring `internal/mcp/firewallrule_mutation_test.go`:

```
TestIPHostGroupCreate_Handler_RequiresConfirm
TestIPHostGroupCreate_Handler_DryRun
TestIPHostGroupCreate_Handler_Apply
TestIPHostGroupUpdate_Handler_RequiresExpectedDiffHash
TestIPHostGroupUpdate_Handler_DryRun
TestIPHostGroupUpdate_Handler_Apply
TestIPHostGroupDelete_Handler_RequiresExpectedDiffHash
TestIPHostGroupDelete_Handler_DiffHashMatch_Applies
```

- [ ] **Step 8: Update tool count assertion**

In `internal/mcp/server_test.go`, update the count assertion:

```
30 → 33  (this task adds 3 new tools)
```

Add 3 new tool names to the expected list: `host_group_create`, `host_group_update`, `host_group_delete`.

(Subsequent tasks 7-11 each bump the count by 3 more.)

- [ ] **Step 9: Run full suite**

```bash
go test ./... -count=1 -race
golangci-lint run ./...
```

Expected: green.

- [ ] **Step 10: Smoke the CLI**

```bash
go run ./cmd/sophosfw host group create --help
go run ./cmd/sophosfw host group update --help
go run ./cmd/sophosfw host group delete --help
```

Expected: cobra help visible for each.

- [ ] **Step 11: Commit**

```bash
git add internal/svc/iphostgroup.go internal/svc/iphostgroup_test.go \
         internal/cli/iphostgroup_mutation.go internal/cli/iphostgroup_mutation_test.go \
         internal/cli/host.go \
         internal/mcp/iphostgroup_mutation.go internal/mcp/iphostgroup_mutation_test.go \
         internal/mcp/server_test.go
git commit -m "$(cat <<'EOF'
feat(svc/cli/mcp): IPHostGroup create/update/delete

Body-as-map mutating surface for IPHostGroup. CLI: host group
create/update/delete with --body @file. MCP: host_group_create/update/
delete (3 new tools, count 30 to 33). Required body keys: Name,
IPFamily. Update + delete gate on expectedDiffHash unless
--ignore-hash. Audit ops: ip_host_group_{create,update,delete}.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: FQDNHost mutating surface

Repeat the Task 6 steps with the FQDNHost row from the substitution table. Specifically:

- Files: `internal/svc/fqdnhost.go`, `internal/cli/fqdnhost_mutation.go`, `internal/mcp/fqdnhost_mutation.go` (+ tests).
- Required keys: `Name`, `FQDN`, `IPFamily`.
- CLI sub-name under `host`: `fqdn`.
- MCP tool prefix: `host_fqdn_`.
- Audit op prefix: `fqdn_host_`.
- XML tag: `FQDNHost`.
- Tool count assertion: 33 → 36.

Tool descriptions:

```
host_fqdn_create:
  Create a new FQDNHost. Required body keys: Name, FQDN, IPFamily.
  Wildcard FQDNs (*.example.com) are accepted.

host_fqdn_update / host_fqdn_delete:
  (mirror IPHostGroup pattern with FQDNHost in place)
```

Wire `host fqdn` into `internal/cli/host.go`.

Commit message:

```
feat(svc/cli/mcp): FQDNHost create/update/delete

Body-as-map mutating surface for FQDNHost. CLI: host fqdn
create/update/delete. MCP: host_fqdn_create/update/delete (3 new
tools, count 33 to 36). Required body keys: Name, FQDN, IPFamily.
Audit ops: fqdn_host_{create,update,delete}.
```

---

## Task 8: FQDNHostGroup mutating surface

Substitution table row: FQDNHostGroup. Required keys: `Name`, `IPFamily`. CLI sub-name: `fqdn-group`. MCP prefix: `host_fqdn_group_`. Audit prefix: `fqdn_host_group_`. Tool count: 36 → 39.

Wire `host fqdn-group` into `internal/cli/host.go`.

Commit message:

```
feat(svc/cli/mcp): FQDNHostGroup create/update/delete

Body-as-map mutating surface for FQDNHostGroup. CLI: host fqdn-group
create/update/delete. MCP: host_fqdn_group_create/update/delete (3
new tools, count 36 to 39). Required body keys: Name, IPFamily.
Audit ops: fqdn_host_group_{create,update,delete}.
```

---

## Task 9: MACHost mutating surface

Substitution table row: MACHost. Required keys: `Name`, `Type` (and the MAC XOR — see step 2 below). CLI sub-name: `mac`. MCP prefix: `host_mac_`. Audit prefix: `mac_host_`. Tool count: 39 → 42.

- [ ] **Step 1: Standard per-type implementation**

Follow Task 6 with the MACHost substitutions.

- [ ] **Step 2: Add MAC XOR validator**

In `internal/svc/machost.go`, after the standard required-fields check and before the marshal step, add:

```go
if op != "delete" {
    _, hasMAC := body["MACAddress"].(string)
    macList, hasList := body["MACAddressList"]
    listSet := false
    if hasList {
        switch v := macList.(type) {
        case []any:
            listSet = len(v) > 0
        case []string:
            listSet = len(v) > 0
        case map[string]any:
            // Sophos sometimes nests as <MACAddressList><MAC>...</MAC></MACAddressList>
            listSet = len(v) > 0
        }
    }
    if hasMAC && listSet {
        return nil, fmt.Errorf("%w: body cannot set both MACAddress and MACAddressList; use exactly one", sophos.ErrInvalidRequest)
    }
    if !hasMAC && !listSet {
        return nil, fmt.Errorf("%w: body must set exactly one of MACAddress (string) or MACAddressList (list)", sophos.ErrInvalidRequest)
    }
}
```

Add a test:
```go
TestMACHost_Create_RejectsBothMACAndList
TestMACHost_Create_RejectsNeitherMACNorList
TestMACHost_Create_AcceptsSingleMACAddress
TestMACHost_Create_AcceptsMACAddressList
```

- [ ] **Step 3: Wire `host mac` into `internal/cli/host.go`**

Commit message:

```
feat(svc/cli/mcp): MACHost create/update/delete

Body-as-map mutating surface for MACHost. CLI: host mac
create/update/delete. MCP: host_mac_create/update/delete (3 new
tools, count 39 to 42). Required body keys: Name, Type. Body must
set exactly one of MACAddress (string) or MACAddressList (list) —
client-side XOR validator since Sophos error messages here are
unhelpful. Audit ops: mac_host_{create,update,delete}.
```

---

## Task 10: Services mutating surface

Substitution table row: Services. Required keys: `Name`, `Type`, `ServiceDetails`. CLI: extends existing `service` parent with create/update/delete (root verbs, NOT a sub-parent). MCP prefix: `service_`. Audit prefix: `services_`. Tool count: 42 → 45.

**Caveat:** Services has polymorphic `ServiceDetails` (TCP/UDP, IP, ICMP, ICMPv6). Body-as-map handles this naturally — the user supplies the right shape. The MCP tool description must point users at `object get Services <name> -o json` for shape examples.

- [ ] **Step 1: Standard per-type implementation**

Follow Task 6 with Services substitutions.

- [ ] **Step 2: CLI wiring**

Read `internal/cli/service.go`. The current parent registers `service list/show/search/usage`. Append `service create/update/delete` directly (NOT under a sub-parent like the others — `service` is already a parent). Final tree:

```
service
├── list / show / search / usage   (existing)
├── create / update / delete       (this task)
└── group / ...                    (Task 11)
```

- [ ] **Step 3: MCP tool descriptions**

```
service_create:
  Create a new Service. Required body keys: Name, Type, ServiceDetails.
  Type is "TCPorUDP", "IP", "ICMP", or "ICMPv6". The shape of
  ServiceDetails varies by Type — call object_get with objectType:
  "Services" on an existing service to learn the schema.

service_update / service_delete:
  (standard mirror)
```

Commit message:

```
feat(svc/cli/mcp): Services create/update/delete

Body-as-map mutating surface for Services. CLI: service
create/update/delete extends the existing service parent (sibling to
the existing list/show/search/usage verbs). MCP: service_create/
update/delete (3 new tools, count 42 to 45). Required body keys:
Name, Type, ServiceDetails. ServiceDetails is polymorphic by Type —
documented in the MCP tool description. Audit ops:
services_{create,update,delete}.
```

---

## Task 11: ServiceGroup mutating surface

Substitution table row: ServiceGroup. Required keys: `Name`. CLI: under `service group`. MCP prefix: `service_group_`. Audit prefix: `service_group_`. Tool count: 45 → 48.

Wire `service group` into `internal/cli/service.go` as a sub-parent (sibling of the new create/update/delete from Task 10).

Commit message:

```
feat(svc/cli/mcp): ServiceGroup create/update/delete

Body-as-map mutating surface for ServiceGroup. CLI: service group
create/update/delete. MCP: service_group_create/update/delete (3 new
tools, count 45 to 48). Required body keys: Name. Audit ops:
service_group_{create,update,delete}.
```

---

## Task 12: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

- [ ] **Step 1: Append per-type integration tests (build-tagged)**

Add at the end of `internal/testutil/integration_test.go`:

```go
func TestIntegration_MCPHostGroupCreate_DryRun(t *testing.T) {
    profileName := os.Getenv("SOPHOSFW_PROFILE")
    require.NotEmpty(t, profileName)
    if os.Getenv("SOPHOSFW_TEST_HOSTGROUP_NAME") == "" {
        t.Skip("set SOPHOSFW_TEST_HOSTGROUP_NAME to a name not in use on the testvm")
    }
    grpName := os.Getenv("SOPHOSFW_TEST_HOSTGROUP_NAME")

    // ... wire MCP server (mirror TestIntegration_MCPFirewallRuleUpdate_DryRun) ...

    result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
        Name: "host_group_create",
        Arguments: map[string]any{
            "name":    grpName,
            "body":    map[string]any{"Name": grpName, "IPFamily": "IPv4"},
            "confirm": true,
            "dryRun":  true,
        },
    })
    require.NoError(t, err)
    require.False(t, result.IsError)
    tc := result.Content[0].(*sdkmcp.TextContent)
    require.Contains(t, tc.Text, `"schema": "sophosfw.v1.preview"`)
}
```

Add one such test per type for the create dry-run path. Total: 6 new integration tests.

(For exhaustive coverage, also add update/delete dry-run smokes — but at minimum, create dry-run per type proves the round-trip.)

- [ ] **Step 2: Build with integration tag**

```bash
go build -tags=integration ./internal/testutil/...
```

Expected: clean build.

- [ ] **Step 3: Run the integration tests against the testvm**

```bash
SOPHOSFW_PROFILE=testvm \
SOPHOSFW_TEST_HOSTGROUP_NAME='sophosfw-test-grp' \
SOPHOSFW_TEST_FQDNHOST_NAME='sophosfw-test-fqdn' \
SOPHOSFW_TEST_FQDNHOSTGROUP_NAME='sophosfw-test-fqdn-grp' \
SOPHOSFW_TEST_MACHOST_NAME='sophosfw-test-mac' \
SOPHOSFW_TEST_SERVICES_NAME='sophosfw-test-svc' \
SOPHOSFW_TEST_SERVICEGROUP_NAME='sophosfw-test-svc-grp' \
go test -tags=integration ./internal/testutil -run "TestIntegration_MCP(HostGroup|FQDNHost|FQDNHostGroup|MACHost|Services|ServiceGroup)Create_DryRun" -v
```

Expected: 6 PASS.

- [ ] **Step 4: Manual smoke — full create + delete cycle for IPHostGroup**

```bash
go run ./cmd/sophosfw host group create sophosfw-test-grp --body @testdata/iphostgroup.yaml --dry-run
go run ./cmd/sophosfw host group create sophosfw-test-grp --body @testdata/iphostgroup.yaml --yes  # actually create
HASH=$(go run ./cmd/sophosfw object get IPHostGroup --filter Name:eq:sophosfw-test-grp -o json | jq -r ._diffHash)
test -n "$HASH" && echo "got hash: $HASH"
go run ./cmd/sophosfw host group delete sophosfw-test-grp --expected-diff-hash "$HASH" --yes
```

Create the testdata file:

```bash
mkdir -p testdata
cat > testdata/iphostgroup.yaml <<'EOF'
Name: sophosfw-test-grp
IPFamily: IPv4
EOF
```

Expected: dry-run prints preview; apply prints `"applied": true`; hash extracted non-empty; delete prints `"applied": true`.

(Don't commit the testdata file — it's a local smoke artifact. Or commit if you want it as a fixture; user's choice.)

- [ ] **Step 5: Commit integration tests**

```bash
git add internal/testutil/integration_test.go
git commit -m "$(cat <<'EOF'
test: phase 12 MCP mutation integration smoke (6 types)

Per-type create dry-run smokes for IPHostGroup, FQDNHost,
FQDNHostGroup, MACHost, Services, ServiceGroup over in-memory MCP
transport. Each test skips unless SOPHOSFW_TEST_<TYPE>_NAME is set,
so CI never runs them. Pattern mirrors Phase 10 firewall/nat smokes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Docs + tag v0.10.0 + verify release

**Files:**
- Modify: `docs/api-coverage.md`
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update `docs/api-coverage.md`**

Update the six rows for IPHostGroup, FQDNHost, FQDNHostGroup, MACHost, Services, ServiceGroup. Each goes from "partial" / "Phase 6" / "Phase 8" to "Phase 12" with the new tool names.

Example for IPHostGroup row:

Before:
```
| Host | IPHostGroup | object list/get IPHostGroup | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
```

After:
```
| Host | IPHostGroup | object list/get IPHostGroup; host group create/update/delete | host_group_create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host group create; host_group_create) | yes (sophosfw host group update; host_group_update) | yes (sophosfw host group delete; host_group_delete) | yes | Phase 12 |
```

Repeat for each of the 6 rows with the right command + tool names.

- [ ] **Step 2: Update `docs/roadmap.md`**

Append:

```
- Phase 12 — Mutating coverage breadth (host groups, FQDN, MAC, services) (complete; v0.10.0)
```

after the Phase 11 line.

- [ ] **Step 3: Final test pass**

```bash
go fmt ./... && go vet ./... && golangci-lint run ./... && go test -race ./...
```

Expected: clean.

- [ ] **Step 4: Commit + push**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "$(cat <<'EOF'
docs: phase 12 complete in roadmap and api-coverage

Six types (IPHostGroup, FQDNHost, FQDNHostGroup, MACHost, Services,
ServiceGroup) now have full create/update/delete coverage in CLI and
MCP. api-coverage rows updated accordingly. Roadmap marks Phase 12
complete with v0.10.0 tag.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git push origin main
```

Wait for CI green:

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

- [ ] **Step 5: Tag v0.10.0**

```bash
git tag -a v0.10.0 -m "v0.10.0 — Phase 12: mutating coverage breadth

CLI + MCP create/update/delete for IPHostGroup, FQDNHost, FQDNHostGroup,
MACHost, Services, ServiceGroup. 18 new MCP tools (30 to 48 total).
Body-as-map pattern (mirror firewall_rule/nat_rule). Generic object_get
now injects _diffHash for catalog-mutable types so update/delete
callers can fetch the hash. Unified marshalObjectBody helper replaces
per-type marshal functions for firewall/nat/new types."
git push origin v0.10.0
```

- [ ] **Step 6: Watch the release workflow**

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

If failure:

```bash
gh run view --repo iainmoffat/sophosfw "$RUN_ID" --log-failed | tail -50
```

- [ ] **Step 7: Verify release artifacts**

```bash
gh release view v0.10.0 --repo iainmoffat/sophosfw --json name,tagName,assets --jq '{name, tagName, assets: [.assets[].name]}'
```

Expected: 5 assets (checksums + 4 platform tarballs). Each tarball contains binary + LICENSE + completions.

- [ ] **Step 8: Verify tap formula updated**

```bash
gh api repos/iainmoffat/homebrew-sophosfw/contents/sophosfw.rb --jq '.content' | base64 -d | grep -E '^  version|^  license'
```

Expected:
```
  license "MIT"
  version "0.10.0"
```

- [ ] **Step 9: Verify brew upgrade**

```bash
brew update
brew upgrade sophosfw
sophosfw version
```

Expected: `sophosfw 0.10.0 (...)`.

- [ ] **Step 10: Final smoke — exercise one new command path**

```bash
sophosfw host group --help
```

Expected: cobra help shows `create / update / delete`.

---

## End of plan

## Self-review checklist

- ✅ **Spec coverage:** Section 3.1 (catalog) → T1; Section 3.2 (required fields) → embedded in T6-T11; Section 3.3 (svc) → T6-T11; Section 3.4 (CLI) → T6-T11; Section 3.5 (MCP) → T6-T11; Section 3.6 (object_get _diffHash) → T5; Section 3.7 (body loader) → T3; Section 7 (acceptance) → T13. Marshal helper unification (Section 8) → T2. ObjectMutationResult + envelope (parts of 3.3 / 3.4) → T4.
- ✅ **No placeholders.** Per-type tasks reference the substitution table and the Task 6 template; no "TBD" or "implement later" anywhere.
- ✅ **Type/file consistency.** XML tags, audit op names, MCP tool prefixes, envelope schema names all match across the substitution table and the Task 6 code.
- ✅ **Dependency order.** Catalog flags (T1) → marshal helper + refactor (T2) → body loader (T3) → result+envelope (T4) → object_get _diffHash (T5) → per-type implementations (T6-T11, each independent of the others) → integration smoke (T12) → release (T13).
- ✅ **Tool count math.** 30 + 3×6 = 48. Each per-type task bumps the count by 3: T6 (33), T7 (36), T8 (39), T9 (42), T10 (45), T11 (48).
- ✅ **Acceptance verifiable.** T13 includes `brew upgrade` + version check. T12 includes 6 integration smokes against the live testvm.

## Notes for the implementer

- **Subagent-driven flow:** the per-type tasks (T6-T11) are mechanical mirrors. After T6 is approved, T7-T11 can be a single subagent each with a tight prompt referencing T6 as the template plus the substitution table row. Reviews on T7-T11 can be lighter (mechanical-mirror pacing).
- **Token handling:** T13 release relies on `HOMEBREW_TAP_TOKEN` already in repo secrets (added in Phase 11). No new operator action required for the release.
- **If a per-type task hits an unexpected Sophos error**: the most likely cause is required-field misalignment. Sophos error responses have a status code + message; if the error mentions a required field not in the table, update the table for that type and add it to the validator.
