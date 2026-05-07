# Phase 12 — Mutating coverage breadth (design)

**Date:** 2026-05-03
**Status:** Design (pre-implementation)
**Goal:** Add create/update/delete coverage (CLI + MCP) for the six object types currently flagged "partial" in `docs/api-coverage.md` — IPHostGroup, FQDNHost, FQDNHostGroup, MACHost, Services, ServiceGroup. Ship as `v0.10.0`.

---

## 1. Motivation

`docs/api-coverage.md` lists six types where Sophos exposes mutations but sophosfw only exposes read-only access:

- **IPHostGroup** — group of IPHosts
- **FQDNHost** — DNS-name host targets
- **FQDNHostGroup** — group of FQDNHosts
- **MACHost** — MAC-address host targets
- **Services** — TCP/UDP/IP/ICMP service definitions
- **ServiceGroup** — group of Services

Closing this gap doubles the mutating surface (host_ip + firewall_rule + nat_rule = 9 mutating tools today; this phase adds 18). It also gives agents a consistent surface across the catalog: every type listed in `api-coverage.md` will have full CRUD. Once Phase 12 ships, the only tags without mutating coverage are network types (Zone, Interface, GatewayConfiguration), which are deliberately deferred.

## 2. Architecture

Pattern mirrors firewall_rule/nat_rule (Phases 9-10): **body-as-map** via inline `Body map[string]any` arguments — no draft files, no per-type typed inputs. Single new code shape repeated six times with different XML tags + required-field sets.

Three changes that affect more than one type:

1. `internal/catalog/objects.yaml` — six entries gain `mutable: true`.
2. `internal/svc/object.go::Get` (and the MCP `object_get` handler) inject `_diffHash` into the returned body whenever the catalog entry is `Mutable: true`. This is how update/delete callers obtain the hash for `expectedDiffHash`. Today only firewall_rule_show/nat_rule_show inject `_diffHash`; this generalizes it.
3. CLI body source: a small new helper `internal/cli/bodyflag.go` resolves `--body @path` (file) or `--body -` (stdin) into a `map[string]any`, auto-detecting YAML vs JSON by content sniff.

Per-type code is mechanical:
- `internal/svc/<type>.go` — `Create`, `Update`, `Delete` methods + per-type required-fields constant + per-type `marshalXxx` (XML inner element).
- `internal/cli/<type>_mutation.go` — three cobra commands wiring into the parent (`host`, `service`).
- `internal/mcp/<type>_mutation.go` + `_test.go` — 3 input types + 3 handlers per type + 8 tests.

No new dependencies; no new envelope schemas (reuses `sophosfw.v1.<type>Mutation` envelope shape from Phase 6 — generic enough).

## 3. Components

### 3.1 Catalog: mutable flags

Edit `internal/catalog/objects.yaml`: set `mutable: true` on these six entries:

```yaml
- tag: IPHostGroup
  ...
  mutable: true

- tag: FQDNHost
  ...
  mutable: true

# ... etc for FQDNHostGroup, MACHost, Services, ServiceGroup
```

Update the catalog test that asserts which tags are immutable. `TestCatalog_OtherEntriesNotMutable` currently iterates `[FQDNHost, MACHost, Zone, Services]` expecting `Mutable: false`. After Phase 12 the immutable list shrinks to: `Zone, Interface, GatewayConfiguration, IPHost(typed), FirewallRule, NATRule` — actually that's the *mutable* list. Re-state the test as: assert these specific tags are immutable: `Zone`, `Interface`, `GatewayConfiguration`. Everything else in the catalog (after Phase 12) is mutable.

### 3.2 Required fields per type

Each svc method validates the body has these top-level keys (string-non-empty for required scalar fields). Sourced from the Sophos 22.0 XML API docs and existing typed parsers in `internal/catalog/`.

| Type | Required keys | Notes |
|---|---|---|
| `IPHostGroup` | `Name`, `IPFamily` | `HostList` may be empty (group with no members is valid, though unusual). |
| `FQDNHost` | `Name`, `FQDN`, `IPFamily` | Wildcard FQDN (`*.example.com`) accepted. |
| `FQDNHostGroup` | `Name`, `IPFamily` | `FQDNHostList` may be empty. |
| `MACHost` | `Name`, `Type`, exactly one of: `MACAddress` or `MACAddressList` | `Type` is `MACAddress` or `MACList`. Validate XOR client-side; Sophos errors are unhelpful. |
| `Services` | `Name`, `Type`, `ServiceDetails` | `Type` is `TCPorUDP`, `IP`, or `ICMP[v6]`. `ServiceDetails` shape varies; pass-through to Sophos. |
| `ServiceGroup` | `Name` | `ServiceList` may be empty. |

Where the Sophos API documents stricter rules (e.g. `IPFamily` must be `IPv4` or `IPv6`), we **do not** add client-side validation — propagate Sophos errors. Required-field check is the only client-side validation.

### 3.3 svc layer (per type)

For each of the 6 types, create a new file `internal/svc/<type>.go` (where `<type>` is the lowercased XML tag — `iphostgroup.go`, `fqdnhost.go`, etc.) with this shape:

```go
type IPHostGroupSvc struct {
    Inner *ObjectSvc
    Audit *AuditLog
    Now   func() time.Time  // injectable for tests
}

var requiredIPHostGroupFields = []string{"Name", "IPFamily"}

func (s *IPHostGroupSvc) Create(ctx context.Context, profileName, name string, body map[string]any, dryRun bool) (*MutationResult, error)
func (s *IPHostGroupSvc) Update(ctx context.Context, profileName, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*MutationResult, error)
func (s *IPHostGroupSvc) Delete(ctx context.Context, profileName, name string, expectedHash string, ignoreHash, dryRun bool) (*MutationResult, error)
```

Where `ObjectMutationResult` is a new shared struct (decision: do NOT rename `FirewallRulePushResult` — out of scope per section 8, would force churn across firewall/nat code paths). The new struct is structurally identical:

```go
type ObjectMutationResult struct {
    Profile     string
    ObjectType  string  // "IPHostGroup", "FQDNHost", etc.
    Name        string
    Operation   string  // "create" | "update" | "delete"
    DryRun      bool
    Preview     *Preview          // populated only when DryRun
    NewDiffHash string            // populated on apply (re-fetch result)
    Item        map[string]any    // populated on create/update apply
}
```

Audit op naming: `<type>_create`, `<type>_update`, `<type>_delete` (lowercased, snake-cased — e.g. `ip_host_group_create`, `fqdn_host_create`, `services_create`, `service_group_create`).

Each method:
1. Resolve profile via `s.Inner.Config.ActiveProfile`.
2. Build deferred-audit closure (named return + defer, mirroring Phase 9-10 pattern).
3. Validate required fields.
4. Check profile read-only.
5. Check catalog entry is Mutable.
6. Marshal body to inner XML via `marshalXxx(body)` helper.
7. Build envelope with `sophos.BuildSetEnvelope("add"|"update", inner, ...)` (or `BuildRemoveEnvelope` for delete).
8. If `dryRun`: emit Preview; audit `"ok (dry-run)"`; return.
9. Send via client. On success: re-fetch and compute new diff hash. (Snapshots: NOT written for these types — host_ip pattern, no draft files.)
10. Audit `"ok"` and return result.

Update path additionally: if `!ignoreHash`, fetch current state, compute its hash, compare with `expectedHash` — mismatch → `ErrInvalidRequest`.
Delete path same as update for the hash check.

`marshalXxx(body map[string]any) ([]byte, error)` is a helper that recursively walks the map and emits XML using the existing `writeKeyValue` helper from `internal/svc/firewallrule_create.go` (which already handles security via `validateXMLName`). Each type can reuse the same recursive walker; the only per-type difference is the outer XML element tag name.

**Refactor opportunity:** the current per-type `marshalFirewallRule` and `marshalNATRule` functions are near-identical. Phase 12 can either (a) duplicate the pattern 6 more times, or (b) introduce a single generic `marshalObjectBody(tag string, body map[string]any) ([]byte, error)` and refactor firewall/nat to use it. Recommend (b) — single helper, less code, less drift risk. Implementation in `internal/svc/marshal.go`.

### 3.4 CLI layer (per type)

CLI tree extension:

| New command | Parent |
|---|---|
| `host group create/update/delete` | `host` (existing) |
| `host fqdn create/update/delete` | `host` (existing) |
| `host fqdn-group create/update/delete` | `host` (existing) |
| `host mac create/update/delete` | `host` (existing) |
| `service create/update/delete` | `service` (existing — already has list/show/search/usage) |
| `service group create/update/delete` | `service` (new sub-parent under existing `service`) |

Each command takes:
- Positional `<name>`
- `--body @path` (required for create + update) — file path or `-` for stdin; YAML or JSON auto-detected
- `--expected-diff-hash <hash>` (required for update + delete unless `--ignore-hash`)
- `--ignore-hash` (boolean)
- `--dry-run` (boolean)
- `--yes` (mutating commands inherit the existing `--yes` gate)

Body-flag helper in `internal/cli/bodyflag.go`:

```go
// LoadBody resolves --body input into a map[string]any.
// Source:
//   - "@/path/to/file": read file contents
//   - "-": read stdin
//   - other: treated as inline JSON/YAML string (rare; supported for one-liners)
// Format auto-detection: try JSON first; if that fails, try YAML.
// Returns ErrInvalidRequest on parse failure or empty input.
func LoadBody(source string) (map[string]any, error)
```

Output envelope: reuses the existing `sophosfw.v1.<type>Mutation` shape from Phase 6 (host_ip), generalized as `sophosfw.v1.objectMutation` with `objectType` field. Or per-type names — simpler for grep but more strings.

**Naming decision:** per-type envelope schemas (`sophosfw.v1.ipHostGroupMutation`, etc.) — matches how host_ip / firewall_rule / nat_rule are named today. Six new schema names land in the schema registry.

### 3.5 MCP layer (per type)

18 new tools. Naming:

| Type | MCP tool names |
|---|---|
| IPHostGroup | `host_group_create`, `host_group_update`, `host_group_delete` |
| FQDNHost | `host_fqdn_create`, `host_fqdn_update`, `host_fqdn_delete` |
| FQDNHostGroup | `host_fqdn_group_create`, `host_fqdn_group_update`, `host_fqdn_group_delete` |
| MACHost | `host_mac_create`, `host_mac_update`, `host_mac_delete` |
| Services | `service_create`, `service_update`, `service_delete` |
| ServiceGroup | `service_group_create`, `service_group_update`, `service_group_delete` |

Tool count: 30 → 48.

Per-type MCP file (`internal/mcp/<type>_mutation.go`) follows the firewall_rule_mutation.go shape:

```go
type IPHostGroupCreateInput struct {
    Profile string         `json:"profile,omitempty"`
    Name    string         `json:"name" jsonschema:"required" jsonschema_description:"the group name"`
    Body    map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the IPHostGroup body. Required keys: Name, IPFamily. The Name in body must match the name argument."`
    Confirm bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
    DryRun  bool           `json:"dryRun,omitempty"`
}

type IPHostGroupUpdateInput struct {
    Profile                string         `json:"profile,omitempty"`
    Name                   string         `json:"name" jsonschema:"required"`
    Body                   map[string]any `json:"body" jsonschema:"required"`
    ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get; required unless ignoreExpectedDiffHash=true"`
    IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty"`
    Confirm                bool           `json:"confirm" jsonschema:"required"`
    DryRun                 bool           `json:"dryRun,omitempty"`
}

type IPHostGroupDeleteInput struct {
    Profile                string `json:"profile,omitempty"`
    Name                   string `json:"name" jsonschema:"required"`
    ExpectedDiffHash       string `json:"expectedDiffHash,omitempty"`
    IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
    Confirm                bool   `json:"confirm" jsonschema:"required"`
    DryRun                 bool   `json:"dryRun,omitempty"`
}
```

Annotations: create/update get `ReadOnlyHint: false`; delete adds `DestructiveHint: ptrBool(true)`.

Handler shape (mirrors firewall_rule):

```go
func (s *Server) handleIPHostGroupCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPHostGroupCreateInput) (*sdkmcp.CallToolResult, any, error) {
    profile := s.resolveProfile(in.Profile)
    if !in.Confirm {
        return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
    }
    if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
        return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profile)
    }
    in.Body["Name"] = in.Name
    result, err := s.ipHostGroupSvc().Create(ctx, profile, in.Name, in.Body, in.DryRun)
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    body, err := renderObjectMutation(result)
    if err != nil {
        return s.errorEnvelopeResult(err, profile)
    }
    return jsonResult(body)
}
```

Update + delete add the `ExpectedDiffHash` gate before the body-name check.

### 3.6 Generic `object_get` `_diffHash` injection

Today, `firewall_rule_show` and `nat_rule_show` inject `_diffHash` (Phase 10 T3). For Phase 12, **the generic `object_get` does the same when the catalog entry is `Mutable: true`**. CLI's `object get -o json` and MCP's `object_get` both benefit.

Implementation: in `internal/svc/object.go::Get` (or wherever the single-record fetch lives), after parsing the response, look up the catalog entry; if mutable, compute `DiffHash(record)` and inject as `_diffHash`. Unit-tested with one mutable type and one immutable type.

CLI behavior unchanged for users — `_diffHash` is just an extra key in the JSON output. YAML output also includes it. Table output (default for `object get`) does not surface it (table column whitelist excludes `_diffHash`).

### 3.7 Body file loader

`internal/cli/bodyflag.go::LoadBody`:

```go
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
        raw = []byte(source)  // inline string — rare but supported
    }
    if err != nil {
        return nil, err
    }
    if len(bytes.TrimSpace(raw)) == 0 {
        return nil, fmt.Errorf("%w: body is empty", sophos.ErrInvalidRequest)
    }
    var body map[string]any
    // Try JSON first (cheaper to fail).
    if jerr := json.Unmarshal(raw, &body); jerr == nil {
        return body, nil
    }
    // Then YAML.
    if yerr := yaml.Unmarshal(raw, &body); yerr == nil {
        return body, nil
    }
    return nil, fmt.Errorf("%w: body is neither valid JSON nor YAML", sophos.ErrInvalidRequest)
}
```

Tests: empty input, JSON path, YAML path, file path, stdin path, garbage.

## 4. Data flow

Identical to firewall_rule (Phase 9-10), per type:

```
CLI: sophosfw host group create my-group --body @body.yaml --dry-run
       ↓
     LoadBody → body map
       ↓
     IPHostGroupSvc.Create(...,  body, dryRun=true)
       ↓
     required-field check → marshal → BuildSetEnvelope("add")
       ↓
     dryRun: emit Preview envelope
     apply: client.DoRaw → re-fetch → compute new hash → return result
       ↓
     CLI render or MCP renderObjectMutation → JSON envelope
```

## 5. Errors

No new sentinels. Reuses:
- `sophos.ErrNotFound` — update/delete on a non-existent name
- `sophos.ErrInvalidRequest` — missing required fields, body name mismatch, expected-diff-hash mismatch, body parse failure
- `sophos.ErrReadOnlyViolation` — profile is read-only
- `sophos.ErrConcurrentModification` — diff hash mismatch (already used by firewall_rule)

## 6. Testing strategy

### Unit tests

Per type (×6), in `internal/svc/<type>_test.go`:

- `TestCreate_RejectsMissingRequiredField`
- `TestCreate_RejectsReadOnlyProfile`
- `TestCreate_RejectsImmutableCatalogEntry` (run once, on a non-mutable type — sanity check the gate)
- `TestCreate_DryRun_EmitsPreview`
- `TestCreate_Apply_SendsAddEnvelope`
- `TestUpdate_RejectsMissingExpectedDiffHash` (when ignoreHash=false)
- `TestUpdate_RejectsHashMismatch`
- `TestUpdate_DryRun_EmitsPreview`
- `TestUpdate_Apply_SendsUpdateEnvelope`
- `TestDelete_RejectsHashMismatch`
- `TestDelete_Apply_SendsRemoveEnvelope`
- `TestDelete_OnMissing_ReturnsNotFound`

That's ~12 tests × 6 types = ~72 svc tests. Many reuse fixtures via table-driven helpers.

Per type (×6), in `internal/mcp/<type>_mutation_test.go`: 8 handler tests mirroring firewall_rule_mutation_test.go (Confirm gate, ExpectedDiffHash gate, DryRun, Apply for each of create/update/delete).

Catalog: `TestCatalog_Phase12MutableTags` — the 6 types are Mutable.

Object-get: `TestObjectGet_InjectsDiffHashForMutableTypes` and `TestObjectGet_DoesNotInjectForImmutableTypes`.

CLI: `TestCmd_HostGroupCreate_DryRun_BodyFromFile` etc. — table-driven across types where possible.

Body loader: 6 tests in `internal/cli/bodyflag_test.go`.

### Integration tests (build-tagged, against testvm)

Add to `internal/testutil/integration_test.go` — one apply-path test per type for dry-run create and one for delete-of-test-fixture. Total: ~12 integration tests, all gated by `SOPHOSFW_TEST_<TYPE>_NAME` env vars so CI never runs them.

### Manual smoke

Once unit + integration green, manually exercise end-to-end:

```bash
sophosfw host group create test-grp --body @testdata/iphostgroup.yaml --dry-run
sophosfw host group create test-grp --body @testdata/iphostgroup.yaml --yes
sophosfw object get IPHostGroup --filter Name:eq:test-grp -o json | jq ._diffHash
HASH=$(sophosfw object get IPHostGroup --filter Name:eq:test-grp -o json | jq -r ._diffHash)
sophosfw host group delete test-grp --expected-diff-hash $HASH --yes
```

## 7. Acceptance

- [ ] `objects.yaml` has 6 new mutable: true entries.
- [ ] Catalog test updated; passes.
- [ ] Generic `object_get` injects `_diffHash` for mutable types only.
- [ ] 6 new svc files; ~72 unit tests passing.
- [ ] 6 new MCP files; ~48 handler tests passing.
- [ ] CLI commands wired into `host` and `service` parents.
- [ ] Tool count assertion in `internal/mcp/server_test.go` updated 30 → 48.
- [ ] Body-file loader works for YAML, JSON, file path, stdin.
- [ ] Integration smoke green for at least 2 types against testvm.
- [ ] `docs/api-coverage.md` updated: 6 partial cells become complete.
- [ ] `docs/roadmap.md` updated: Phase 12 marked complete.
- [ ] `v0.10.0` tagged + pushed; release workflow green; tap formula updates; `brew upgrade sophosfw` reports 0.10.0.

## 8. Out of scope

- **Draft cycle for these types** (`<type> new/pull/diff/push`). Their bodies are simple enough that body-as-map suffices. If users hit friction, add later.
- **Per-type `<type> show` commands.** Generic `object get` + `_diffHash` injection covers it.
- **Group-membership convenience commands** (`host group add-member`, `host group remove-member`). Use `update` with the modified `HostList`. If users want them, add as a Phase 12.x patch.
- **Network types** (Zone, Interface, GatewayConfiguration). Mutating these requires deeper validation (link-aware) and is a separate phase. Roadmap captures them for a future Phase 13+.
- **Marshal helper unification across firewall/nat/host_ip.** Phase 12 introduces the generic `marshalObjectBody`; refactoring existing firewall_rule/nat_rule to use it is in scope. Refactoring host_ip is OUT — host_ip uses a typed input (no map walk needed) and the existing code path is fine.
- **Rename of `FirewallRulePushResult` to `ObjectMutationResult`.** Tempting but introduces churn across the codebase. Phase 12 introduces a NEW `ObjectMutationResult` for the new types; firewall_rule + nat_rule keep their existing result types unchanged.
- **Service-Type-aware help text.** `Services` has polymorphic `ServiceDetails`; the MCP description points to `object get Services <name> -o json` for examples.

## 9. Risks

- **Each type's required fields must match Sophos.** Bad client-side validation produces frustrating "rejected by client" errors. Mitigation: keep required-field check minimal (Name + handful of obviously-required keys); let Sophos surface schema errors for the rest.
- **`_diffHash` injection in `object_get` may surprise existing tests.** Several `internal/svc/object_test.go` and `internal/mcp/object_test.go` tests assert exact returned-body shape. Plan: pre-flight by running the test suite against the new injection logic; update assertions as needed in the same commit. Estimate: 5-10 test updates.
- **`MACHost` MAC vs MACList is a XOR-style required field.** Validate XOR client-side because Sophos error messages here are unhelpful (returns `Operation could not be performed on Entity` with no detail).
- **Group types validate member references against live state.** Sophos rejects `IPHostGroup` create if `HostList` references missing IPHosts. Don't pre-validate client-side — too much state to track. Document in the MCP tool description so agents know to check references first.
- **Marshal helper unification** could regress firewall/nat behavior if the unified helper differs in edge cases (escaping, nil handling, list semantics). Mitigation: introduce the helper in a single commit, verify all firewall_rule/nat_rule tests still pass before extending to new types.

## 10. Decision log

- **Q1 — Scope: All 6 partial types in one phase (option A).** Rationale: pattern is mechanical; finishing in one phase gives a "completeness signal" and avoids salami-slicing.
- **Q2 — Input shape: Body-as-map (option B).** Rationale: consistent with Phases 7-10 firewall/nat pattern; less code; naturally handles polymorphic `Services.ServiceDetails`.
- **Q3 — CLI surface: Minimal create/update/delete + `--body @file` (option A).** No draft cycle. `object get -o yaml` already provides the read-side of an edit-cycle.
- **Q4 — Diff-hash strategy: Generic `object_get` injects `_diffHash` for mutable types (option A).** One change benefits all 6 types; consistent with the firewall/nat show pattern.
- **Release tag: `v0.10.0`** (minor bump — user-visible mutating surface ~doubles).

## 11. References

- Phase 6 design (host_ip mutating, source of svc audit-deferred pattern): `docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md` (Phase 6 section)
- Phase 9 design (firewall_rule create — body-as-map pattern): `docs/superpowers/specs/2026-05-03-sophosfw-phase9-design.md`
- Phase 10 design (MCP firewall/nat mutating, source of `_diffHash` show pattern): `docs/superpowers/specs/2026-05-03-sophosfw-phase10-design.md`
- Sophos 22.0 XML API docs (per-type required fields)
- Existing typed parsers: `internal/catalog/{fqdnhost,machost,iphost,service}.go`
- Existing `marshalFirewallRule` / `marshalNATRule` (template for unified `marshalObjectBody`): `internal/svc/firewallrule_create.go`, `internal/svc/natrule_create.go`
