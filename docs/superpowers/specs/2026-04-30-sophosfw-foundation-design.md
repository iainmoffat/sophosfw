# sophosfw — Foundation Design (Phases 0-2)

**Status:** approved 2026-04-30
**Scope:** Phases 0, 1, and 2 of the broader sophosfw roadmap (research/design, foundation, generic API coverage), plus the agent-skill outline. Phases 3-7 are explicitly deferred and tracked in `docs/roadmap.md`.
**Reference project:** `/Users/ipm/code/tdx` (Cobra + Go MCP SDK, layered `cli`/`svc`/`render`/`mcp`).
**Target API:** Sophos Firewall 22.0 XML API (`/webconsole/APIController`).

## 1. Goals, non-goals, and deliverables

### In scope (foundation phase)

1. Project skeleton: Go module `github.com/iainmoffat/sophosfw`, local-only git (no remote in this phase), `Makefile`, lint/test targets ready for CI.
2. Profile-based configuration; credentials in macOS Keychain on Darwin with a file fallback for other platforms; `auth login/status/test/logout/profile *` commands.
3. Sophos XML API client — generic `Get`, filtered `Get`, raw envelope passthrough, status-code normalization, login injection, credential redaction.
4. Hybrid object catalog — YAML metadata for ~12 known XML tags (`IPHost`, `IPHostGroup`, `Services`, `ServiceGroup`, `FQDNHost`, `FQDNHostGroup`, `MACHost`, `Zone`, `Interface`, `Gateway`, `FirewallRule`, `NATRule`); typed Go structs for `IPHost` and `Services` only.
5. Generic CLI commands: `object list/get/usage/schema`, `raw get`, `raw request --dry-run`.
6. MCP scaffold: `internal/mcp/` package and `sophosfw mcp serve` command that registers zero tools and prints a scaffold message. Confirms the CLI/MCP seam works without committing to a tool surface.
7. Read-only safety: client-layer mutating-XML rejection + per-command profile-readonly check + integration-test allowlist gate (mechanical, not by convention).
8. Stable JSON envelope contract under the `sophosfw.v1.*` schema namespace; structured error envelope; per-error-kind exit codes.
9. Agent skill skeleton at `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/`, symlinked into the repo at `.claude/skills/sophos-firewall/`. README links to it.
10. `docs/roadmap.md` tracking Phases 3-7 with a paragraph each so deferred work isn't forgotten.

### Out of scope (deferred to later specs)

- All mutating CLI commands (`host ip create/update/delete`, `firewall rule create`, etc.) — Phase 6.
- `raw request` apply path — only `--dry-run` ships in foundation; apply path lands with the deliberate Phase 6 design (preview/diff/apply).
- First-class read-only commands beyond the generic `object` ones (`host ip list`, `service list`, `firewall rule list`, `nat rule list`) — Phase 3.
- Full MCP read-only tool suite — Phase 4.
- Mutating MCP tools — Phase 6.
- Draft/snapshot workflows for complex objects — Phase 7.
- TUI; web UI.

### Foundation acceptance bar (consolidated)

A foundation release is "done" when:

1. `make build && make test && make lint` all pass on a clean checkout.
2. `sophosfw version` prints version + commit + Go runtime.
3. `sophosfw auth profile add home --url https://…` followed by `sophosfw auth login` stores credentials in keychain (Darwin) or the file backend (other OS), validated against the firewall.
4. `sophosfw auth status --json` and `sophosfw auth test --json` emit valid envelopes.
5. `sophosfw raw get IPHost --json` returns a parsed Sophos response with credentials redacted in any debug output.
6. `sophosfw raw request mutating.xml --dry-run` detects mutating verbs, prints redacted XML, and exits with `unsupported_in_phase` if `--yes` is passed (no apply path exists).
7. `sophosfw object list IPHost` (table) and `--json` (envelope) work; same for `--filter Name:like:<text>`.
8. `sophosfw object get IPHost --name <known-name> --json` returns typed `IPHost` data.
9. `sophosfw object usage IPHost --name <known-name>` returns the `objectUsage` envelope.
10. `sophosfw object schema IPHost` prints the catalog entry.
11. `sophosfw mcp serve` starts, prints "0 tools registered (foundation phase scaffold; Phase 4 will add tools)", and exits cleanly on `^C`.
12. Read-only profile mode rejects any constructed mutating envelope at the client layer (asserted by test).
13. Integration suite (`SOPHOSFW_INTEGRATION=1`) runs against the prod firewall without making any change — round-trips every catalog tag, exercises filter syntax.
14. `make skill-doctor` passes — agent skill files exist, README links to the skill, examples reference real implemented commands.
15. `docs/roadmap.md` lists Phases 3-7 with one paragraph each.
16. `~/.config/sophosfw/credentials.yaml` (when used) is verified to be `0600` before reading; client warns on every `--insecure-skip-verify` invocation; never logs unredacted credentials in any code path (asserted by test).

## 2. Architecture and package layout

### Layered architecture

```
cmd/sophosfw/main.go        (Cobra root wiring)
        │
        ├──► internal/cli   (Cobra commands; argument parsing only)
        │       │
        │       └──► internal/svc   (application services; the only home for
        │               │            read-only enforcement and dry-run gating)
        │               │
        │               ├──► internal/sophos   (XML client, request, response,
        │               │                       filter, status-code mapping)
        │               ├──► internal/catalog  (YAML loader + typed parsers)
        │               ├──► internal/config   (~/.config/sophosfw/config.yaml)
        │               └──► internal/creds    (keychain on Darwin, file else)
        │
        └──► internal/mcp   (foundation: stub server with zero tools)
                │
                └──► internal/svc  (Phase 4 tools will call the same services)

Sibling helpers:
  internal/render   table (lipgloss) + JSON envelope writers
  internal/safety   mutating-XML detector + redaction helpers
```

The CLI layer is thin: each Cobra command parses flags, calls a `svc.*` method, and hands the result to `render`. The future MCP tool surface does the same. Read-only enforcement and dry-run gating live exclusively in `svc` — there are no safety decisions in `cli` or `mcp`.

### Package tree (foundation phase)

```
/Users/ipm/code/sophosfw/
├── cmd/sophosfw/main.go
├── internal/
│   ├── cli/
│   │   ├── root.go           # cobra root, global flags, error→exit-code mapper
│   │   ├── auth.go           # auth login/status/test/logout/profile *
│   │   ├── config.go         # config show
│   │   ├── object.go         # object list/get/usage/schema
│   │   ├── raw.go            # raw get, raw request --dry-run
│   │   ├── mcp.go            # mcp serve (calls internal/mcp)
│   │   └── version.go        # version
│   ├── svc/
│   │   ├── auth.go           # AuthSvc
│   │   ├── object.go         # ObjectSvc (list/get/usage)
│   │   ├── raw.go            # RawSvc (get + dry-run preview)
│   │   └── profile.go        # ProfileSvc (CRUD over config)
│   ├── sophos/
│   │   ├── client.go         # HTTP, TLS, timeouts, login injection
│   │   ├── request.go        # envelope builders
│   │   ├── response.go       # generic + typed parsers
│   │   ├── filter.go         # field:criteria:value → <Filter>
│   │   ├── status.go         # <Status> code normalization → Go errors
│   │   └── *_test.go
│   ├── catalog/
│   │   ├── catalog.go        # YAML loader, lookup API
│   │   ├── objects.yaml      # metadata for ~12 tags
│   │   ├── iphost.go         # typed IPHost struct + parser
│   │   └── service.go        # typed Services struct + parser
│   ├── config/
│   │   └── config.go         # config.yaml model, atomic write
│   ├── creds/
│   │   ├── store.go          # interface
│   │   ├── keychain_darwin.go  # go-keyring backend (build tag darwin)
│   │   └── file.go           # 0600 yaml fallback (build tag !darwin)
│   ├── mcp/
│   │   └── server.go         # stub server — registers zero tools
│   ├── render/
│   │   ├── table.go          # lipgloss table writer
│   │   ├── json.go           # sophosfw.v1.* envelope writers
│   │   └── color.go          # honors NO_COLOR
│   └── safety/
│       ├── mutating.go       # IsMutating(xml) → (bool, []string)
│       └── redact.go         # RedactXML, RedactString
├── testdata/sophos/
│   ├── responses/            # captured XML response fixtures
│   ├── requests/             # canonical request envelope fixtures
│   └── postman/              # vendored Sophos Postman collection (read-only ref)
├── docs/
│   ├── implementation-plan.md  # produced by writing-plans skill
│   ├── api-coverage.md
│   ├── command-map.md
│   ├── configuration.md
│   ├── safety-model.md
│   ├── agent-skill.md
│   ├── roadmap.md            # Phases 3-7 tracker
│   ├── examples.md
│   └── superpowers/specs/
│       └── 2026-04-30-sophosfw-foundation-design.md   (this file)
├── .claude/skills/sophos-firewall/   # symlink → ai-tooling/skillshare/...
├── Makefile
├── go.mod
├── go.sum
├── README.md
├── CLAUDE.md                 # mirrors AGENTS.md per global guidance
├── AGENTS.md                 # project-local rules
└── .gitignore
```

### Key interfaces

```go
// internal/sophos
type Client interface {
    Do(ctx context.Context, req Envelope) (*Response, error)
    DoRaw(ctx context.Context, rawXML []byte) (*Response, error)
}

// internal/svc — what cli (now) and mcp (Phase 4) both call
type Objects interface {
    List(ctx context.Context, xmlTag string, filter *Filter) (*ObjectList, error)
    Get(ctx context.Context, xmlTag, name string) (*Object, error)
    Usage(ctx context.Context, xmlTag, name string) (*Usage, error)
}

type Raw interface {
    Get(ctx context.Context, xmlTag string) (*RawResponse, error)
    PreviewRequest(ctx context.Context, xml []byte) (*Preview, error)  // dry-run only
}

// internal/creds
type Credentials struct {
    Username string
    Password string
}
type Store interface {
    Load(profile string) (Credentials, error)
    Save(profile string, c Credentials) error
    Delete(profile string) error
    Backend() string  // "keychain" | "file"
}
```

The MCP stub deliberately calls `svc.Objects.List(ctx, "IPHost", nil)` at startup and discards the result — proves the seam works in the foundation phase, even though no MCP tools are registered. (If the call returns an auth or network error, that's fine — the stub only verifies the type-level seam, not that the firewall is reachable.)

### Module path and git

- Module: `github.com/iainmoffat/sophosfw`
- Local-only git in foundation (`git init` in `/Users/ipm/code/sophosfw`); no remote.
- Go version: 1.26.2 (matches tdx so we share the toolchain).

## 3. Sophos client and catalog

### XML client (`internal/sophos`)

**Endpoint and transport.**
```
POST https://<host>:<port>/webconsole/APIController
Content-Type: application/x-www-form-urlencoded
Body:        reqxml=<URL-encoded XML envelope>
```
Form-field `reqxml` (not query string) to avoid request-size limits on long envelopes. TLS verification on by default; `--insecure-skip-verify` is per-invocation only (no profile-level toggle), with a stderr warning printed before *every* call when set. Default request timeout 30s, configurable per profile.

**Envelope construction.** Built with `encoding/xml` + small typed structs — never string concatenation. User-supplied names (`Name=O'Reilly`, etc.) are escaped automatically. The client owns `<Login>` injection: callers pass a credential-free envelope; the client materializes `<Request><Login>…</Login>…</Request>` at send time. Service-layer code never touches passwords; credentials never appear in any logging path.

**Generic envelope shape:**
```go
type Envelope struct {
    Operations []Op   // <Get>, <Set op="add">, <Set op="update">, <Remove>, <*Statistics>
    TxnID      string // optional <transactionid>
}

type GetOp struct {
    XMLTag string       // e.g. "IPHost"
    Name   string       // optional — single-object get
    Filter *FilterClause
}

type FilterClause struct {
    Field    string  // e.g. "Name"
    Criteria string  // "=", "!=", "like" for object queries
                     // also "not like", "startswith", "in", ">", ">=" for *Statistics
    Value    string
}
```
`filter.go` validates `Criteria` against the allowed set per operation type so a typo turns into a Go error before bytes hit the wire.

**Response handling.** Two layers:

1. **Generic** — every response parses into `Response{Status, Login, Body}` where `Body` is `map[string][]json.RawMessage` keyed by XML tag. Unknown tags survive with full fidelity. This powers `object list` for any tag whether or not we have a typed wrapper.
2. **Typed** — `catalog`-registered tags get a typed unmarshaller. `IPHost` (`Name`, `IPFamily`, `HostType`, `IPAddress`, `Subnet`, `StartIPAddress`, `EndIPAddress`, `IPAddressList`) and `Services` (`Name`, `Type`, `ServiceDetails`) ship with full structs. The other 10 tags fall through to generic in this phase.

**Status normalization (`status.go`).** Sophos returns numeric codes inside `<Status code="200">…</Status>`. Mapping:

- `200`-range → success.
- `500`+ → typed errors: `ErrAuthFailed`, `ErrNotFound`, `ErrPermissionDenied`, `ErrInvalidRequest`, `ErrServerError` — each wrapping the original code and message.
- Login-stanza failures (`<Login><status>Authentication Failure</status></Login>`) detected separately and surfaced as `ErrAuthFailed` even when the rest of the envelope returned 200.

### Catalog (`internal/catalog`)

**`objects.yaml` schema** (single file in foundation; split into per-tag files when entries pass ~25 or the file passes ~300 lines):

```yaml
objects:
  - tag: IPHost
    aliases: [host-ip, ip-host]
    description: "IP host objects (single addresses, ranges, networks)"
    columns: [Name, IPFamily, HostType, IPAddress, Subnet]
    filterable: [Name, IPAddress, IPFamily, HostType]
    usageTag: IPHostStatistics
    typedParser: iphost

  - tag: Services
    aliases: [service]
    description: "Service objects (TCP/UDP/IP/ICMP definitions)"
    columns: [Name, Type, ServiceDetails]
    filterable: [Name, Type]
    usageTag: ServicesStatistics
    typedParser: service

  # … 10 more entries: IPHostGroup, ServiceGroup, FQDNHost, FQDNHostGroup,
  #   MACHost, Zone, Interface, Gateway, FirewallRule, NATRule
  #   (all with typedParser: "" — generic fall-through in foundation)
```

**Note on absence:** there is no `mutating:` block in this phase. Phase 6 will introduce a richer mutation-related schema (validators, expected fields, etc.) and adding a partial structure now would prejudge that design.

**Lookup API:**
```go
type Catalog struct{ /* private */ }

func Load(path string) (*Catalog, error)
func (c *Catalog) Resolve(nameOrAlias string) (*Entry, bool)
func (c *Catalog) Tags() []string
func (c *Catalog) Parse(tag string, raw json.RawMessage) (any, error)
   // dispatches to typed parser if registered, else returns map[string]any
```

`object schema <xml-tag>` prints the catalog entry. `object list <xml-tag>` accepts either canonical tag or alias.

**Why this seam matters.** Every higher-layer code path — `cli/object.go`, the future MCP `list_objects` tool, `svc.Objects.List` — funnels through `catalog.Resolve` to validate the tag and pick parsing/columns. If Phase 6 wants to add a mutating operation for `IPHost`, the only catalog file changed is `objects.yaml` (and the new mutation-schema fields it will introduce); the catalog API stays stable.

## 4. Configuration, profiles, credentials, and safety

### Filesystem layout

```
~/.config/sophosfw/
├── config.yaml                 # global settings + profile registry
└── profiles/<name>/
    ├── cache/                  # response cache (Phase 3+; not created in foundation)
    └── snapshots/              # draft snapshots (Phase 7; not created in foundation)
```
Foundation only creates `config.yaml` and the profile directory. Cache/snapshot dirs are created on demand by later phases.

### `config.yaml`

```yaml
version: 1
currentProfile: home
defaults:
  output: table          # "table" | "json"
  timeout: 30s
  insecureSkipVerify: false
profiles:
  home:
    url: https://fw.example.com:4444
    timeout: 30s
    insecureSkipVerify: false   # (reserved; no profile-level toggle in foundation)
    readOnly: false             # read-write default per Q10
    apiVersion: ""              # optional pin; empty = let firewall decide
    notes: ""
    credentialsBackend: keychain  # set by `auth login`; "keychain" | "file"
```
`auth profile use <name>` updates `currentProfile`. `auth profile list` shows all profiles with the active one marked.

### Credential storage

```go
type Credentials struct {
    Username string
    Password string
}
type Store interface {
    Load(profile string) (Credentials, error)
    Save(profile string, c Credentials) error
    Delete(profile string) error
    Backend() string
}
```

**Backends:**
- **`keychain_darwin.go`** — `github.com/zalando/go-keyring`. Service name `sophosfw`, account name = profile name. Single keychain item per profile holding `username\npassword` (newline-delimited). Build tag: `darwin`.
- **`file.go`** — `~/.config/sophosfw/credentials.yaml`, file mode `0600`, parent directory `0700`. Verified on read; refuses to load if perms are looser. Build tag: `!darwin`.

`creds.New()` selects the backend automatically based on platform. `auth login` prompts for username and password (password via `golang.org/x/term` no-echo), validates against the firewall, then persists. `auth logout` calls `Delete`.

### Safety model — three concentric layers

**Layer 1 — Client-layer enforcement (load-bearing).**
`sophos.Client.Do` and `sophos.Client.DoRaw` pass the outbound XML through `safety.IsMutating(xml []byte) (bool, []string)` before dispatching. If the active profile is `readOnly: true` and the XML contains any mutating verb (`<Set …>`, `<Remove …>`), the client returns `ErrReadOnlyViolation` with the list of detected verbs. Catches bugs in higher-level code that forget the gate.

**Layer 2 — Service-layer enforcement.**
`svc.Raw.PreviewRequest` is the only foundation-phase code path that accepts user-supplied XML. It runs `safety.IsMutating` first and returns `Preview{Mutating: true, Verbs: […], Redacted: <xml>}`. The CLI prints a warning and the redacted XML when mutating verbs are detected. **There is no apply path in foundation.** A `--yes` flag exists on `raw request` for forward-compatibility, but it always returns `unsupported_in_phase` (the apply path lands deliberately in Phase 6 alongside diff/preview/apply). `--dry-run` is effectively the only mode foundation supports.

**Layer 3 — Integration-test gate.**
`testutil` provides an `IntegrationClient` wrapper enabled only when `SOPHOSFW_INTEGRATION=1`. It is hardcoded to read-only mode regardless of profile setting. Any test in the integration suite that constructs a mutating envelope panics at construction time, not at send time. The "no mutations against your prod firewall, ever" promise is mechanical, not convention.

### Redaction

`safety.RedactXML(xml []byte) []byte` rewrites `<Username>…</Username>` and `<Password>…</Password>` to `<Username>***</Username><Password>***</Password>` before any debug log, error message, dry-run printout, or test fixture write. The client uses redacted forms in all log/error paths; raw bytes never leave `client.Do`. `safety.RedactString` exists for non-XML log lines that mention credentials.

`--debug` output: at debug level the client logs the redacted request envelope, the HTTP status, and the response body (capped at 64 KB). Everything passes through `RedactXML` first.

### TLS

Default verification on. Per-invocation `--insecure-skip-verify` only — no profile-level "always insecure" in foundation. When set, client logs to stderr before each call:
```
warning: TLS verification disabled for this request (--insecure-skip-verify)
```

## 5. Output, errors, and testing

### JSON envelope contract (`internal/render`)

Every command that prints structured output emits one envelope. The shape is stable across versions; the `schema` field is the version key.

**Success envelope schemas (foundation phase):**
- `sophosfw.v1.authStatus`
- `sophosfw.v1.connectionTest`
- `sophosfw.v1.profileList`
- `sophosfw.v1.objectList`
- `sophosfw.v1.object`
- `sophosfw.v1.objectUsage`
- `sophosfw.v1.objectSchema`
- `sophosfw.v1.rawResponse`
- `sophosfw.v1.preview`

Example shapes are documented in `docs/configuration.md`. Notable fields:

```json
{
  "schema": "sophosfw.v1.objectList",
  "profile": "home",
  "xmlTag": "IPHost",
  "filter": { "field": "Name", "criteria": "like", "value": "LAN" },
  "count": 7,
  "items": [ /* typed if catalog has parser, else raw map */ ]
}
```

```json
{
  "schema": "sophosfw.v1.preview",
  "profile": "home",
  "mutating": true,
  "verbs": ["Set:add"],
  "redactedXml": "<Request><Login><Username>***</Username>...</Request>",
  "wouldSendBytes": 412,
  "warning": "Mutating XML detected. Apply path is not implemented in this phase."
}
```

**Error envelope** — every error path prints (when `--json`):
```json
{
  "schema": "sophosfw.v1.error",
  "kind": "auth_failed | not_found | permission_denied | invalid_request |
           server_error | read_only_violation | tls_error | network_error |
           config_error | catalog_unknown_tag | unsupported_in_phase",
  "message": "human-readable",
  "profile": "home",
  "details": { /* kind-specific structured data */ }
}
```

**Exit codes** mirror `kind`: `1` = generic, `2` = config_error, `3` = auth_failed, `4` = read_only_violation, `5` = network/tls error, `6` = unsupported_in_phase. Other kinds map to `1` for now; we tighten in later phases.

### Table output (`render.Table`)

`lipgloss` table:
- Boxed border, single-line.
- Header row bold; no alternating row tints (some terminals render unreadably).
- Long values truncated to terminal width with `…`; full value shown on `--no-truncate` or `--json`.
- `NO_COLOR=1` honored; falls back to plain ASCII.
- Columns come from the catalog entry; user can override per call with `--columns Name,IPAddress`.

### Errors

Sentinels in `sophos`:
```go
var (
    ErrAuthFailed         = errors.New("sophos: authentication failed")
    ErrNotFound           = errors.New("sophos: object not found")
    ErrPermissionDenied   = errors.New("sophos: permission denied")
    ErrInvalidRequest     = errors.New("sophos: invalid request")
    ErrServerError        = errors.New("sophos: server error")
    ErrReadOnlyViolation  = errors.New("sophos: read-only profile rejected mutating XML")
)
```

Wrapping pattern: `fmt.Errorf("list IPHost in profile %q: %w", profile, ErrAuthFailed)` — the kind survives `errors.Is`, so the CLI's top-level error handler maps to JSON `kind` and exit code in one place (`internal/cli/root.go` `cobra.OnFinalize`).

### Testing strategy

**Unit tests (no firewall required):**
- `sophos`: envelope build → byte-for-byte against fixtures in `testdata/sophos/requests/`; response parse from `testdata/sophos/responses/` covering success, auth fail, permission denied, server error, single-result, multi-result, empty-result, malformed XML.
- `safety`: `IsMutating` table-driven with a fixture per verb; `RedactXML` round-trip tests (idempotent, structure-preserving).
- `catalog`: load valid/invalid YAML; `Resolve` by tag and alias; `Parse` dispatches to typed parser and falls through.
- `creds`: file backend perm-check tests in a temp dir; keychain backend behind a Darwin build tag and `KEYCHAIN_TEST=1` env gate (developer opt-in).
- `render`: golden-file tests for each `sophosfw.v1.*` envelope; table golden files with `NO_COLOR=1` fixed.

**CLI command tests (`internal/cli/*_test.go`):**
Use a fake `sophos.Client` that returns canned responses. Covers flag wiring, error→exit-code mapping, JSON vs table output, `--profile` selection, read-only enforcement.

**MCP stub test:**
Exercises `mcp serve` startup and the "0 tools registered" message — small, but proves the seam before Phase 4.

**Integration tests (gated):**
```bash
SOPHOSFW_INTEGRATION=1 SOPHOSFW_PROFILE=home go test ./... -run Integration -tags integration
```
Build tag `integration` keeps them out of normal builds. Suite uses the `IntegrationClient` wrapper (read-only enforcement is mechanical, not convention). Coverage:
- `auth test` against the real firewall.
- `raw get IPHost` returns ≥0 results without error.
- `object list IPHost` round-trips and parses.
- `object usage IPHost --name <name>` for a name we discover from the list step.
- Catalog tag-by-tag smoke test: every tag in `objects.yaml` survives a `Get` (envelope built, response parsed, status 200).

**Fixture capture helper:**
`testdata/sophos/responses/` is hand-curated to start (the Postman collection seeds request shapes; responses come from the integration suite via a `-capture` flag that writes responses to `testdata/sophos/responses/<name>.xml` after redacting any IPs/names marked sensitive in a `.captureignore` file). Opt-in; never runs in CI.

### Make targets

```
make fmt          # gofmt -s -w
make vet          # go vet ./...
make lint         # golangci-lint run
make test         # go test -race ./...
make test-int     # SOPHOSFW_INTEGRATION=1 go test -tags integration ./...
make build        # go build -o bin/sophosfw ./cmd/sophosfw
make install      # cp bin/sophosfw to GOBIN
make skill-doctor # bin/sophosfw skill doctor
```

## 6. Agent skill, roadmap doc, and acceptance criteria

### Agent skill — source of truth + sync

**Canonical location:** `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/`
**Project-local symlink:** `/Users/ipm/code/sophosfw/.claude/skills/sophos-firewall` → canonical path. Symlink is committed.

**Files:**
```
sophos-firewall/
├── SKILL.md               # main skill file with frontmatter
├── examples.md            # concrete CLI + (Phase-4-aware) MCP examples
├── safety-checklist.md    # dangerous-operations checklist
├── api-patterns.md        # XML envelope shapes, status codes, filter criteria
└── audit-template.md      # post-operation audit summary format
```

**`SKILL.md` frontmatter:**
```yaml
---
name: sophos-firewall
description: |
  Use when the user wants to inspect, search, or (later) modify Sophos Firewall
  configuration. Covers the sophosfw CLI and its MCP server. Read-only by default;
  any mutating operation requires explicit human confirmation. Production firewall
  is treated as live infrastructure.
---
```

**`SKILL.md` section structure** (matches the spec the user supplied; foundation-aware annotations marked):
1. Purpose
2. When to use this skill / when not to
3. Safety model — read-only first, three-layer enforcement, prod assumptions
4. CLI usage pattern — profile selection, `--json` for parsing, exit codes
5. MCP usage pattern — *foundation phase ships only the stub; full tools come in Phase 4*
6. Profile and credential handling — keychain-first, never log creds
7. Common read-only workflows — `auth status`, `object list IPHost`, `object get IPHost --filter Name:like:LAN`, `object usage IPHost --name <name>`, `raw get <tag>`
8. Common change workflows — *not implemented in foundation; describes the dry-run/preview/apply pattern Phase 6 will land on*
9. Raw API escape hatch — `raw get` for unknown read paths; `raw request --dry-run` to preview a hand-authored envelope; **must not** be used to mutate in this phase (apply path doesn't exist)
10. XML API basics — `<Request>/<Login>/<Get>/<Filter>/<Status>` shapes, status code semantics
11. Output and JSON parsing — schema envelope contract, error envelope, exit codes
12. Error handling — `auth_failed` → re-login; `read_only_violation` → check profile mode, do not retry around the gate; `unsupported_in_phase` → tell the user and stop
13. Audit summary pattern — every operation that touches the firewall ends with a compact summary
14. Dangerous operations checklist — pulled from `safety-checklist.md`
15. Examples — pointer to `examples.md`
16. Things agents must never do — full list from the source spec
17. Current limitations — honest list of what's not in foundation

**`audit-template.md` content:**
```
Operation: <CLI command or MCP tool name>
Profile: <name>  Mode: <read-only | read-write>  Mutating: <yes|no>
Result: <ok | error:<kind>>
Affected: <count> <tag> object(s)  Names: <name1, name2, ...>
Notes: <anything the user should know — slow response, partial data, etc.>
```

**Skill ↔ implementation sync mechanism:** `make skill-doctor` runs `cmd/sophosfw skill doctor` (small subcommand) which walks the skill files and verifies:
- Every CLI command mentioned in `examples.md` exists in the binary's `--help` output.
- Every MCP tool mentioned exists in the registered tool set (zero in foundation, so this just verifies the section is correctly marked "stub only").
- The skill doesn't reference any deferred-phase command without the deferral marker.

Failure exits non-zero so CI can pick it up later. Lightweight version of "keep the skill in sync with implemented commands."

### Roadmap doc — `docs/roadmap.md`

Tracks deferred phases per the user's explicit ask. Outline:

```markdown
# sophosfw roadmap

## Status
- Phase 0 — Research and design (this spec)
- Phase 1 — Foundation (covered by this spec; implementation plan to follow)
- Phase 2 — Generic API coverage (covered by this spec; implementation plan to follow)
- Phase 3 — First-class read-only commands (host ip, service, firewall rule, nat rule)
- Phase 4 — MCP read-only server (full tool suite)
- Phase 5 — Agent skill completion (mutating workflows, finalized examples)
- Phase 6 — Safe mutations (host ip create/update/delete + MCP equivalents)
- Phase 7 — Complex draft workflows (firewall rule pull/edit/diff/preview/push)

## Phase 3 — First-class read-only commands
**Goal:** ergonomic wrappers over the catalog for high-traffic objects.
**New commands:** host ip list/show/search/usage, service list/show/usage, firewall rule list/show, nat rule list/show.
**New typed structs:** FQDNHost, MACHost, FirewallRule, NATRule, Zone.
**Pre-reqs:** none beyond foundation.

## Phase 4 — MCP read-only server
**Goal:** expose foundation read-only capabilities as MCP tools.
**New tools:** get_auth_status, test_firewall_connection, list_profiles, get_current_profile,
              raw_get, list_objects, get_object, search_objects, get_object_usage,
              list_ip_hosts, get_ip_host, list_services, get_service,
              list_firewall_rules, get_firewall_rule, list_nat_rules, get_nat_rule
**Pre-reqs:** Phase 3 first-class commands so the typed surface is rich enough.

## Phase 5 — Agent skill completion
**Goal:** finalize the agent skill against actually-implemented surface.
**Scope:** real MCP tool examples, mutating workflow descriptions ahead of Phase 6,
          updated dangerous-operations checklist, refreshed audit template.

## Phase 6 — Safe mutations
**Goal:** ship the apply path with full safety gates.
**Scope:** host ip create/update/delete with --dry-run/--yes, raw request apply path,
          mutating MCP tools requiring confirm:true and expectedDiffHash where
          practical, mutation-related fields in catalog YAML.
**Pre-reqs:** Phase 4 (so MCP equivalents land together).

## Phase 7 — Complex draft workflows
**Goal:** YAML draft/edit/diff/preview/push for firewall rules, NAT rules, VPN, etc.
**Scope:** firewall rule pull <name> --draft → edit → diff → preview → push --expected-diff-hash --yes;
          snapshots under ~/.config/sophosfw/profiles/<name>/snapshots/.
```

The README links to this. Each future phase gets its own brainstorm → spec → plan → implementation when its turn comes.

### Foundation acceptance criteria

(Repeated here for completeness — same list as section 1.)

1. `make build && make test && make lint` all pass on a clean checkout.
2. `sophosfw version` prints version + commit + Go runtime.
3. `sophosfw auth profile add home --url https://…` → `sophosfw auth login` stores creds in keychain (Darwin) / file backend (other), validated against the firewall.
4. `sophosfw auth status --json` and `sophosfw auth test --json` emit valid envelopes.
5. `sophosfw raw get IPHost --json` returns parsed Sophos response with credentials redacted from any debug output.
6. `sophosfw raw request mutating.xml --dry-run` detects mutating verbs, prints redacted XML, exits with `unsupported_in_phase` if `--yes` is passed.
7. `sophosfw object list IPHost` (table) and `--json` (envelope) work; same for `--filter Name:like:<text>`.
8. `sophosfw object get IPHost --name <known-name> --json` returns typed `IPHost` data.
9. `sophosfw object usage IPHost --name <known-name>` returns the `objectUsage` envelope.
10. `sophosfw object schema IPHost` prints the catalog entry.
11. `sophosfw mcp serve` starts, prints "0 tools registered (foundation phase scaffold; Phase 4 will add tools)", exits cleanly on `^C`.
12. Read-only profile mode rejects any constructed mutating envelope at the client layer (asserted by test).
13. Integration suite (`SOPHOSFW_INTEGRATION=1`) runs against the prod firewall without making any change — round-trips every catalog tag, exercises filter syntax.
14. `make skill-doctor` passes — agent skill files exist, README links to the skill, examples reference real implemented commands.
15. `docs/roadmap.md` lists Phases 3-7 with one paragraph each.
16. `~/.config/sophosfw/credentials.yaml` (when used) is verified to be `0600` before reading; client warns on every `--insecure-skip-verify` invocation; never logs unredacted credentials in any code path (asserted by test).

## Appendix A — Decisions log (clarifying questions)

| # | Decision | Choice |
|---|---|---|
| 1 | Scope | Phases 0-2 + agent-skill outline; Phases 3-7 tracked in `docs/roadmap.md` |
| 2 | Test access | Real prod firewall; integration tests gated on `SOPHOSFW_INTEGRATION=1`; mechanically read-only |
| 3 | Credential storage | macOS Keychain on Darwin (`go-keyring`), file fallback (`0600`) elsewhere |
| 4 | Module path | `github.com/iainmoffat/sophosfw`; local-only git, no remote |
| 5 | Agent skill location | Canonical in `ai-tooling/skillshare/skills/sophos-firewall/`; project-local symlink |
| 6 | UI surface | CLI + MCP only; `lipgloss` for table styling; no TUI |
| 7 | Read-only enforcement | Belt-and-braces: client layer + per-command + integration-test gate |
| 8 | Raw API in foundation | `raw get` + `raw request --dry-run` only; no apply path |
| 9 | Object catalog | Hybrid: YAML metadata + typed Go structs for `IPHost` and `Services` |
| 10 | Profile default | Read-write default with `--read-only` opt-in; warnings on future mutating commands |
| 11 | MCP scaffold | Stub package + zero-tool `mcp serve` to prove the seam |

## Appendix B — Out-of-scope, captured for posterity

These are tempting things I considered and explicitly defer:
- Per-tag YAML files in `catalog/objects/*.yaml` — defer until `objects.yaml` >25 entries or >300 lines.
- Profile-level `insecureSkipVerify` (always-on for a profile) — never; per-invocation only.
- Auto-typed structs for all 12 catalog tags — defer until first-class commands need them.
- `mutating:` block in `objects.yaml` — defer to Phase 6 with the rest of the mutation schema.
- A `safety` package that grows beyond `IsMutating` and `RedactXML` — defer; foundation needs only those.
