# sophosfw — Phase 4 Design (MCP read-only server)

**Status:** approved 2026-05-01. Implementation plan to follow.

**Predecessor:** Phase 3, tagged `v0.2.0-phase3` on `main` (commit `92bfc63`). Earlier spec: `docs/superpowers/specs/2026-05-01-sophosfw-phase3-design.md`.

## 1. Goal and scope

### 1.1 Goal

Phase 4 turns the foundation's `sophosfw mcp serve` zero-tool stub into a real stdio MCP server that exposes the read-only sophosfw surface as 21 tools. Agents using a Claude Desktop, Continue, or any MCP-capable client can call into the sophosfw command surface without shelling out to the cli. The MCP tool outputs reuse the existing `sophosfw.v1.*` JSON envelopes verbatim, giving agents a single response contract whether they read cli `--json` output or invoke an MCP tool.

### 1.2 In scope

- Replace the foundation stub `internal/mcp/server.go` `Serve` with a real stdio JSON-RPC implementation using `github.com/modelcontextprotocol/go-sdk` v1.5.0 (matches the user's `tdx` project).
- 21 tools, one per cli verb-noun pair, in snake_case:
  - **Auth/profile (4):** `auth_status`, `auth_test`, `auth_profile_list`, `auth_profile_current`
  - **Generic catalog (4):** `object_list`, `object_get`, `object_search`, `object_usage`
  - **Raw (1):** `raw_get`
  - **Typed host (4):** `host_ip_list`, `host_ip_show`, `host_ip_search`, `host_ip_usage`
  - **Typed service (4):** `service_list`, `service_show`, `service_search`, `service_usage`
  - **Firewall rule (2):** `firewall_rule_list`, `firewall_rule_show`
  - **NAT rule (2):** `nat_rule_list`, `nat_rule_show`
- Per-group package layout: one Go file per concept (`auth.go`, `object.go`, `raw.go`, `hostip.go`, `service.go`, `firewallrule.go`, `natrule.go`), each owning its input structs, handlers, and `register*` glue.
- One `--profile` flag on `mcp serve` to set the server's default profile. Per-tool calls can override via the `profile` input field.
- Every tool input struct uses Go-native types translated from cli flags. `Filter` is a string `Field:Criteria:Value`. `WithReferences` is a bool. Strings are required where marked; the SDK enforces this.
- Output bodies are `sophosfw.v1.*` JSON envelopes returned as MCP text content.
- Errors are returned as success bodies with `sophosfw.v1.error` envelopes (NOT as MCP tool errors). Schema-validation failures still come back through the SDK's tool-error channel.
- One refactor before the MCP work: extract envelope construction into shared `internal/render` helpers so cli and MCP use the same source for what each `sophosfw.v1.*` envelope looks like.
- One refactor: extract `cli.ErrorKind` into a shared error→kind mapping so cli and MCP map the same way.
- ~49 new tests total: 21 per-tool happy-path + 4 error-path + 2 wire-format smokes + 21 render-envelope round-trip + 1 integration smoke (build-tagged). Existing cli/svc tests stay green after the refactor.
- Phase 4 ships as `v0.3.0-phase4`.

### 1.3 Out of scope (deferred)

- MCP **resources** and **prompts**. Phase 4 is tools-only.
- MCP **tool annotations** beyond `readOnlyHint: true` and per-tool `title`. `destructiveHint`, `idempotentHint`, etc. land with mutation tools in Phase 6.
- **Mutating tools entirely.** Every Phase 4 tool maps to an existing read-only svc method. `raw_request` (which can be mutating) is NOT exposed.
- **`confirm: true` / `expectedDiffHash` parameters.** Phase 6 / Phase 7.
- **Streaming responses.** Each tool returns a single JSON body.
- **Tool autocompletion.**
- **Updates to the agent skill.** Phase 5.
- **New typed parsers in the catalog.** Phase 4 uses existing parsers from foundation + Phase 3.
- **`--columns` flag exposure on MCP tools.** It's a presentation flag for table mode; MCP always returns JSON. Re-evaluate if a real use case shows up.

### 1.4 Deliverable

Phase 4 ships as `v0.3.0-phase4` on `main`. Acceptance: `go fmt ./... && go vet ./... && go test -race ./...` clean, `make build` produces a binary that registers all 21 tools when invoked as `sophosfw mcp serve`, manual smoke (`mcp serve` connected to a local mcp-inspector or Claude Desktop) returns well-formed envelopes for at least `host_ip_list`, `service_list`, `firewall_rule_list`, `nat_rule_list`, `auth_status`. `make skill-doctor` still passes (the agent skill update for MCP tools lands in Phase 5; doctor's required-commands list is unchanged).

## 2. Architecture

### 2.1 Dependency direction

```
github.com/modelcontextprotocol/go-sdk v1.5.0
       │
       ▼
internal/mcp/server.go      (Deps, NewServer, Serve, registerAll dispatcher)
internal/mcp/server_helpers.go  (resolveProfile, jsonResult, errorEnvelopeResult)
       │
       ├── auth.go         (auth_status, auth_test, auth_profile_list, auth_profile_current)
       ├── object.go       (object_list, object_get, object_search, object_usage)
       ├── raw.go          (raw_get)
       ├── hostip.go       (host_ip_*)
       ├── service.go      (service_*)
       ├── firewallrule.go (firewall_rule_*)
       └── natrule.go      (nat_rule_*)
       │
       ▼  (re-uses, never reimplements)
svc package (HostIPSvc, ServiceSvc, FirewallRuleSvc, NATRuleSvc, ObjectSvc, AuthSvc, ProfileSvc, RawSvc)
       │
       ▼
sophos client + catalog
```

Each per-group file owns:
1. Input struct types (one per tool).
2. Handler functions (one per tool).
3. One `registerXxx(s *Server) error` method that the central `registerAll` calls.

The svc layer does the I/O. The render layer (after T1's refactor) does the envelope construction.

### 2.2 Package layout (new + modified files)

**New files:**
```
internal/mcp/
├── server_helpers.go         # resolveProfile, jsonResult, errorEnvelopeResult, ptrBool
├── auth.go                   # 4 auth tools
├── auth_test.go
├── object.go                 # 4 generic catalog tools
├── object_test.go
├── raw.go                    # 1 raw_get tool
├── raw_test.go
├── hostip.go                 # 4 typed host tools
├── hostip_test.go
├── service.go                # 4 typed service tools
├── service_test.go
├── firewallrule.go           # 2 firewall rule tools
├── firewallrule_test.go
├── natrule.go                # 2 nat rule tools
├── natrule_test.go
└── server_test.go            # 2 wire-format smokes
internal/render/
├── envelope.go               # ~22 envelope-construction helpers (one per `sophosfw.v1.*` schema, including error)
└── envelope_test.go          # one test per envelope helper, asserts byte-identical to existing cli output
internal/svc/
└── errors.go                 # ErrorKind(err) → string mapping shared between cli and mcp (per Section 5.2)
```

**Modified files:**
```
internal/mcp/server.go        # rewrites Serve to wire SDK; registerAll dispatcher
internal/cli/mcp.go           # new --profile flag; passes DefaultProfile into Deps
internal/cli/auth.go          # use new render helpers (small refactor)
internal/cli/object.go        # use new render helpers
internal/cli/raw.go           # use new render helpers
internal/cli/hostip.go        # use new render helpers
internal/cli/service.go       # use new render helpers
internal/cli/firewallrule.go  # use new render helpers
internal/cli/natrule.go       # use new render helpers
internal/cli/errors.go        # if extracting ErrorKind to shared package; otherwise unchanged
cmd/sophosfw/main.go          # pass DefaultProfile from --profile flag through to mcp.Deps
go.mod                        # +github.com/modelcontextprotocol/go-sdk v1.5.0
go.sum                        # corresponding hash entries
```

Approximate net new code: 600-800 LOC across the mcp package + ~150 LOC moved into `render/envelope.go` (refactor, not new) + ~30 LOC new on the cli side (--profile flag).

### 2.3 Data flow: a representative call

Agent invokes `host_ip_list` with `{"profile": "home"}` over stdio.

1. SDK reads the JSON-RPC `tools/call` request, validates input against the registered JSON Schema (auto-generated from `HostIpListInput`), deserializes into a typed `HostIpListInput` value.
2. SDK dispatches to `s.handleHostIpList(ctx, req, in)`.
3. Handler calls `profile := s.resolveProfile(in.Profile)`. With `in.Profile = "home"`, result is `"home"`. (Without it, would fall through to `s.deps.DefaultProfile`, which is set by `mcp serve --profile <name>`. If that's also empty, the eventual `s.Inner.List` call hands the empty profile name to `s.Config.ActiveProfile("")`, which falls back to the config's `currentProfile`.)
4. Handler parses any `Filter` input (none here).
5. Handler calls `s.hostIPSvc().List(ctx, "home", nil)`. Returns `*svc.HostIPList`.
6. Handler calls `render.HostIPListEnvelope(out)`. Returns the JSON bytes for the `sophosfw.v1.hostIpList` envelope.
7. Handler returns `jsonResult(body)` — a `*mcp.CallToolResult` with one text content piece holding the envelope bytes.
8. SDK serializes the JSON-RPC response and writes to stdout.

Total handler code: ~10 lines. Most are error-handling boilerplate identical across tools.

## 3. Tool inventory

### 3.1 Auth and profile tools (4)

| Tool | Inputs | Output schema | svc method |
|---|---|---|---|
| `auth_status` | `Profile string` (optional) | `sophosfw.v1.authStatus` | `AuthSvc.Status` |
| `auth_test` | `Profile string` (optional) | `sophosfw.v1.connectionTest` | `AuthSvc.Test` |
| `auth_profile_list` | (none) | `sophosfw.v1.profileList` (all profiles) | `ProfileSvc.List` |
| `auth_profile_current` | (none) | `sophosfw.v1.profileList` (single-entry) | filter `ProfileSvc.List` to current |

`auth_test` does perform a network round-trip (calls Sophos to verify credentials), but it's strictly read-only — no envelope is constructed that could mutate.

### 3.2 Generic catalog tools (4)

| Tool | Inputs | Output schema | svc method |
|---|---|---|---|
| `object_list` | `Profile`, `Tag` (required), `Filter` | `sophosfw.v1.objectList` | `ObjectSvc.List` |
| `object_get` | `Profile`, `Tag` (required), `Name` (required) | `sophosfw.v1.object` | `ObjectSvc.Get` |
| `object_search` | `Profile`, `Tag` (required), `Query` (required) | `sophosfw.v1.objectList` | `ObjectSvc.List` then client-side Name substring filter |
| `object_usage` | `Profile`, `Tag` (required), `Name` (required) | `sophosfw.v1.objectUsage` | `ObjectSvc.Usage` |

`object_search` is new in Phase 4 (the cli doesn't expose it on the generic surface — typed search is on `host_ip_search`/`service_search`). Implementation: the handler calls `ObjectSvc.List(ctx, profile, tag, nil)` with no filter, then locally filters the items by `strings.Contains(strings.ToLower(item.Name), strings.ToLower(query))`. Matches the typed-search pattern from Phase 3.

### 3.3 Raw tool (1)

| Tool | Inputs | Output schema | svc method |
|---|---|---|---|
| `raw_get` | `Profile`, `XmlTag` (required) | `sophosfw.v1.rawResponse` | `RawSvc.Get` |

`raw_request` is NOT exposed (can be mutating). Phase 6.

### 3.4 Typed host tools (4)

| Tool | Inputs | Output schema | svc method |
|---|---|---|---|
| `host_ip_list` | `Profile`, `Filter` | `sophosfw.v1.hostIpList` | `HostIPSvc.List` |
| `host_ip_show` | `Profile`, `Name` (required) | `sophosfw.v1.hostIp` | `HostIPSvc.Get` |
| `host_ip_search` | `Profile`, `Query` (required) | `sophosfw.v1.hostIpSearch` | `HostIPSvc.Search` |
| `host_ip_usage` | `Profile`, `Name` (required), `WithReferences bool` | `sophosfw.v1.hostIpUsage` | `HostIPSvc.Usage` |

### 3.5 Typed service tools (4)

| Tool | Inputs | Output schema | svc method |
|---|---|---|---|
| `service_list` | `Profile`, `Filter` | `sophosfw.v1.serviceList` | `ServiceSvc.List` |
| `service_show` | `Profile`, `Name` (required) | `sophosfw.v1.service` | `ServiceSvc.Get` |
| `service_search` | `Profile`, `Query` (required) | `sophosfw.v1.serviceSearch` | `ServiceSvc.Search` |
| `service_usage` | `Profile`, `Name` (required), `WithReferences bool` | `sophosfw.v1.serviceUsage` | `ServiceSvc.Usage` |

### 3.6 Firewall rule tools (2)

| Tool | Inputs | Output schema | svc method |
|---|---|---|---|
| `firewall_rule_list` | `Profile`, `Filter` | `sophosfw.v1.firewallRuleList` | `FirewallRuleSvc.List` |
| `firewall_rule_show` | `Profile`, `Name` (required) | `sophosfw.v1.firewallRule` | `FirewallRuleSvc.Get` |

### 3.7 NAT rule tools (2)

| Tool | Inputs | Output schema | svc method |
|---|---|---|---|
| `nat_rule_list` | `Profile`, `Filter` | `sophosfw.v1.natRuleList` | `NATRuleSvc.List` |
| `nat_rule_show` | `Profile`, `Name` (required) | `sophosfw.v1.natRule` | `NATRuleSvc.Get` |

### 3.8 Tool annotations

Every tool's MCP `Annotations` block sets:
- `ReadOnlyHint: true`
- `Title`: human-readable, e.g. `"List IP host objects"`
- `Description` (the `Tool.Description` field): one-sentence summary mirroring the cli `Short` field, optionally with a hint like `"Returns sophosfw.v1.hostIpList envelope."`

`DestructiveHint`, `IdempotentHint`, `OpenWorldHint` not set in Phase 4 (they're meaningful for mutation tools — Phase 6).

## 4. Server lifecycle

### 4.1 `Deps`, `NewServer`, `Serve`

```go
type Deps struct {
    Config         *config.Config
    Creds          creds.Store
    Catalog        *catalog.Catalog
    NewClient      svc.ClientFactory
    DefaultProfile string  // from --profile flag at server startup
}

type Server struct {
    deps Deps
    impl *mcp.Server  // SDK server handle
}

func NewServer(d Deps) *Server { ... }

func (s *Server) Serve(ctx context.Context, transport mcp.Transport) error {
    if err := s.registerAll(); err != nil { return err }
    return s.impl.Run(ctx, transport)
}
```

`Serve`'s signature changes from `(ctx, w io.Writer) error` to `(ctx, transport mcp.Transport) error`. The cli's `mcp serve` command constructs the transport (`mcp.NewStdioTransport(os.Stdin, os.Stdout)`) and passes it in. The foundation stub's behavior of "print startup line, block on ctx.Done()" is replaced by the SDK's `impl.Run()` which:
- Reads JSON-RPC requests from the transport.
- Dispatches to registered handlers.
- Writes JSON-RPC responses back.
- Returns when transport closes or `ctx` cancels.

The startup-report behavior (printing `"sophosfw MCP server: 0 tools registered..."`) is removed — MCP servers should be silent on stdout outside of JSON-RPC frames. (The line was only useful for the foundation stub's manual smoke test; Phase 4 has the SDK's own initialization handshake.)

### 4.2 `registerAll`

```go
func (s *Server) registerAll() error {
    if err := s.registerAuth();         err != nil { return err }
    if err := s.registerObject();       err != nil { return err }
    if err := s.registerRaw();          err != nil { return err }
    if err := s.registerHostIP();       err != nil { return err }
    if err := s.registerService();      err != nil { return err }
    if err := s.registerFirewallRule(); err != nil { return err }
    if err := s.registerNATRule();      err != nil { return err }
    return nil
}
```

Each `registerXxx` adds 1-4 tools via `s.impl.AddTool(tool, handler)`. The SDK uses Go reflection on the handler's third argument type to derive the input JSON Schema.

### 4.3 Helper functions (`server_helpers.go`)

```go
// resolveProfile returns the input's Profile if non-empty, otherwise the server's
// DefaultProfile. The svc layer receives the result; if it's still empty there,
// AuthSvc/ProfileSvc/etc. fall back to the config's currentProfile.
func (s *Server) resolveProfile(input string) string {
    if input != "" { return input }
    return s.deps.DefaultProfile
}

// jsonResult wraps a JSON byte slice as an MCP tool result with one text content.
func jsonResult(body []byte) *mcp.CallToolResult {
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: string(body)},
        },
    }
}

// errorEnvelopeResult renders a sophosfw.v1.error envelope as a tool result body.
// Per the design (Q6/B), business errors return as successful tool calls with an
// error envelope body — not as MCP tool errors.
func (s *Server) errorEnvelopeResult(err error, profile string) *mcp.CallToolResult {
    kind := svc.ErrorKind(err)  // shared error→kind helper
    body, _ := render.ErrorEnvelope(kind, err.Error(), profile)
    return jsonResult(body)
}

// ptrBool is a one-liner since the SDK uses *bool for nullable annotation fields.
func ptrBool(b bool) *bool { return &b }
```

### 4.4 cli `mcp serve` changes

`internal/cli/mcp.go` adds one flag and passes it through to `Deps`:

```go
func newMCPCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
    var defaultProfile string
    cmd := &cobra.Command{Use: "mcp", Short: "MCP server commands"}
    serveCmd := &cobra.Command{
        Use:   "serve",
        Short: "Start the MCP server (Phase 4: 21 read-only tools)",
        RunE: func(cmd *cobra.Command, _ []string) error {
            s := mcp.NewServer(mcp.Deps{
                Config:         d.Config,
                Creds:          d.Creds,
                Catalog:        cat,
                NewClient:      d.NewClient,
                DefaultProfile: defaultProfile,
            })
            transport := mcp.NewStdioTransport(os.Stdin, cmd.OutOrStdout())
            return s.Serve(cmd.Context(), transport)
        },
    }
    serveCmd.Flags().StringVar(&defaultProfile, "profile", "", "default profile for tool calls (empty = config currentProfile)")
    cmd.AddCommand(serveCmd)
    return cmd
}
```

`Deps.NewClient` already exists from foundation but wasn't wired into the stub. T1 of the implementation plan adds the field and the stub still works (no behavior change because the stub didn't use it).

## 5. Refactors landed before MCP work

### 5.1 Render envelope helpers (T1 of the plan)

`internal/render/envelope.go` exports one function per `sophosfw.v1.*` schema. Example:

```go
func HostIPListEnvelope(list *svc.HostIPList) ([]byte, error) {
    var buf bytes.Buffer
    err := WriteJSON(&buf, "sophosfw.v1.hostIpList", map[string]any{
        "profile": list.Profile,
        "xmlTag":  "IPHost",
        "count":   list.Count,
        "items":   list.Items,
    })
    return buf.Bytes(), err
}
```

The cli renderers call `render.HostIPListEnvelope(out)` and write the bytes to stdout. MCP handlers call it and return the bytes as text content. Single source of truth.

**~21 envelope helpers**, one per schema. Each is 5-10 LOC. Tests (envelope_test.go): one per helper, asserting byte-identical output to the existing cli when given the same input — guarantees the refactor is invisible to consumers.

### 5.2 Shared error→kind mapping (T2 of the plan)

`cli.ErrorKind(err) → string` already exists in `internal/cli/errors.go`. T2 moves the mapping logic into a function that both cli and mcp can call. Two reasonable options:

- **A: extract to `internal/svc`** — add `svc.ErrorKind` alongside `svc.FindReferences`. Pros: cli already imports svc; no new package. Cons: error mapping is more presentation than service.
- **B: new `internal/sophosfwerr` package** — clean home for cross-cutting error mapping. Pros: cleanest semantics. Cons: yet another package.

**Recommend A.** `internal/svc/errors.go` exports `func ErrorKind(err error) string`. `internal/cli/errors.go`'s `ErrorKind` becomes a thin wrapper or is replaced. The mcp package imports it directly. T2's diff is small.

## 6. Error handling

### 6.1 Mapping table

Per Section 6 of brainstorm. Same vocabulary cli already uses; nothing new at the wire level.

| Source | Envelope `kind` |
|---|---|
| `sophos.ErrAuthFailed` | `auth_failed` |
| `sophos.ErrNotFound` | `not_found` |
| `sophos.ErrPermissionDenied` | `permission_denied` |
| `sophos.ErrInvalidRequest` | `invalid_request` |
| `sophos.ErrServerError` | `server_error` |
| `sophos.ErrReadOnlyViolation` | `read_only_violation` |
| `svc.ErrUnsupportedInPhase` | `unsupported_in_phase` |
| Filter parse failure (`sophos.ParseFilterFlag`) | `invalid_request` |
| `errors.Is(err, ErrCatalogUnknownTag)` | `invalid_request` |
| Profile not found | `config_error` |
| Network connectivity / DNS / connection refused | `network_error` |
| TLS handshake failures | `tls_error` |
| Anything else | `generic` |

### 6.2 Reserved channels

The SDK's tool-error channel (`return result, nil, err` with `err != nil`, producing `is_error: true`) is reserved for:
- SDK-detected schema validation failures on input (handled by SDK, not by us).
- Catastrophic internal failures (handler panics, etc.) — caught by SDK's panic recovery if available, otherwise produces an `is_error: true` response from the SDK runtime.

All foreseeable business errors come back as success bodies with `sophosfw.v1.error` envelopes.

### 6.3 `--with-references` partial failures

Already handled by `HostIPSvc.Usage` and `ServiceSvc.Usage`: the success body contains both the populated `references` map and a `referenceErrors` map for any per-referrer failures. No change needed at the MCP layer.

### 6.4 No-default-profile error

If `Profile` is empty in the input AND `DefaultProfile` is empty AND the config has no `currentProfile`, the eventual `Config.ActiveProfile("")` call returns an error. The handler's catch-all error path renders this as a `config_error` envelope. Agent gets a useful message: "no current profile configured".

## 7. Testing strategy

### 7.1 Per-tool handler tests (~21 + 4 error tests)

Each per-group `*_test.go` follows the pattern:

```go
// internal/mcp/hostip_test.go
type fakeHostIpClient struct { /* same as svc tests */ }

func newServerForHostIPTest(t *testing.T, body map[string][]json.RawMessage) *Server {
    t.Helper()
    cat, _ := catalog.NewDefault()
    cfg := config.New()
    cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
    store := creds.NewFileStore(t.TempDir())
    require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
    return NewServer(Deps{
        Config: cfg, Creds: store, Catalog: cat,
        NewClient: func(_ config.Profile, _ creds.Credentials) svc.Client {
            return fakeHostIpClient{body: body}
        },
        DefaultProfile: "home",
    })
}

func TestHostIpList_Handler(t *testing.T) {
    s := newServerForHostIPTest(t, map[string][]json.RawMessage{
        "IPHost": {json.RawMessage(`{"Name":"LAN",...}`)},
    })
    out, _, err := s.handleHostIpList(context.Background(), nil, HostIpListInput{})
    require.NoError(t, err)
    require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIpList"`)
    require.Contains(t, textOf(out), `"cidr": "10.0.0.0/24"`)
}
```

`textOf(*mcp.CallToolResult)` extracts the joined text from all `Content` items.

**21 happy-path tests**, one per tool. Each asserts schema name + at least one expected key data field.

**4 error-path tests** in dedicated `*_test.go` files:
- `TestHostIpShow_NotFound`: empty body → `not_found` envelope.
- `TestAuthStatus_NoProfileConfigured`: empty config → `config_error` envelope.
- `TestObjectGet_UnknownTag`: bad tag → `invalid_request` envelope.
- `TestRawGet_AuthFailed`: stub client returning `sophos.ErrAuthFailed` → `auth_failed` envelope.

### 7.2 Wire-format integration tests (2)

`internal/mcp/server_test.go`:

```go
func TestServer_DispatchesHostIpList_OverWire(t *testing.T) {
    server := newServerForHostIPTest(t, ...)
    client := mcp.ConnectInMemory(server.impl)  // SDK's in-memory transport pair
    defer client.Close()
    result, err := client.CallTool(context.Background(), "host_ip_list", map[string]any{})
    require.NoError(t, err)
    require.Contains(t, textOf(result), `"schema": "sophosfw.v1.hostIpList"`)
}

func TestServer_RegistersAllTools(t *testing.T) {
    server := newServerForHostIPTest(t, nil)
    client := mcp.ConnectInMemory(server.impl)
    tools, err := client.ListTools(context.Background())
    require.NoError(t, err)
    require.Len(t, tools, 21)
    names := toolNames(tools)
    require.Contains(t, names, "host_ip_list")
    require.Contains(t, names, "auth_status")
    require.Contains(t, names, "raw_get")
    require.Contains(t, names, "nat_rule_show")
}
```

These prove SDK accepts handler signatures and dispatch works.

### 7.3 Render envelope tests

`internal/render/envelope_test.go` has one test per envelope helper. Each asserts the output bytes match what the existing cli would produce for the same input. This guarantees the T1 refactor is invisible.

```go
func TestHostIPListEnvelope_MatchesCliOutput(t *testing.T) {
    list := &svc.HostIPList{Profile: "home", Count: 1, Items: []svc.HostIP{...}}
    got, err := render.HostIPListEnvelope(list)
    require.NoError(t, err)
    // The cli's existing output for the same data, captured into want:
    want := `{
  "schema": "sophosfw.v1.hostIpList",
  "profile": "home",
  ...
}` + "\n"
    require.Equal(t, want, string(got))
}
```

**~21 tests** for envelope round-tripping. Boring but locks the contract.

### 7.4 Integration tests (build-tagged)

Extend `internal/testutil/integration_test.go` with one MCP-flavored test that boots the server in-memory and dispatches `host_ip_list` against the real firewall:

```go
//go:build integration

func TestIntegration_MCPServer_HostIpList(t *testing.T) {
    // Build server with real foundation deps (loadProfile, real ClientFactory).
    // Connect in-memory SDK client.
    // Call host_ip_list, assert no error, asser the body parses as sophosfw.v1.hostIpList.
}
```

One test is enough — the per-tool tests cover behavior; this one proves the SDK transport doesn't break against a real svc + sophos client.

### 7.5 Total

- **~25** new behavioral tests (21 happy + 4 error).
- **~2** wire-format smokes.
- **~21** render envelope round-trip tests.
- **~1** integration smoke (build-tagged).
- **~49** new test functions total.

Plus all existing cli/svc tests must stay green after the refactor (zero-regression target).

## 8. Acceptance criteria

A Phase 4 implementation is acceptance-passing when:

1. `go fmt ./...` produces no output.
2. `go vet ./...` produces no warnings.
3. `go test -race ./...` passes all tests, including the ~49 new ones.
4. `make build` produces a binary that:
   - Lists all 21 tools when `mcp serve` is invoked and asked via `tools/list` over stdio.
   - Shows `--profile` flag in `sophosfw mcp serve --help`.
5. Manual smoke against a local mcp-inspector (or equivalent):
   - `host_ip_list {}` returns a `sophosfw.v1.hostIpList` envelope.
   - `service_list {}` returns a `sophosfw.v1.serviceList` envelope.
   - `firewall_rule_list {}` returns a `sophosfw.v1.firewallRuleList` envelope.
   - `nat_rule_list {}` returns a `sophosfw.v1.natRuleList` envelope.
   - `auth_status {}` returns a `sophosfw.v1.authStatus` envelope.
   - `host_ip_show {"name":"missing-host"}` returns a body with `"schema": "sophosfw.v1.error"` and `"kind": "not_found"`.
6. `make skill-doctor` still passes.
7. `SOPHOSFW_INTEGRATION=1 SOPHOSFW_PROFILE=home make test-int` passes the new MCP integration smoke.
8. No mutating envelopes constructed anywhere in Phase 4 code.
9. Tagged as `v0.3.0-phase4` on `main`.

## 9. Open questions / assumptions to verify in the plan

- **SDK API specifics**: this design assumes the SDK's tool-handler signature is `func(ctx, *CallToolRequest, In) (*CallToolResult, any, error)` and that `AddTool` accepts a typed handler. The plan's first task should `go get github.com/modelcontextprotocol/go-sdk@v1.5.0` and verify the actual SDK shape. If it differs, the per-tool handler signatures here adjust accordingly. Spec contract (envelopes, tool names, profile resolution) does not.
- **`mcp.NewStdioTransport`** — the SDK may name this `NewStdioTransport`, `StdioTransport`, etc. Plan task 1 verifies by reading SDK docs.
- **`mcp.ConnectInMemory`** — used in wire-format tests. Real name may be different. If absent, the plan's wire-format tests use stdio with a `bytes.Buffer` pair as transport.
- **Object_search contract**: the search is client-side substring on `Name`. If the search predicate should also include other catalog-defined "filterable" fields (matching `host_ip_search` which checks Name + IPAddress + Subnet), the plan's `object_search` test should set that expectation. Recommend Name-only for genericism (catalog tags vary widely in their fields); document the limitation in the tool description.
- **`auth_test` round-trip side effects**: it actually calls the firewall to verify creds. If the agent calls it repeatedly, that's traffic. Tool description warns that it's a network operation.
