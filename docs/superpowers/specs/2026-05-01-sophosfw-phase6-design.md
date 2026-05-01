# sophosfw — Phase 6 Design (Safe mutations: host ip + raw apply)

**Status:** approved 2026-05-01. Implementation plan to follow.

**Predecessor:** Phase 5, tagged `v0.4.0-phase5` on `main` (commit `09638d2`). Earlier specs: foundation, Phase 3, Phase 4, Phase 5.

## 1. Goal and scope

### 1.1 Goal

Phase 6 ships the first mutating operations against live firewall infrastructure. Three first-class CLI commands (`host ip create/update/delete`), three MCP tools (`host_ip_create/update/delete`), and a real `raw request --yes --confirm-mutating` apply path replace the foundation's `ErrUnsupportedInPhase` stubs. The deliverable is the safety contract for mutations — every code path that writes is gated by explicit human/agent intent (`--yes` / `confirm: true`), drift detection (`--expected-diff-hash` / `expected_diff_hash`), pre-flight read-only-profile rejection, and append-only local audit logging — not surface coverage. Service / firewall rule / nat rule mutations defer to a later phase.

### 1.2 In scope

- **3 cli commands**: `sophosfw host ip create`, `sophosfw host ip update`, `sophosfw host ip delete`. All default to `--dry-run` (preview, no apply); pass `--yes` to actually send. `update` and `delete` REQUIRE `--expected-diff-hash <hex>` (with `--ignore-diff-hash` opt-out flag for emergency override). Validation: client-side required-field check per HostType, server-side semantics.
- **3 MCP tools**: `host_ip_create`, `host_ip_update`, `host_ip_delete`. Each requires `confirm: true` (the SDK schema marks the field required; the handler explicitly verifies the value is `true`). `update` and `delete` require `expected_diff_hash` (same rules as cli; `ignore_expected_diff_hash: true` opts out). `raw_apply` is NOT exposed as an MCP tool — too sharp an edge for the agent surface.
- **`raw request --yes --confirm-mutating` apply path**: existing cli command extended. `--yes` alone is enough for non-mutating envelopes; mutating envelopes (Set/Remove) additionally require `--confirm-mutating`. The svc layer's `RawSvc.Apply` is rewritten from the foundation stub.
- **Pre-flight read-only-profile rejection in svc**: every mutation method checks `profile.ReadOnly` before building any envelope; returns `sophos.ErrReadOnlyViolation` immediately. Defense-in-depth alongside the foundation's wire-level check (which stays).
- **Append-only audit log** at `~/.config/sophosfw/audit.log` (mode 0600). One JSON entry per mutation attempt (success and failure). Fields: timestamp, profile, operation, objectType, objectName, expectedDiffHash, redactedXml, result, errorMessage. Disabled cleanly via `auditLog: false` in config defaults; default-on.
- **`expectedDiffHash` mechanism**: SHA-256 over canonical JSON of the typed record (excluding `derived` block). New `internal/svc/diffhash.go`. `host ip show --include-diff-hash` (default true) adds `_diffHash` field to the JSON output. Same field automatic in MCP `host_ip_show`. Update/Delete fetch current state, compute hash, compare to caller's `expectedDiffHash`; mismatch → `ErrDiffHashMismatch`.
- **Catalog `Mutable bool` field** added to `Entry`. Only `IPHost` gets `mutable: true` in Phase 6. All other entries default false. Mutation methods pre-flight check this; future typed types must add `mutable: true` before Phase 7+ mutation work.
- **Sophos envelope builders**: `BuildSetEnvelope(operation, inner, username, password)` and `BuildRemoveEnvelope(inner, username, password)` in `internal/sophos/request.go`. svc layer renders inner XML (`<IPHost><Name>X</Name>...</IPHost>`) and wraps via these helpers.
- **Agent skill updates** (canonical files in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/`): SKILL.md "Common Change Workflows" gets concrete examples; `mcp-tools.md` adds "host_ip mutating tools" section; `safety-checklist.md` adds items #13 and #14 (dry-run-first; diff-hash-mismatch handling); `audit-template.md` adds a third example for mutations; `examples.md` adds a "Mutating IP host objects" section. Same workflow as Phase 5: changes land as untracked working-tree changes in skillshare.
- **Skill-doctor expansion**: 3 new required strings — `sophosfw host ip create`, `sophosfw host ip delete`, `host_ip_create` (MCP sentinel). Append to `requiredCommandsInExamples` in `internal/cli/skill.go`. Tests updated.
- **Documentation updates**: `docs/api-coverage.md` IPHost row's Add/Update/Remove cells flip from "Phase 6" to actual command names; `docs/roadmap.md` Phase 6 status → "complete; v0.5.0-phase6".
- **Tag** as `v0.5.0-phase6`.

### 1.3 Out of scope (deferred)

- **Mutating commands for service, firewall rule, nat rule**. Phase 6.5 or Phase 7 will pick these up after the safety contract is validated against IPHost.
- **Typed structs for FirewallRule and NATRule**. Phase 3 deferred these "until the mutation surface clarifies what we need"; Phase 6 keeps that deferral until at least one rule-mutation phase.
- **Real-firewall apply integration tests**. Unit tests use fakes; build-tagged integration smoke covers `--dry-run` only. The foundation's `IntegrationClient` continues to PANIC on any mutating envelope sent in the standard `make test-int` path. A separate `mutation_integration` tag could be added later by a future task.
- **Snapshot / draft / diff workflows**. Phase 7.
- **Bulk operations / transactions across multiple objects**. Phase 7.
- **Rollback support**. Phase 7.
- **Catalog `mutationVerbs` / `requiredOnCreate` / `requiredOnUpdate` schema fields**. Phase 6 adds only `mutable: true|false`. Richer schema-in-YAML waits until we've added more typed mutation surfaces.
- **Audit log rotation, size limits, structured query tools**. Append-only file; user rotates manually if desired.
- **`raw_apply` MCP tool**. CLI-only escape hatch.

### 1.4 Deliverable

Phase 6 ships as `v0.5.0-phase6` on `main`. Acceptance: `go fmt`/`vet`/`test -race` clean, `make build` produces a binary exposing the new mutating commands and 24-tool MCP server, `make skill-doctor` green, manual smoke confirms `host ip create --dry-run` returns the expected `sophosfw.v1.preview` envelope and `host ip create --yes` (against a willing test target) actually creates the object and writes an audit log entry.

## 2. Architecture and dependency direction

```
                              cmd/sophosfw/main.go
                                    │
                                    │ (constructs AuditLog from baseDir + config flag)
                                    │ (passes Audit into svc.Deps)
                                    ▼
internal/cli/hostip.go (existing — adds 3 mutating subcommands + show --include-diff-hash)
internal/cli/raw.go    (existing — adds --confirm-mutating flag + Apply routing)
                                    │
                                    ▼
internal/mcp/hostip.go (existing — adds 3 mutating tools)
internal/mcp/raw.go    (existing — keeps raw_get; raw_apply NOT registered)
                                    │
                                    ▼
internal/svc/hostip.go (existing — adds Create/Update/Delete)
internal/svc/raw.go    (existing — replaces Apply stub with real impl)
internal/svc/audit.go  (NEW — append-only JSON audit logger; ~80 LOC)
internal/svc/diffhash.go (NEW — SHA-256 over canonical JSON; ~30 LOC)
                                    │
                                    ▼
internal/sophos/request.go (existing — adds BuildSetEnvelope, BuildRemoveEnvelope)
internal/safety/mutating.go (existing — IsMutating; no changes)
internal/catalog/catalog.go (existing — adds Mutable field to Entry)
internal/catalog/objects.yaml (existing — adds mutable: true to IPHost)
internal/config/config.go (existing — adds Defaults.AuditLog *bool)
```

The **new mutation flow** is layered: cli/MCP → svc → audit log + sophos client. Each layer enforces a piece of the safety contract:

1. **cli/MCP**: parses input; verifies intent flags (`--yes` / `confirm: true` / `--confirm-mutating` for raw mutating).
2. **svc**: validates inputs (Q8/C — required-field check); pre-flight read-only-profile rejection (Q4/C); for update/delete, fetches current state and validates `expectedDiffHash`; builds envelope; writes audit log entry on either success or failure.
3. **sophos client**: builds the wire envelope; the foundation's wire-level read-only-profile check stays as defense-in-depth.

The new svc fields are append-only — none of the existing read-side methods change. The cli surface is additive. The MCP surface adds 3 tools; the existing 21 read-only tools stay unchanged.

## 3. Audit log mechanics

### 3.1 New file: `internal/svc/audit.go`

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

type AuditEntry struct {
	Timestamp        string `json:"timestamp"`
	Profile          string `json:"profile"`
	Operation        string `json:"operation"`        // create | update | delete | raw_apply | raw_apply_mutating
	ObjectType       string `json:"objectType"`       // IPHost | raw
	ObjectName       string `json:"objectName,omitempty"`
	ExpectedDiffHash string `json:"expectedDiffHash,omitempty"`
	RedactedXML      string `json:"redactedXml"`
	Result           string `json:"result"`           // ok | error:<kind>
	ErrorMessage     string `json:"errorMessage,omitempty"`
}

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
	if !a.enabled {
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

### 3.2 Configuration knob

`internal/config/config.go` `Defaults` struct gains:

```go
type Defaults struct {
	Timeout  time.Duration `yaml:"timeout,omitempty"`
	AuditLog *bool         `yaml:"auditLog,omitempty"`  // NEW: pointer for "unset = default-on"
}
```

Plus a new accessor on `*Config`:

```go
func (c *Config) AuditLogEnabled() bool {
	if c == nil || c.Defaults.AuditLog == nil {
		return true  // default-on
	}
	return *c.Defaults.AuditLog
}
```

### 3.3 Wiring

`cmd/sophosfw/main.go`:

```go
audit := svc.NewAuditLog(baseDir, cfg.AuditLogEnabled())
```

The audit log gets passed into:
- `svc.HostIPSvc{Audit: audit}` (new field).
- `svc.RawSvc{Audit: audit}` (new field).
- `mcp.Deps{Audit: audit}` (new field, threaded into the per-group factories).

Read-side methods (List/Get/Search/Usage) don't write to the audit log. Only mutation paths do.

### 3.4 Failure mode

If `audit.Write` itself errors (disk full, permissions, etc.), the mutation operation does NOT fail — the audit failure is suppressed (`_ = s.Audit.Write(...)`) so a misbehaving log doesn't block legitimate mutations. The mutation's success/failure is reported on its own terms.

## 4. `expectedDiffHash` mechanics

### 4.1 New file: `internal/svc/diffhash.go`

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
// serialization of the given typed record.
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

### 4.2 What's hashed

For IPHost: the raw `catalog.IPHost` record (not the wrapped `svc.HostIP` with its `Derived` block). Specifically, fields: `Name`, `IPFamily`, `HostType`, `IPAddress`, `Subnet`, `StartIPAddress`, `EndIPAddress`, `IPAddressList`. The canonicalize function sorts keys alphabetically; values are marshaled with Go's default encoding. The hex hash is exposed to callers as the `_diffHash` JSON field.

### 4.3 Caller flow

1. Agent calls `host_ip_show` (or cli `host ip show --json --include-diff-hash`). Response includes `_diffHash: "abc123..."`.
2. Agent decides to update; constructs `host_ip_update` call with `expectedDiffHash: "abc123..."` plus the new field values.
3. svc fetches current IPHost state, computes its diff hash, compares.
4. Match → svc proceeds to build/send the Set envelope, write audit log.
5. Mismatch → svc returns `ErrDiffHashMismatch`; cli/MCP wraps in `sophosfw.v1.error` envelope with `kind: diff_hash_mismatch`. Agent is expected to re-fetch and re-evaluate (per skill update item #14).

### 4.4 Error sentinels

New in `internal/svc/errors_kind.go`:

```go
var (
	ErrDiffHashMismatch = errors.New("diff hash mismatch: object has changed since you last read it")
	ErrDiffHashRequired = errors.New("expectedDiffHash is required for update/delete")
)
```

`ErrorKind` mapping additions:
- `errors.Is(err, ErrDiffHashMismatch)` → `"diff_hash_mismatch"`
- `errors.Is(err, ErrDiffHashRequired)` → `"invalid_request"`

### 4.5 Override

Both cli (`--ignore-diff-hash`) and MCP (`ignore_expected_diff_hash: true`) bypass the comparison. The audit log entry records `expectedDiffHash: "ignored"` (literal string) rather than a hex value when ignored. Agent skill item #14 explicitly tells agents NOT to use this reflexively.

## 5. svc.HostIPSvc mutation methods

### 5.1 Input and result types

```go
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

type HostIPMutationResult struct {
	Profile   string
	Operation string             // "create" | "update" | "delete"
	Name      string
	DryRun    bool
	Preview   *Preview            // populated when DryRun=true; reuses existing svc.Preview
	Item      *HostIP             // populated when applied; re-fetched post-write
}
```

### 5.2 Method signatures

```go
func (s *HostIPSvc) Create(ctx context.Context, profileName string, input HostIPCreateInput, dryRun bool) (*HostIPMutationResult, error)

func (s *HostIPSvc) Update(ctx context.Context, profileName string, input HostIPCreateInput, expectedHash string, ignoreHash bool, dryRun bool) (*HostIPMutationResult, error)

func (s *HostIPSvc) Delete(ctx context.Context, profileName, name, expectedHash string, ignoreHash bool, dryRun bool) (*HostIPMutationResult, error)
```

The `HostIPSvc` struct gains `Audit *AuditLog` (Phase 5 had `Inner *ObjectSvc` only; Phase 6 adds Audit).

### 5.3 Validation

Private function `validateHostIPCreate(input HostIPCreateInput) error`:

```go
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
```

### 5.4 Pre-flight read-only check

Each mutation method starts with:

```go
profile, name, err := s.Inner.Config.ActiveProfile(profileName)
if err != nil {
	return nil, err
}
if profile.ReadOnly {
	return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
}
```

### 5.5 Catalog mutable check

After read-only-check, before validation:

```go
entry, ok := s.Inner.Catalog.Resolve("IPHost")
if !ok || !entry.Mutable {
	return nil, fmt.Errorf("%w: IPHost is not marked mutable in the catalog", sophos.ErrUnsupportedInPhase)
}
```

(`ErrUnsupportedInPhase` reused — meaning "this typed type doesn't support mutations yet.")

### 5.6 Audit log writing

Every mutation method ends with a deferred `s.Audit.Write(entry)`. The entry's `Result` field is "ok" or "error:<kind>"; the redacted XML is the envelope that would have been sent (for dry-run, the same envelope, since the user is asking what WOULD go on the wire). The audit entry is written even in the dry-run path so the user has a record of what they previewed.

## 6. CLI surface

### 6.1 `host ip create`

`internal/cli/hostip.go` adds `newHostIpCreateCmd(d, cat)`:

- Flags: `--name` (required), `--ip-family` (default IPv4), `--host-type` (default Network), `--ip-address`, `--subnet`, `--start-ip`, `--end-ip`, `--ip-list`, `--yes` (default false).
- RunE: builds `HostIPCreateInput`, calls `HostIPSvc.Create(ctx, profile, input, !yes)`.
- Renders via new `renderHostIpMutation(cmd, *HostIPMutationResult) error` helper that emits either `sophosfw.v1.preview` (dry-run) or `sophosfw.v1.hostIpMutation` (apply).

### 6.2 `host ip update`

Same flags as create plus:
- `--expected-diff-hash <hex>` (required unless --ignore-diff-hash).
- `--ignore-diff-hash` (bool; opt-out).
- Cobra-level validation: at least one of `--expected-diff-hash` or `--ignore-diff-hash` must be set when `--yes` is given. (For `--dry-run` the diff-hash check is skipped — preview the envelope, don't fetch state.)

### 6.3 `host ip delete <name>`

- Positional name.
- `--expected-diff-hash <hex>` (required unless --ignore-diff-hash).
- `--ignore-diff-hash`.
- `--yes`.

### 6.4 `host ip show --include-diff-hash`

Existing `host ip show` cmd gains:
- `--include-diff-hash` (default true) — when true, the JSON output includes `_diffHash: "<hex>"` as a top-level field. The `host_ip_show` MCP tool always includes the field (no flag).

The diff hash is computed over the IPHost record (excluding Derived) using `svc.DiffHash`.

### 6.5 New envelope schema: `sophosfw.v1.hostIpMutation`

```json
{
  "schema": "sophosfw.v1.hostIpMutation",
  "profile": "home",
  "operation": "create",
  "name": "LAN-network",
  "applied": true,
  "item": {
    "Name": "LAN-network",
    "IPFamily": "IPv4",
    "HostType": "Network",
    "IPAddress": "10.0.0.0",
    "Subnet": "255.255.255.0",
    "derived": { "cidr": "10.0.0.0/24", "kind": "network" },
    "_diffHash": "abc123..."
  }
}
```

Dry-run path uses the existing `sophosfw.v1.preview` envelope (foundation already defined this for `raw request --dry-run`).

New helper in `internal/render/envelope.go`: `HostIpMutationEnvelope(*svc.HostIPMutationResult) ([]byte, error)`.

## 7. MCP surface

### 7.1 New tools

`internal/mcp/hostip.go` adds three tools and three handlers:

```go
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
	// All Create fields, plus:
	ExpectedDiffHash       string `json:"expectedDiffHash" jsonschema:"required"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
}

type HostIpDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash" jsonschema:"required"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}
```

### 7.2 Confirm enforcement

Each handler's first check:

```go
if !in.Confirm {
	return s.errorEnvelopeResult(
		fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest),
		profile,
	)
}
```

The SDK schema-required marker guarantees the field is present; we also explicitly verify the value is `true`. `confirm: false` would otherwise pass schema validation.

### 7.3 Tool annotations

```go
sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
	Name:        "host_ip_create",
	Description: "Create a new IPHost. Requires confirm: true. Use dryRun: true to preview without applying.",
	Annotations: &sdkmcp.ToolAnnotations{
		ReadOnlyHint: false,
		Title:        "Create IP host",
	},
}, s.handleHostIpCreate)
```

`host_ip_delete` additionally sets `DestructiveHint: true` (the SDK supports this for destructive-tool warnings).

### 7.4 `raw_apply` NOT registered

Phase 6 deliberately does not expose `raw_apply` as an MCP tool. The cli `raw request --yes --confirm-mutating` path is the only mutating-raw access. Section 1.3 documents this.

### 7.5 Tool count update

`internal/mcp/server_test.go` `TestServer_RegistersAllTools` count goes from 21 → 24. The expected-name list adds `host_ip_create`, `host_ip_update`, `host_ip_delete`.

## 8. `raw request --yes --confirm-mutating` apply path

### 8.1 svc.RawSvc.Apply rewrite

Replace the foundation's `ErrUnsupportedInPhase` stub with the real implementation:

```go
func (s *RawSvc) Apply(ctx context.Context, profileName string, body []byte) error {
	profile, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return err
	}
	if profile.ReadOnly {
		return fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, name)
	}
	creds, err := s.Creds.Load(name)
	if err != nil {
		return err
	}
	full, err := sophos.BuildRawEnvelope(body, creds.Username, creds.Password)
	if err != nil {
		return err
	}

	cl := s.NewClient(profile, creds)
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

### 8.2 cli routing

`internal/cli/raw.go` adds `--confirm-mutating` flag:

```go
c.Flags().BoolVar(&confirmMutating, "confirm-mutating", false,
	"required when --yes is used and the envelope contains Set/Remove verbs")
```

When `--yes` is given:
1. Build the full envelope (using saved creds).
2. Call `safety.IsMutating(full)`.
3. If mutating AND `!confirmMutating`: error with the explicit message "raw request: envelope contains mutating verbs (Set/Remove); pass --confirm-mutating to acknowledge intent (with --yes)".
4. Otherwise: route through `RawSvc.Apply`.

Apply success path: prints `ok` to stdout; exits 0. The receipt is in the audit log; agents check there.

Apply failure path: returns the error; existing `cli.HandleError` handles it.

## 9. Catalog `Mutable` field

### 9.1 Code change

`internal/catalog/catalog.go` `Entry` gains:

```go
type Entry struct {
	Tag         string   `yaml:"tag"`
	Aliases     []string `yaml:"aliases,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Columns     []string `yaml:"columns,omitempty"`
	Filterable  []string `yaml:"filterable,omitempty"`
	UsageTag    string   `yaml:"usageTag,omitempty"`
	TypedParser string   `yaml:"typedParser,omitempty"`
	Mutable     bool     `yaml:"mutable,omitempty"`  // NEW
}
```

### 9.2 YAML edit

Find the IPHost entry in `internal/catalog/objects.yaml`:

```yaml
  - tag: IPHost
    aliases: [host-ip, ip-host]
    description: "IP host objects (single addresses, ranges, networks)"
    columns: [Name, IPFamily, HostType, IPAddress, Subnet]
    filterable: [Name, IPAddress, IPFamily, HostType]
    usageTag: IPHostStatistics
    typedParser: iphost
```

Add one line:

```yaml
    mutable: true
```

All other entries omit the field, defaulting to false.

### 9.3 Use sites

- `HostIPSvc.Create/Update/Delete` check `entry.Mutable == true` pre-flight.
- `internal/cli/object.go` `newObjectSchemaCmd` includes `mutable` in the JSON output (added to the `ObjectSchemaEnvelope`).
- `internal/render/envelope.go` `ObjectSchemaEnvelope` adds `"mutable": e.Mutable` to the payload map.

## 10. Sophos envelope builders

`internal/sophos/request.go` adds two helpers:

```go
// BuildSetEnvelope wraps inner XML in a <Set operation="..."> within the
// standard Sophos <Request><Login>...</Login>...</Request> envelope.
func BuildSetEnvelope(operation string, inner []byte, username, password string) ([]byte, error)

// BuildRemoveEnvelope wraps inner XML in a <Remove>...</Remove>.
func BuildRemoveEnvelope(inner []byte, username, password string) ([]byte, error)
```

These reuse the foundation's `BuildEnvelope` machinery for the `<Login>` wrapper and just add the `<Set>` or `<Remove>` layer around the user-supplied body.

The svc layer renders the typed inner via a helper:

```go
// marshalIPHost emits e.g. <IPHost><Name>X</Name><HostType>Network</HostType>
// <IPFamily>IPv4</IPFamily><IPAddress>10.0.0.0</IPAddress>
// <Subnet>255.255.255.0</Subnet></IPHost>.
// Empty fields are omitted.
func marshalIPHost(input HostIPCreateInput) ([]byte, error)
```

## 11. Error handling

| Condition | Error | Envelope kind |
|---|---|---|
| Required flag missing | `sophos.ErrInvalidRequest` (wrapped) | `invalid_request` |
| HostType-required-field missing | `sophos.ErrInvalidRequest` | `invalid_request` |
| Profile is read-only | `sophos.ErrReadOnlyViolation` | `read_only_violation` |
| `expectedDiffHash` empty AND `ignoreHash` false | `svc.ErrDiffHashRequired` | `invalid_request` |
| Hash mismatch | `svc.ErrDiffHashMismatch` | `diff_hash_mismatch` (NEW) |
| `confirm: false` (MCP) | `sophos.ErrInvalidRequest` | `invalid_request` |
| Catalog entry not mutable | `svc.ErrUnsupportedInPhase` | `unsupported_in_phase` |
| Sophos rejects (e.g. duplicate name on create) | typed `sophos.StatusError` | various |
| Audit log write fails | suppressed (logged-and-swallowed) | not surfaced |

`cli.ErrorKind` (now `svc.ErrorKind` per Phase 4 T2) gains:

```go
case errors.Is(err, ErrDiffHashMismatch):
	return "diff_hash_mismatch"
case errors.Is(err, ErrDiffHashRequired):
	return "invalid_request"
```

The cli's exit-code mapper (`internal/cli/errors.go` `ExitCodeFor`) gains a new mapping: `diff_hash_mismatch` → exit code 7 (new). Foundation defines codes 0-6; Phase 6 adds 7 for "drift detected".

## 12. Agent skill updates

Canonical files in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/`. Same workflow as Phase 5 — changes land as untracked working-tree changes; no sophosfw-repo commit for the canonical files.

### 12.1 SKILL.md "Common Change Workflows"

Replace the Phase 5 forward-looking text with concrete examples:

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

Mutations are recorded in `~/.config/sophosfw/audit.log` (one JSON line per attempt, including failures).
```

### 12.2 mcp-tools.md addition

New section between existing host_ip and service sections:

```markdown
## host_ip mutating tools

| Tool | Purpose |
|---|---|
| `host_ip_create` | Create a new IPHost (requires confirm: true) |
| `host_ip_update` | Update an existing IPHost (requires confirm: true AND expectedDiffHash) |
| `host_ip_delete` | Delete an IPHost (requires confirm: true AND expectedDiffHash) |

**When to use**
- The user explicitly asks to add/change/remove a host.

**Gotchas**
- ALL THREE require `confirm: true` to apply. Without it: error envelope.
- `host_ip_update` and `host_ip_delete` require `expectedDiffHash` from a prior `host_ip_show`. If the firewall state has drifted since you read it, you get `kind: diff_hash_mismatch`. Re-fetch and re-evaluate.
- `dryRun: true` returns the preview envelope without applying — use this to show the user what WILL be sent, then call again with `dryRun: false` (or omit).
- Audit log entries land in `~/.config/sophosfw/audit.log`.
```

### 12.3 safety-checklist.md additions

```markdown
13. ☐ When mutating: ALWAYS run `--dry-run` (CLI) or `dryRun: true` (MCP) first. Show the user the redacted XML and the verbs detected. Wait for explicit confirmation before re-running with `--yes` (CLI) or omitting `dryRun` (MCP).
14. ☐ When `expectedDiffHash` mismatch errors (`kind: diff_hash_mismatch`): do NOT add `--ignore-diff-hash` reflexively. Re-fetch the current object, re-evaluate whether the proposed change is still desired, ASK THE USER what to do.
```

### 12.4 audit-template.md addition

Add a third example showing a mutation entry from `~/.config/sophosfw/audit.log`:

```markdown
Example (mutation, from audit.log):

{"timestamp":"2026-05-15T14:23:11.234567890Z","profile":"home","operation":"create","objectType":"IPHost","objectName":"LAN-network","redactedXml":"<Request><Login><Username>admin</Username><Password>***REDACTED***</Password></Login><Set operation=\"add\"><IPHost><Name>LAN-network</Name>...</IPHost></Set></Request>","result":"ok"}

Mutating operations (host ip create/update/delete; raw request --yes --confirm-mutating) write to ~/.config/sophosfw/audit.log automatically. Disabled per-config via auditLog: false.
```

### 12.5 examples.md addition

New section:

```markdown
## Mutating IP host objects

```bash
# Create (preview):
sophosfw host ip create --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0

# Create (apply):
sophosfw host ip create --name LAN-network --host-type Network --ip-address 10.0.0.0 --subnet 255.255.255.0 --yes

# Show (capture diff hash):
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

## 13. Skill-doctor expansion

`internal/cli/skill.go` `requiredCommandsInExamples` gains 3 entries:

```go
"sophosfw host ip create",
"sophosfw host ip delete",
"host_ip_create",  // MCP sentinel
```

Total: 9 (Phase 5) + 3 = 12 required strings.

Skill-doctor tests in `internal/cli/skill_test.go` get stub `examples.md` + `mcp-tools.md` updates so the synthetic skill mentions the 3 new strings; existing tests stay deterministic.

## 14. Testing strategy

Per Q10/A — fakes only at unit; build-tagged dry-run integration smoke; no real-firewall apply.

### 14.1 New unit tests (~25 functions)

- `svc/audit_test.go` — 4 tests (append, disabled, file mode, concurrent writes).
- `svc/diffhash_test.go` — 3 tests (stable, different-input, key-order invariant).
- `svc/hostip_mutation_test.go` — 10 tests (Create dry-run, Create apply, Create read-only-rejection, Create validation failures, Update mismatch, Update match, Update ignoreHash, Delete required-hash, Delete apply, mutable-false-rejection).
- `svc/raw_test.go` — 3 new tests appended (Apply success, Apply read-only-rejection, Apply audit on failure).
- `cli/hostip_test.go` — 4 new tests appended (Create dry-run default, Create --yes applies, Update requires hash, Delete positional).
- `cli/raw_test.go` — 2 new tests appended (--yes without --confirm-mutating errors, --yes + --confirm-mutating applies).
- `mcp/hostip_test.go` — 5 new tests appended (Create requires confirm, Create dry-run, Create apply, Update requires hash, Delete apply).
- `mcp/server_test.go` — count update 21 → 24.
- `cli/skill_test.go` — existing 5 tests' stub skill content updated.

### 14.2 Integration smoke (build-tagged `integration`)

One new test in `internal/testutil/integration_test.go`:

```go
func TestIntegration_HostIPCreate_DryRun(t *testing.T) {
	// ... boot real config + creds + svc ...
	// Run host ip create --dry-run against the real firewall.
	// Assert preview envelope has mutating: true, verbs: ["Set:add"].
	// NO Apply call; the IntegrationClient would panic if any code path
	// attempted to send a mutating envelope.
}
```

The existing `IntegrationClient`'s panic-on-mutating stays as the safety net for the standard `make test-int` invocation.

### 14.3 Total

~25 new tests + 1 new integration smoke. All deterministic; the unit tests use fake clients.

## 15. Acceptance criteria

A Phase 6 implementation is acceptance-passing when:

1. `go fmt ./... && go vet ./... && go test -race ./...` all clean.
2. `make build` produces a binary that exposes `host ip create/update/delete`, `host ip show --include-diff-hash`, `raw request --yes --confirm-mutating`.
3. `sophosfw mcp serve` registers exactly 24 tools; `tools/list` includes `host_ip_create`, `host_ip_update`, `host_ip_delete`. `raw_apply` is NOT registered.
4. The audit log writer creates `~/.config/sophosfw/audit.log` (mode 0600) on first mutation; disabled cleanly via `auditLog: false`.
5. `make skill-doctor` outputs `skill ok` against the live skill (which now includes 12 required strings — 9 from Phase 5 plus 3 new).
6. Canonical skill content updates land in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` (untracked working-tree changes; not committed in sophosfw repo).
7. `internal/svc/raw.go` `Apply` no longer returns `ErrUnsupportedInPhase`; foundation stub comment removed.
8. `internal/catalog/objects.yaml` IPHost entry has `mutable: true`. All other entries default false.
9. `IntegrationClient` from foundation T32 continues to panic on mutating envelopes in standard `make test-int`.
10. `docs/api-coverage.md` IPHost row reflects new mutating commands; `docs/roadmap.md` Phase 6 status → "complete; v0.5.0-phase6".
11. Tagged as `v0.5.0-phase6`.

## 16. Implementation plan task estimate

12 tasks for the implementation plan:

- T1: Audit log (`internal/svc/audit.go` + tests; config knob).
- T2: Diff hash (`internal/svc/diffhash.go` + tests).
- T3: Sophos envelope builders (`BuildSetEnvelope`, `BuildRemoveEnvelope` + tests).
- T4: Catalog `Mutable` field (struct + YAML edit + parser test).
- T5: `HostIPSvc.Create` (validate, pre-flight, dry-run, apply, audit + tests).
- T6: `HostIPSvc.Update`, `Delete` (with diff hash + tests).
- T7: `RawSvc.Apply` real impl (+ tests).
- T8: cli `host ip create/update/delete` + `host ip show --include-diff-hash` + envelope helper.
- T9: cli `raw request --yes --confirm-mutating` + Apply routing.
- T10: MCP `host_ip_create/update/delete` (+ tests; tool count 21→24).
- T11: Agent skill content updates + skill-doctor required-list expansion.
- T12: Integration smoke + docs/api-coverage + docs/roadmap status + acceptance verification + tag v0.5.0-phase6.
