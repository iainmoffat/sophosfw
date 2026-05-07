# sophosfw — Phase 5 Design (Agent skill completion)

**Status:** approved 2026-05-01. Implementation plan to follow.

**Predecessor:** Phase 4, tagged `v0.3.0-phase4` on `main` (commit `056e6bf`). Earlier specs: foundation, Phase 3, Phase 4 in `docs/superpowers/specs/`.

## 1. Goal and scope

### 1.1 Goal

Update the agent skill at `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` to reflect the surface that actually ships now (Phase 3 first-class commands + Phase 4 MCP tools), refresh the dangerous-operations checklist for the read-only-only stance, and add forward-looking guidance about Phase 6 mutating workflows. Expand the project's `skill doctor` to validate the new surface stays documented.

### 1.2 In scope

- **Update `SKILL.md`**: replace stale "Phase 4 will" language; expand the "Read-Only First Rule" with first-class commands; rewrite "MCP Usage Pattern" to describe the 21 tools and link to the new `mcp-tools.md`; rewrite "Common Read-Only Workflows" to use first-class commands; extend "Common Change Workflows" with the Phase 6 forward-looking pattern (`--dry-run` → preview → `--yes` for cli; `confirm: true` for MCP); rename "Current Limitations (Foundation Phase)" to "Current Limitations (Phase 5)" and update bullets.
- **Create new `mcp-tools.md`** (`/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md`): per-group reference (auth, object, raw, host_ip, service, firewall_rule, nat_rule), each with a tool-name table, "When to use" prose, "Gotchas" bullets, and one representative YAML-style input snippet. Approximately 180 lines. Top of file links back to SKILL.md and notes that the agent's MCP host already shows tool input schemas — this file teaches judgment, not schema.
- **Update `examples.md`**: keep existing CLI sections; add new sections for first-class commands (`host ip`, `service`, `firewall rule`, `nat rule`); replace the foundation "MCP scaffold" section with a real "MCP server configuration" section showing the user's MCP host config; add an "MCP tool calls" section with YAML-style snippets for the 6 most-used tools.
- **Update `safety-checklist.md`**: rewrite item #3 (Foundation phase → Phase 5 stance); add item #11 (audit summary applies to MCP tool calls); add item #12 (`--with-references` partial-failure honesty).
- **Update `audit-template.md`**: replace single example with two (CLI first-class + MCP tool with `with_references`); add a paragraph noting the Names field can list referrer names and the Notes field should call out `referenceErrors`.
- **Expand `skill doctor`**: add 5 new strings to `requiredCommandsInExamples` (4 first-class command strings + `host_ip_list` MCP sentinel); change `runSkillDoctor` to scan both `examples.md` AND `mcp-tools.md`; treat missing `mcp-tools.md` as an error; tighten the function signature from the inline `interface { Write([]byte) (int, error) }` to `io.Writer` (small cleanup acknowledged by the foundation T31 quality reviewer).
- **Update tests** in `internal/cli/skill_test.go`: 1 new test (doctor finds strings in mcp-tools.md), 1 new test (doctor errors when mcp-tools.md missing), update existing pass-case tests to provide a stub `mcp-tools.md`.
- **Update docs**: `docs/api-coverage.md` and `docs/roadmap.md` status updates for Phase 5 completion.
- **Tag** as `v0.4.0-phase5`.

### 1.3 Out of scope (deferred)

- **`api-patterns.md` updates**: the foundation reference doc (XML envelopes, status codes, filter criteria) is still accurate. No edits.
- **New typed parsers / new catalog tags**: Phase 5 is docs-only.
- **Code refactors to `internal/cli/skill.go` beyond the required-commands list and the dual-file scan**: don't restructure the doctor.
- **Phase 6's actual mutating commands**: still don't exist. Phase 5's forward-looking content names the pattern but uses no example commands that don't yet work.
- **A new agent skill for a different MCP server**: scope-creep.
- **Detailed input-schema duplication for MCP tools**: the agent's host (Claude Desktop, Claude Code) already shows tool input schemas via `tools/list`. The skill teaches judgment.

### 1.4 Deliverable

Phase 5 ships as `v0.4.0-phase5` on `main`. Acceptance: `go fmt ./... && go vet ./... && go test -race ./...` clean, `make skill-doctor` outputs `skill ok` against the live (symlinked) skill content, the 5 canonical skill files are present in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/`, and the `internal/cli/skill.go` source + tests are updated to validate the expanded surface.

## 2. Architecture and dependency direction

```
                         /Users/ipm/code/ai-tooling/skillshare/
                         skills/sophos-firewall/   (canonical, in skillshare repo)
                         ├── SKILL.md              (modified)
                         ├── examples.md           (modified)
                         ├── safety-checklist.md   (modified)
                         ├── audit-template.md     (modified)
                         ├── api-patterns.md       (untouched)
                         └── mcp-tools.md          (new)
                              │
                              │  symlink, foundation T30
                              ▼
/Users/ipm/code/sophosfw/.claude/skills/sophos-firewall/
                              │
                              │  validated by
                              ▼
                  internal/cli/skill.go     (source updated)
                  internal/cli/skill_test.go (tests updated)
                              │
                              │  invoked by
                              ▼
                  make skill-doctor
```

Phase 5 changes content in two places:

1. **Skill content** in the user's separate `ai-tooling/skillshare` repo (not the sophosfw repo). Edits to existing files plus the new `mcp-tools.md`. Foundation T30 established that these changes are NOT committed in the sophosfw repo — the user commits them separately in skillshare.
2. **Skill doctor** in the sophosfw repo: `internal/cli/skill.go` and `internal/cli/skill_test.go`. This is the only source change in the sophosfw repo.

The Phase 5 sophosfw-repo commits include:
- Skill-doctor source + test updates (single commit).
- `docs/api-coverage.md` + `docs/roadmap.md` status updates (single commit).
- Acceptance pass adjustments (if any).
- The phase tag `v0.4.0-phase5`.

The skill content edits land in the working tree of the skillshare repo as untracked/uncommitted changes for the user to commit there.

## 3. SKILL.md edits — section by section

### 3.1 "Read-Only First Rule"

Current text leads with generic `object` commands. Rewrite to lead with first-class commands; demote generic to "escape hatch":

```markdown
## Read-Only First Rule

If the user asks for information about a typed object kind, prefer the
first-class command:
- IP hosts: `sophosfw host ip list/show/search/usage`.
- Services: `sophosfw service list/show/search/usage`.
- Firewall rules: `sophosfw firewall rule list/show`.
- NAT rules: `sophosfw nat rule list/show`.

For object kinds without first-class commands (FQDNHost, MACHost, Zone,
IPHostGroup, etc.), use the generic surface:
- `sophosfw object list <tag>` — generic, works for any catalog tag.
- `sophosfw object get <tag> --name <name>` — single record by name.
- `sophosfw object usage <tag> --name <name>` — IPHostStatistics-style.
- `sophosfw object schema <tag>` — catalog metadata.
- `sophosfw raw get <tag>` — when the catalog doesn't have what you need.

The same operations are available as MCP tools (`host_ip_show`,
`service_list`, `object_list`, `raw_get`, etc.). See `mcp-tools.md` for
the per-group reference.

Do not invoke `sophosfw raw request` unless the user explicitly asks to
see a preview of a hand-authored envelope. Never pass `--yes` — the
apply path is unimplemented and will return `unsupported_in_phase`.
```

### 3.2 "MCP Usage Pattern"

Current text says Phase 4 will add tools. Rewrite:

```markdown
## MCP Usage Pattern

Phase 4 ships 21 MCP read-only tools accessible over stdio JSON-RPC.
Configure your MCP host (Claude Desktop, Claude Code, mcp-inspector)
with:

` ` `json
{
  "mcpServers": {
    "sophosfw": {
      "command": "sophosfw",
      "args": ["mcp", "serve", "--profile", "home"]
    }
  }
}
` ` `

The `--profile` flag sets the server's default profile. Each tool also
accepts an optional `profile` argument that overrides the server-default
on a per-call basis.

Tool groups: 4 auth, 4 object (generic catalog), 1 raw, 4 host_ip, 4
service, 2 firewall_rule, 2 nat_rule. See `mcp-tools.md` for the per-
group reference and the gotchas list.

Output bodies are the same `sophosfw.v1.*` JSON envelopes the cli emits
in `--json` mode — the contract is uniform across cli and MCP. Errors
return as success bodies with a `sophosfw.v1.error` envelope (NOT as
MCP tool errors). The envelope's `kind` field tells the agent what
went wrong.
```

(In the actual file, replace ` ` ` with real triple-backticks for the JSON fence.)

### 3.3 "Common Read-Only Workflows"

Current cheatsheet lists generic commands. Rewrite to use first-class commands plus MCP equivalents:

```markdown
## Common Read-Only Workflows

See `examples.md` for command-by-command patterns and `mcp-tools.md` for
the MCP tool reference. Quick reference:
- Inventory all IP hosts: `sophosfw host ip list --json` (cli) or
  `host_ip_list` (MCP).
- Find a host by name fragment: `sophosfw host ip search LAN --json` or
  `host_ip_search {query: LAN}`.
- Where is this host used (rules + groups)?
  `sophosfw host ip usage NAME --with-references --json` or
  `host_ip_usage {name: NAME, with_references: true}`.
- List firewall rules: `sophosfw firewall rule list --json` or
  `firewall_rule_list`.
- Check connection health: `sophosfw auth test --json` or `auth_test`.
- Inspect a tag without a first-class command: `sophosfw object list
  Zone --json` or `object_list {tag: Zone}`.
```

### 3.4 "Common Change Workflows"

Add Phase 6 forward-looking pattern:

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

### 3.5 "Current Limitations"

Rename and update:

```markdown
## Current Limitations (Phase 5)

- No mutating operations — anything that would change the firewall.
  Phase 6 will land the apply path.
- No first-class command groups for FQDNHost, MACHost, Zone,
  IPHostGroup, ServiceGroup, FQDNHostGroup, Interface, Gateway. Use
  the generic `object` commands or `object_list/object_get` MCP tools
  for those tags.
- `--with-references` only scans IPHostGroup, FirewallRule, NATRule
  (for IPHost) and ServiceGroup, FirewallRule, NATRule (for Service).
  VPN, schedule, interface, certificate are not scanned.
- No agent-skill-side caching; every tool call is a fresh round-trip
  to the firewall.
```

### 3.6 Untouched sections

"Purpose", "When to Use", "When NOT to Use", "Safety Model", "CLI Usage Pattern", "Profile and Credential Handling", "Raw API Escape Hatch", "XML API Basics", "Output and JSON Parsing", "Error Handling", "Audit Summary Pattern", "Dangerous Operations Checklist", "Examples", "Things Agents MUST NEVER Do" — all still accurate. No edits.

## 4. `mcp-tools.md` (new file)

Top-of-file preamble (~10 lines):

```markdown
# Sophos Firewall MCP Tools — per-group reference

This file is the agent's reference for the 21 MCP tools registered by
`sophosfw mcp serve`. The agent's MCP host (Claude Desktop, Claude Code,
mcp-inspector) already exposes tool input schemas via the `tools/list`
mechanism — this file teaches *judgment* (when to use what, what to
expect, what to watch out for), not schema.

Output bodies for every tool are `sophosfw.v1.*` JSON envelopes. Errors
return as success bodies with `sophosfw.v1.error` envelopes; the `kind`
field tells the agent what went wrong (`auth_failed`, `not_found`,
`permission_denied`, etc.).

See `SKILL.md` for the broader safety contract and `examples.md` for
worked examples.
```

Then 7 group sections. Each group has:
1. Header + 1-sentence purpose.
2. Table of tool names with one-line descriptions.
3. **When to use** — 2-3 bullets.
4. **Gotchas** — 1-3 bullets per group.
5. **Example** — one YAML-style input snippet.

### 4.1 `auth` group

```markdown
## auth — authentication and profile management

| Tool | Purpose |
|---|---|
| `auth_status` | Profile + URL + whether credentials are stored (no network call) |
| `auth_test` | Test connectivity + credential validity (network call) |
| `auth_profile_list` | List all configured profiles |
| `auth_profile_current` | Single-entry profile list for the current profile |

**When to use**
- The user asks "which firewall am I talking to?" → `auth_status`.
- The user asks "is the connection working?" → `auth_test`.
- Multi-profile setups → `auth_profile_list` to enumerate, `profile`
  argument on subsequent tools to target a specific one.

**Gotchas**
- `auth_test` makes a real network round-trip. If the user is on a
  bandwidth-constrained connection or you're calling many tools in a
  loop, prefer `auth_status` (no network) when sufficient.
- `auth_status` reports `loggedIn: false` when credentials aren't
  stored locally — that's not necessarily an error; the user just
  hasn't run `sophosfw auth login`.

**Example**
` ` `yaml
auth_test:
  profile: home
` ` `
```

### 4.2 `object` group

```markdown
## object — generic catalog tools

Generic catalog operations for any XML tag the catalog knows about
(IPHost, Services, Zone, Interface, Gateway, FirewallRule, NATRule, plus
the typed groups). Items are typed structs when the catalog has a
parser, otherwise `map[string]any`.

| Tool | Purpose |
|---|---|
| `object_list` | All records of a tag (with optional Field:Criteria:Value filter) |
| `object_get` | Single record by name |
| `object_search` | Name-substring filter (client-side; pulls all then filters) |
| `object_usage` | Object's *Statistics tag |

**When to use**
- The tag has no first-class command group (e.g. Zone, FQDNHost,
  IPHostGroup) → use these.
- You want catalog metadata about a tag → use `object_schema` (NOT in
  this group; it's exposed only via cli for now).

**Gotchas**
- `object_search` pulls the entire list and filters client-side. On
  large firewalls this is expensive — prefer `object_list` with a
  `filter` argument when possible.
- The `tag` argument accepts both canonical names (`IPHost`) and
  aliases (`host-ip`). The catalog resolves either.
- `object_usage` requires the tag's catalog entry to declare a
  `usageTag`. If the entry doesn't have one (e.g. FirewallRule), the
  call returns an error.

**Example**
` ` `yaml
object_list:
  tag: Zone
  filter: "Type:=:LAN"
` ` `
```

### 4.3 `raw` group

```markdown
## raw — escape hatch

| Tool | Purpose |
|---|---|
| `raw_get` | Issue `<Get><tag></tag></Get>` for any XML tag, including ones without a catalog entry |

**When to use**
- The catalog doesn't know about the tag the user wants to inspect.
- You're debugging a discrepancy between catalog-typed output and the
  raw API response.

**Gotchas**
- `raw_get` is read-only. Mutating raw envelopes (`raw request --yes`)
  are NOT exposed as MCP tools — Phase 6 territory.
- Output is the re-encoded XML fragment per record. Less ergonomic
  than typed output; prefer `object_list` for cataloged tags.

**Example**
` ` `yaml
raw_get:
  xmlTag: VPNIPSecPolicy
` ` `
```

### 4.4 `host_ip` group

```markdown
## host_ip — IPHost objects

Typed surface for IP host objects (single addresses, networks, ranges).

| Tool | Purpose |
|---|---|
| `host_ip_list` | All IPHost records (with derived CIDR + kind) |
| `host_ip_show` | One IPHost by name |
| `host_ip_search` | Multi-field substring across Name, IPAddress, Subnet |
| `host_ip_usage` | IPHostStatistics + optional reference graph |

**When to use**
- The user wants to inspect IP-level objects (single host, network, range).
- The user asks "where is X used?" → `host_ip_usage` with `with_references: true`.
- The user gives an IP and asks what host(s) match → `host_ip_search`.

**Gotchas**
- `derived.cidr` is only populated for `kind == "network"`. For `kind
  == "host"`, only `IPAddress` is set.
- `with_references: true` adds 3 round-trips (IPHostGroup,
  FirewallRule, NATRule). Per-referrer failures appear in
  `referenceErrors`; partial success is normal — report what came back
  honestly.
- `host_ip_search` pulls the entire IPHost list and filters
  client-side; on large firewalls (~1000+ records) this is expensive.
  Prefer `host_ip_list` with a `filter` argument when possible.

**Example**
` ` `yaml
host_ip_usage:
  name: LAN-network
  with_references: true
` ` `
```

### 4.5 `service` group

Same shape as host_ip. 4 tools (list/show/search/usage). Gotchas:
- `derived.protocol` and `derived.portRange` are synthesized; the raw `ServiceDetails` field is preserved.
- `service_search` matches Name and the synthesized `derived.portRange` — substring on numeric ports works (e.g. `query: 22` matches SSH).
- `service_usage` with `with_references: true` queries ServiceGroup, FirewallRule, NATRule.

### 4.6 `firewall_rule` group

```markdown
## firewall_rule — firewall rules

| Tool | Purpose |
|---|---|
| `firewall_rule_list` | All firewall rules (untyped maps) |
| `firewall_rule_show` | One firewall rule by name |

**When to use**
- The user wants to audit firewall policy.
- The user names a specific rule and asks for details.

**Gotchas**
- Items are untyped `map[string]any`. The shape varies by Sophos
  firmware version. Phase 6 will define a typed FirewallRule struct
  alongside the mutation surface.
- No `usage` or `search` — rules are leaf objects. Use the cli
  `--filter` argument or post-process the JSON.
- Array fields like `SourceZones` and `Sources` are arrays in JSON;
  the cli's table mode comma-joins them, but JSON output preserves
  the array shape.

**Example**
` ` `yaml
firewall_rule_list:
  filter: "Status:=:Enable"
` ` `
```

### 4.7 `nat_rule` group

Same shape as firewall_rule. 2 tools (list/show), untyped maps, no usage. One bullet about `OriginalSourceNetworks` array shape.

## 5. `examples.md` edits

Existing 6 sections kept (Authentication, Inspect IP host objects, Inspect services, Inspect firewall and NAT rules, Raw API escape hatch, MCP scaffold).

The "MCP scaffold" section is REPLACED by an "MCP server configuration" section (real config snippet).

5 new sections appended:

1. **First-class IP host commands** — bash examples for `host ip list/show/search/usage`. Each example: 1 line command + 1 line "what comes back" comment.
2. **First-class service commands** — same pattern for `service list/show/search/usage`.
3. **First-class firewall and NAT rule commands** — `firewall rule list/show`, `nat rule list/show`.
4. **MCP tool calls** — Q4/B-style YAML snippets for 6 most-used tools: `auth_status`, `host_ip_list`, `host_ip_show {name: ...}`, `host_ip_usage {name: ..., with_references: true}`, `service_list`, `firewall_rule_list`. Each with 1-line "returns" comment.
5. **MCP server configuration** — JSON snippet for the user's MCP host config showing `--profile` flag.

The existing "Inspect firewall and NAT rules (generic, no typed parser yet)" section title gets the parenthetical truncated to "(generic)" since typed parsers aren't a stale promise anymore.

## 6. `safety-checklist.md` edits

Item #3 rewrite:

> **3.** ☐ For any data-changing intent: stop. Phase 5 ships read-only operations only. Mutating workflows arrive in Phase 6. Until then, `unsupported_in_phase` errors mean stop and tell the user.

New item #11:

> **11.** ☐ When MCP tools are configured: the same audit summary applies. Don't omit it just because the user is talking to you through Claude Desktop / Claude Code. The agent skill is the contract regardless of transport.

New item #12:

> **12.** ☐ When `--with-references` (CLI) or `with_references: true` (MCP) returns partial data with a `referenceErrors` block, report the partial state honestly. Do NOT claim full reference coverage when some referrer queries failed.

## 7. `audit-template.md` edits

Replace the existing single example with two:

```markdown
Example (CLI first-class command):
` ` `
Operation: sophosfw host ip search LAN-network --json
Profile:   home
Mode:      read-write
Mutating:  no
Result:    ok
Affected:  1 IPHost object(s)
Names:     LAN-network
Notes:     none
` ` `

Example (MCP tool with reference graph):
` ` `
Operation: host_ip_usage {name: LAN-network, with_references: true}
Profile:   home
Mode:      read-write
Mutating:  no
Result:    ok
Affected:  1 IPHostStatistics record + 3 referrer types scanned
Names:     LAN-network; LAN-grp (IPHostGroup); LAN-To-WAN (FirewallRule)
Notes:     FirewallRule reference query partially succeeded; NATRule
           query failed with permission_denied (referenceErrors set)
` ` `
```

Add one explanatory paragraph after the examples:

```markdown
When `with_references` is used, the Names field can list both the
primary object name AND any referrer names found (separated by
semicolons, with the referrer type in parentheses). When
`referenceErrors` is present in the response, mention which referrer
types failed and why in the Notes field — partial coverage must be
reported honestly.
```

## 8. Skill-doctor expansion

### 8.1 `internal/cli/skill.go` — `requiredCommandsInExamples`

Append 5 new strings:

```go
var requiredCommandsInExamples = []string{
    "sophosfw auth status",
    "sophosfw object list",
    "sophosfw raw get",
    "sophosfw mcp serve",
    "sophosfw host ip list",     // Phase 3
    "sophosfw service list",     // Phase 3
    "sophosfw firewall rule list", // Phase 3
    "sophosfw nat rule list",    // Phase 3
    "host_ip_list",              // Phase 4 MCP sentinel
}
```

The `host_ip_list` entry is intentionally NOT prefixed with `sophosfw` — it's an MCP tool name, not a CLI command.

### 8.2 `internal/cli/skill.go` — `runSkillDoctor`

Change to read both `examples.md` AND `mcp-tools.md`, concat, then check each required string against the combined haystack. Treat missing `mcp-tools.md` as an error:

```go
func runSkillDoctor(out io.Writer, skillDir string) error {
    if _, err := os.Stat(skillDir); err != nil {
        return fmt.Errorf("skill directory missing: %s", skillDir)
    }
    if _, err := os.Stat(filepath.Join(skillDir, "SKILL.md")); err != nil {
        return fmt.Errorf("SKILL.md missing in %s", skillDir)
    }

    examplesBody, err := os.ReadFile(filepath.Join(skillDir, "examples.md"))
    if err != nil {
        return fmt.Errorf("examples.md missing in %s: %w", skillDir, err)
    }
    mcpToolsBody, err := os.ReadFile(filepath.Join(skillDir, "mcp-tools.md"))
    if err != nil {
        return fmt.Errorf("mcp-tools.md missing in %s: %w", skillDir, err)
    }

    haystack := string(examplesBody) + "\n" + string(mcpToolsBody)

    missing := []string{}
    for _, req := range requiredCommandsInExamples {
        if !strings.Contains(haystack, req) {
            missing = append(missing, req)
        }
    }
    if len(missing) > 0 {
        return fmt.Errorf("required surface not documented in examples.md or mcp-tools.md: %s", strings.Join(missing, ", "))
    }
    fmt.Fprintln(out, "skill ok")
    return nil
}
```

The `out` parameter type changes from the inline interface to `io.Writer` (small cleanup; T31 reviewer flagged the inline interface as a NON-BLOCKING concern).

### 8.3 `internal/cli/skill_test.go`

Update existing tests to write a stub `mcp-tools.md` so they keep passing. Add 2 new tests:

- `TestSkillDoctor_FindsRequiredInMcpTools`: stub fake skill dir with `mcp-tools.md` containing `host_ip_list` and `examples.md` containing the 8 cli strings; assert doctor passes.
- `TestSkillDoctor_FailsWhenMcpToolsMissing`: stub fake skill dir with `examples.md` but no `mcp-tools.md`; assert doctor errors on missing file.

## 9. Testing strategy

The skill content (markdown files) is not unit-testable beyond the doctor's required-string check. Phase 5's testing surface is:

- **Skill-doctor unit tests** in `internal/cli/skill_test.go`: 5 test functions total (3 existing updated + 2 new). All deterministic, all use `t.TempDir()`.
- **Real-skill validation**: `make skill-doctor` against the live symlinked content. This is the "does the actual canonical skill content satisfy the contract" check, run as part of acceptance (T7).
- **No tests for the markdown content's prose quality**: manual review covers that.

## 10. Acceptance criteria

A Phase 5 implementation is acceptance-passing when:

1. `go fmt ./...`, `go vet ./...`, `go test -race ./...` all clean.
2. The 4 canonical skill files (`SKILL.md`, `examples.md`, `safety-checklist.md`, `audit-template.md`) updated in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` per Sections 3, 5, 6, 7.
3. The new `mcp-tools.md` created at `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md` per Section 4.
4. The project-side symlink at `/Users/ipm/code/sophosfw/.claude/skills/sophos-firewall` resolves to all 5 files (4 existing + 1 new).
5. `make skill-doctor` outputs `skill ok` against the live symlinked skill content.
6. `internal/cli/skill.go` updated per Sections 8.1, 8.2; tests in `internal/cli/skill_test.go` updated per Section 8.3; all skill_test.go tests pass.
7. The sophosfw-repo commits contain ONLY the skill-doctor source/test changes and the docs/api-coverage + docs/roadmap status updates. The skill content edits remain untracked in the skillshare repo for the user to commit there separately (foundation T30 pattern).
8. `docs/api-coverage.md` and `docs/roadmap.md` updated for Phase 5 status.
9. Tagged as `v0.4.0-phase5`.

## 11. Implementation plan task estimate

Roughly 7 tasks for the implementation plan:

- **T1**: SKILL.md edits (canonical file, text-only).
- **T2**: mcp-tools.md (new canonical file, text-only).
- **T3**: examples.md updates (canonical file).
- **T4**: safety-checklist.md + audit-template.md updates (canonical files).
- **T5**: skill-doctor source + test updates (sophosfw repo, single commit).
- **T6**: docs/api-coverage.md + docs/roadmap.md status (sophosfw repo).
- **T7**: acceptance verification + tag v0.4.0-phase5.

T1-T4 are docs-only on canonical files (no go code; no sophosfw-repo commit). T5 is the only one that requires Go changes. T6 is trivial doc nudges. T7 is verification and tag.
