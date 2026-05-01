# sophosfw Phase 5 Implementation Plan — Agent skill completion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the canonical agent skill files at `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` to reflect the Phase 3 first-class commands and Phase 4 MCP tool surface, add forward-looking guidance for Phase 6, and expand `internal/cli/skill.go`'s skill-doctor to validate the new surface.

**Architecture:** Phase 5 changes content in two places. The skill content (4 modified files + 1 new file) lives in the user's separate `ai-tooling/skillshare` repo and is NOT committed in the sophosfw repo (foundation T30 pattern). The skill-doctor source + tests live in the sophosfw repo and ARE committed there. The sophosfw-repo commits include skill-doctor changes, docs/api-coverage + docs/roadmap status updates, and the phase tag.

**Tech Stack:** Markdown (canonical skill content), Go 1.26.2 (skill-doctor source), testify (tests). No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-01-sophosfw-phase5-design.md`](../specs/2026-05-01-sophosfw-phase5-design.md)

**Predecessor:** Phase 4, tagged `v0.3.0-phase4` on `main` (commit `056e6bf`).

---

## Conventions

- **Module:** `github.com/iainmoffat/sophosfw`. Working directory for the sophosfw repo: `/Users/ipm/code/sophosfw`.
- **Canonical skill files** live in `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` (separate repo).
- **No Co-Authored-By trailer** on implementation commits in the sophosfw repo.
- **DO NOT commit changes in the ai-tooling/skillshare repo** — leave them as untracked/uncommitted working-tree changes for the user to commit separately. Foundation T30 set this precedent.
- **Tasks T1-T4** make canonical skill-content changes. They produce NO sophosfw-repo commit. The acceptance check runs `make skill-doctor` against the live symlinked content.
- **Tasks T5-T7** make sophosfw-repo commits.

---

## Task 1: SKILL.md edits

**Files:**
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md` (5 sections rewritten + 1 new section added)

**No sophosfw-repo commit produced by this task.**

- [ ] **Step 1: Read the current SKILL.md to confirm its shape**

```bash
wc -l /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md
```
Expected: ~175 lines.

The file has 19 numbered sections. T1 rewrites 5 of them and inserts 1 new section.

- [ ] **Step 2: Replace the "Read-Only First Rule" section**

Find this block in `SKILL.md`:
```markdown
## Read-Only First Rule

If the user asks for information, prefer:
- `sophosfw object list <tag>` — generic, works for any catalog tag.
- `sophosfw object get <tag> --name <name>` — single record.
- `sophosfw object usage <tag> --name <name>` — where is this object used.
- `sophosfw raw get <tag>` — when the catalog doesn't have what you need.

Do not invoke `sophosfw raw request` unless the user explicitly asks to see
a preview of a hand-authored envelope. Never pass `--yes` — the apply path
is unimplemented and will return `unsupported_in_phase`.
```

Replace with:
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

- [ ] **Step 3: Replace the "MCP Usage Pattern" section**

Find this block:
```markdown
## MCP Usage Pattern

Foundation phase ships `sophosfw mcp serve` as a *stub* — zero tools are
registered. Phase 4 will add the real tool surface (`get_auth_status`,
`list_objects`, `get_object`, `get_object_usage`, `list_ip_hosts`, etc.).

For now, prefer the CLI directly. If the user asks you to use MCP tools,
tell them the MCP scaffold is in place but tools land in Phase 4.
```

Replace with (use real triple-backticks for the JSON code block):
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

(Replace each ` ` ` with three real backticks. The JSON fence should be a real ```json ... ``` block.)

- [ ] **Step 4: Replace the "Common Read-Only Workflows" section**

Find this block:
```markdown
## Common Read-Only Workflows

See `examples.md` for command-by-command patterns. Quick reference:
- Inventory all IP host objects: `sophosfw object list IPHost --json`.
- Search for a host: `sophosfw object get IPHost --filter Name:like:LAN --json`.
- Check object usage: `sophosfw object usage IPHost --name "LAN-network" --json`.
- Test the connection: `sophosfw auth test --json`.
```

Replace with:
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

- [ ] **Step 5: Replace the "Common Change Workflows" section**

Find this block:
```markdown
## Common Change Workflows

**Not implemented in foundation phase.** Phase 6 will land the
`--dry-run`/preview/`--yes`/apply pattern. Until then, if the user wants to
change something, summarize what would need to change and tell them apply
isn't supported yet.
```

Replace with:
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

- [ ] **Step 6: Replace the "Current Limitations (Foundation Phase)" section**

Find this block:
```markdown
## Current Limitations (Foundation Phase)

- No mutating operations — anything that would change the firewall.
- MCP server is a zero-tool stub.
- Only `IPHost` and `Services` have typed parsers; other tags fall through
  to generic map output.
- No draft/snapshot workflows yet.
- No first-class wrappers for `host ip`, `firewall rule`, `nat rule`, etc.
  Use generic `object` commands instead.
```

Replace with:
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

- [ ] **Step 7: Verify the file**

```bash
wc -l /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md
```
Expected: ~210 lines (up from ~175).

Sanity check: all 5 rewrites applied:
```bash
grep -c "Phase 5" /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md
grep -c "host ip list" /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md
grep -c "mcp-tools.md" /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md
grep "Foundation Phase" /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md || echo "no foundation references — good"
```
Expected: ≥3 "Phase 5" matches, ≥2 "host ip list" matches, ≥3 "mcp-tools.md" matches, no "Foundation Phase" matches.

- [ ] **Step 8: NO commit in sophosfw repo for this task**

Foundation T30 established that canonical skill content is committed in the user's `ai-tooling/skillshare` repo separately. Leave the changes as untracked working-tree changes there. The sophosfw repo's `git status` should be clean for this task.

---

## Task 2: Create `mcp-tools.md`

**Files:**
- Create: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md`

**No sophosfw-repo commit produced by this task.**

- [ ] **Step 1: Create the new file**

Create `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md` with the full content below. Use real triple-backticks (` ``` `) where the content shows ` ` ` placeholders.

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

---

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

---

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
- You want to filter by a Sophos-supported field (Name, Status, etc.)
  → `object_list` with `filter: "Field:Criteria:Value"`.

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

---

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

---

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

---

## service — Services objects

Typed surface for service objects (TCP/UDP/IP/ICMP definitions).

| Tool | Purpose |
|---|---|
| `service_list` | All Services records (with derived protocol + portRange) |
| `service_show` | One service by name |
| `service_search` | Substring across Name and synthesized portRange |
| `service_usage` | ServicesStatistics + optional reference graph |

**When to use**
- The user wants to inspect services and their ports.
- The user gives a port and asks which service uses it → `service_search`
  with the port as the query (e.g. `query: "22"` matches SSH).
- "Where is this service used in rules?" → `service_usage` with
  `with_references: true`.

**Gotchas**
- `derived.protocol` and `derived.portRange` are synthesized; the raw
  `ServiceDetails` field is preserved alongside.
- `service_search` matches against Name AND the synthesized
  `derived.portRange`, so numeric port queries work.
- `with_references: true` queries ServiceGroup, FirewallRule, NATRule.
  Same partial-failure semantics as `host_ip_usage`.

**Example**
` ` `yaml
service_usage:
  name: HTTP
  with_references: true
` ` `

---

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

---

## nat_rule — NAT rules

| Tool | Purpose |
|---|---|
| `nat_rule_list` | All NAT rules (untyped maps) |
| `nat_rule_show` | One NAT rule by name |

**When to use**
- The user wants to inspect NAT mappings (linked NAT, source NAT).
- The user names a specific NAT rule and asks for details.

**Gotchas**
- Items are untyped `map[string]any`. Same shape caveat as
  firewall_rule.
- `OriginalSourceNetworks` and similar fields are arrays in JSON.
- No `usage` or `search`.

**Example**
` ` `yaml
nat_rule_list:
  filter: "Status:=:Enable"
` ` `
```

(In the actual file, replace every ` ` ` with three real backticks.)

- [ ] **Step 2: Verify the file**

```bash
wc -l /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md
```
Expected: ~180-210 lines.

Sanity check the 7 group sections are present:
```bash
grep -c "^## " /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md
```
Expected: 7 (one per group).

Sanity check the MCP tool sentinel for the doctor:
```bash
grep -c "host_ip_list" /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/mcp-tools.md
```
Expected: ≥1.

- [ ] **Step 3: Verify the symlink resolves**

```bash
ls -la /Users/ipm/code/sophosfw/.claude/skills/sophos-firewall/mcp-tools.md
cat /Users/ipm/code/sophosfw/.claude/skills/sophos-firewall/mcp-tools.md | head -5
```
Expected: file resolves through the symlink, top 5 lines match the new file's preamble.

- [ ] **Step 4: NO commit in sophosfw repo**

---

## Task 3: examples.md updates

**Files:**
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md`

**No sophosfw-repo commit produced by this task.**

- [ ] **Step 1: Read the current examples.md**

```bash
wc -l /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md
```
Expected: ~55 lines.

- [ ] **Step 2: Rename "Inspect firewall and NAT rules" section title**

Find:
```markdown
## Inspect firewall and NAT rules (generic, no typed parser yet)
```
Replace with:
```markdown
## Inspect firewall and NAT rules (generic)
```

(The "no typed parser yet" parenthetical is stale.)

- [ ] **Step 3: Replace the "MCP scaffold" section**

Find this block:
```markdown
## MCP scaffold

` ` `bash
sophosfw mcp serve
# Prints: "0 tools registered (foundation phase scaffold; Phase 4 will add tools). Catalog has 12 tags loaded."
` ` `
```

Replace with (real triple-backticks):
```markdown
## MCP server configuration

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

Phase 4 ships 21 MCP read-only tools (4 auth + 4 object + 1 raw + 4
host_ip + 4 service + 2 firewall_rule + 2 nat_rule). See `mcp-tools.md`
for the per-group reference.
```

- [ ] **Step 4: Append "First-class IP host commands" section**

At the end of the file, append:

```markdown

## First-class IP host commands

` ` `bash
# All IP hosts with derived CIDR and kind:
sophosfw host ip list --json

# One host by name:
sophosfw host ip show LAN-network --json

# Multi-field substring search (Name, IPAddress, Subnet):
sophosfw host ip search LAN --json

# Stats + reference-graph scan:
sophosfw host ip usage LAN-network --with-references --json
` ` `
```

- [ ] **Step 5: Append "First-class service commands" section**

Append:

```markdown

## First-class service commands

` ` `bash
# All services with derived protocol/portRange:
sophosfw service list --json

# One service by name:
sophosfw service show HTTP --json

# Substring search across Name and portRange:
sophosfw service search 22 --json

# Stats + reference-graph scan:
sophosfw service usage HTTP --with-references --json
` ` `
```

- [ ] **Step 6: Append "First-class firewall and NAT rule commands" section**

Append:

```markdown

## First-class firewall and NAT rule commands

` ` `bash
sophosfw firewall rule list --json
sophosfw firewall rule show "LAN-To-WAN" --json
sophosfw nat rule list --json
sophosfw nat rule show "WAN-Outbound" --json
` ` `
```

- [ ] **Step 7: Append "MCP tool calls" section**

Append:

```markdown

## MCP tool calls

The agent's MCP host renders tool calls as structured invocations. The
shapes below are what the agent thinks in terms of:

` ` `yaml
auth_status: {}
# returns sophosfw.v1.authStatus envelope

host_ip_list: {}
# returns sophosfw.v1.hostIpList envelope (with derived CIDR/kind on each item)

host_ip_show:
  name: LAN-network
# returns sophosfw.v1.hostIp envelope

host_ip_usage:
  name: LAN-network
  with_references: true
# returns sophosfw.v1.hostIpUsage envelope (records + references + optional referenceErrors)

service_list: {}
# returns sophosfw.v1.serviceList envelope

firewall_rule_list: {}
# returns sophosfw.v1.firewallRuleList envelope (untyped map items)
` ` `
```

- [ ] **Step 8: Verify the file**

```bash
wc -l /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md
```
Expected: ~135-150 lines (up from ~55).

Sanity check the 5 new sections appear:
```bash
grep -c "^## " /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md
```
Expected: ≥10 sections (was 6, added 4 new sections + replaced "MCP scaffold" with "MCP server configuration" so net 6+4 = 10).

Required-string sanity check (these must appear for the doctor):
```bash
for s in "sophosfw host ip list" "sophosfw service list" "sophosfw firewall rule list" "sophosfw nat rule list"; do
  grep -q "$s" /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md && echo "OK: $s" || echo "MISSING: $s"
done
```
Expected: all 4 OK.

- [ ] **Step 9: NO commit in sophosfw repo**

---

## Task 4: safety-checklist.md and audit-template.md updates

**Files:**
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/safety-checklist.md`
- Modify: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/audit-template.md`

**No sophosfw-repo commit produced by this task.**

- [ ] **Step 1: Update `safety-checklist.md` item #3**

Find:
```markdown
3. ☐ For any data-changing intent: stop. Foundation phase has no apply path.
```

Replace with:
```markdown
3. ☐ For any data-changing intent: stop. Phase 5 ships read-only operations only. Mutating workflows arrive in Phase 6. Until then, `unsupported_in_phase` errors mean stop and tell the user.
```

- [ ] **Step 2: Append items #11 and #12 to `safety-checklist.md`**

At the end of the file (after the existing item #10), append:

```markdown
11. ☐ When MCP tools are configured: the same audit summary applies. Don't omit it just because the user is talking to you through Claude Desktop / Claude Code. The agent skill is the contract regardless of transport.
12. ☐ When `--with-references` (CLI) or `with_references: true` (MCP) returns partial data with a `referenceErrors` block, report the partial state honestly. Do NOT claim full reference coverage when some referrer queries failed.
```

- [ ] **Step 3: Verify safety-checklist.md**

```bash
wc -l /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/safety-checklist.md
grep -c "^[0-9]\+\." /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/safety-checklist.md
```
Expected: ~17-19 lines, 12 numbered items.

- [ ] **Step 4: Update `audit-template.md` — replace single example with two**

Find this entire block:
```markdown
Example:
` ` `
Operation: sophosfw object list IPHost --filter Name:like:LAN
Profile:   home
Mode:      read-write
Mutating:  no
Result:    ok
Affected:  3 IPHost object(s)
Names:     LAN-network, LAN-DHCP-pool, LAN-printers
Notes:     none
` ` `
```

Replace with (real triple-backticks):
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

When `with_references` is used, the Names field can list both the
primary object name AND any referrer names found (separated by
semicolons, with the referrer type in parentheses). When
`referenceErrors` is present in the response, mention which referrer
types failed and why in the Notes field — partial coverage must be
reported honestly.
```

- [ ] **Step 5: Verify audit-template.md**

```bash
wc -l /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/audit-template.md
grep -c "^Example" /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/audit-template.md
```
Expected: ~45-55 lines, 2 Example sections.

- [ ] **Step 6: NO commit in sophosfw repo**

---

## Task 5: skill-doctor source + tests

**Files:**
- Modify: `/Users/ipm/code/sophosfw/internal/cli/skill.go`
- Modify: `/Users/ipm/code/sophosfw/internal/cli/skill_test.go`

**This task DOES produce a sophosfw-repo commit.**

- [ ] **Step 1: Read the current skill.go to confirm shape**

```bash
cat /Users/ipm/code/sophosfw/internal/cli/skill.go
```

Expected: ~70 lines. The current `requiredCommandsInExamples` has 4 entries; the current `runSkillDoctor` reads only `examples.md`; its `out` parameter is an inline interface.

- [ ] **Step 2: Update `requiredCommandsInExamples` and `runSkillDoctor`**

Replace the entire current contents of `internal/cli/skill.go` with:

```go
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var requiredCommandsInExamples = []string{
	"sophosfw auth status",
	"sophosfw object list",
	"sophosfw raw get",
	"sophosfw mcp serve",
	"sophosfw host ip list",      // Phase 3
	"sophosfw service list",      // Phase 3
	"sophosfw firewall rule list", // Phase 3
	"sophosfw nat rule list",     // Phase 3
	"host_ip_list",               // Phase 4 MCP sentinel; if this is documented, the rest of the MCP surface is too
}

func newSkillCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "skill", Short: "Agent-skill maintenance helpers"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "path",
			Short: "Print the absolute path to the installed agent skill",
			RunE: func(cmd *cobra.Command, _ []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), d.SkillDir)
				return nil
			},
		},
		&cobra.Command{
			Use:   "doctor",
			Short: "Validate that the agent skill is in sync with the implementation",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runSkillDoctor(cmd.OutOrStdout(), d.SkillDir)
			},
		},
	)
	return cmd
}

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

Changes from the current file:
- `requiredCommandsInExamples` grows from 4 entries to 9.
- `runSkillDoctor` now reads `mcp-tools.md` as well; missing file → error.
- `out` parameter type changes from `interface{ Write([]byte) (int, error) }` to `io.Writer`. Imports `"io"`.
- Error message updated to mention both files.

- [ ] **Step 3: Update existing tests in `skill_test.go`**

Read the current test file first to see the existing tests:
```bash
cat /Users/ipm/code/sophosfw/internal/cli/skill_test.go
```

The existing 3 tests are: `TestSkillDoctor_PassesWhenSkillExists`, `TestSkillDoctor_FailsWhenSkillMissing`, `TestSkillDoctor_FailsIfRequiredCommandMissingFromExamples`. Phase 5 needs to:
1. Update `TestSkillDoctor_PassesWhenSkillExists` so its synthetic skill includes `mcp-tools.md` AND mentions all 9 required strings.
2. Add `TestSkillDoctor_FindsRequiredInMcpTools`.
3. Add `TestSkillDoctor_FailsWhenMcpToolsMissing`.
4. Update `TestSkillDoctor_FailsIfRequiredCommandMissingFromExamples` so its synthetic skill includes `mcp-tools.md` (so it doesn't fail for the wrong reason).

Replace the entire current contents of `internal/cli/skill_test.go` with:

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkillDoctor_PassesWhenSkillExists(t *testing.T) {
	// Set up a fake project root with a fake skill that has all 9 required
	// strings split across examples.md and mcp-tools.md.
	dir := t.TempDir()
	skillDir := filepath.Join(dir, ".claude", "skills", "sophos-firewall")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"),
		[]byte(`# Skill\n\nReferences sophosfw cli + MCP.`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status
sophosfw object list IPHost
sophosfw raw get IPHost
sophosfw mcp serve
sophosfw host ip list
sophosfw service list
sophosfw firewall rule list
sophosfw nat rule list`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "mcp-tools.md"),
		[]byte(`# MCP Tools\n\nIncludes host_ip_list and other MCP tools.`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.NoError(t, root.Execute())
}

func TestSkillDoctor_FailsWhenSkillMissing(t *testing.T) {
	d, _ := newRootForTest(t)
	d.SkillDir = filepath.Join(t.TempDir(), "absent")
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}

func TestSkillDoctor_FailsIfRequiredCommandMissingFromExamples(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`x`), 0o600))
	// examples.md has only one of the required cli strings; mcp-tools.md
	// is present but has no required strings either.
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "mcp-tools.md"),
		[]byte(`# MCP Tools\n`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}

func TestSkillDoctor_FindsRequiredInMcpTools(t *testing.T) {
	// host_ip_list lives in mcp-tools.md, NOT examples.md. The other 8
	// required strings live in examples.md. Doctor must concatenate
	// both files and find all 9.
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`x`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status
sophosfw object list IPHost
sophosfw raw get IPHost
sophosfw mcp serve
sophosfw host ip list
sophosfw service list
sophosfw firewall rule list
sophosfw nat rule list`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "mcp-tools.md"),
		[]byte(`# MCP Tools

The host_ip_list tool lists IPHost records.`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.NoError(t, root.Execute())
}

func TestSkillDoctor_FailsWhenMcpToolsMissing(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`x`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status
sophosfw object list IPHost
sophosfw raw get IPHost
sophosfw mcp serve
sophosfw host ip list
sophosfw service list
sophosfw firewall rule list
sophosfw nat rule list
host_ip_list`), 0o600))
	// mcp-tools.md intentionally NOT created.

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "mcp-tools.md")
}
```

- [ ] **Step 4: Run the tests**

```bash
go test ./internal/cli -run TestSkillDoctor -v
```
Expected: 5 tests PASS (the 3 existing-but-updated + 2 new).

- [ ] **Step 5: Run the full test suite**

```bash
go test ./... -count=1
```
Expected: PASS across all packages.

- [ ] **Step 6: Run `make skill-doctor` against the LIVE skill**

This is the moment-of-truth check that the canonical skill content (modified in T1-T4) actually satisfies the new doctor's requirements:

```bash
make skill-doctor
```
Expected: `skill ok`.

If this fails with "required surface not documented", trace the failing string back to T1-T4 and fix the relevant skill file. The doctor checks `examples.md` AND `mcp-tools.md` together; missing `host ip list` would point at examples.md, missing `host_ip_list` at mcp-tools.md.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/skill.go internal/cli/skill_test.go
git commit -m "feat(cli): expand skill doctor for Phase 3 + Phase 4 surface"
```

Verify no Co-Authored-By trailer:
```bash
git log HEAD -1 --pretty=full | grep -i co-auth || echo "no Co-Authored-By trailer"
```
Expected: "no Co-Authored-By trailer".

---

## Task 6: docs/api-coverage.md and docs/roadmap.md status

**Files:**
- Modify: `/Users/ipm/code/sophosfw/docs/roadmap.md`

**This task DOES produce a sophosfw-repo commit. `api-coverage.md` doesn't need any change for Phase 5 (no new API surface).**

- [ ] **Step 1: Update `docs/roadmap.md` Status section**

Find:
```markdown
- Phase 4 — MCP read-only server (complete; v0.3.0-phase4)
- Phase 5 — Agent skill completion (mutating workflows, finalized examples)
```

Replace with:
```markdown
- Phase 4 — MCP read-only server (complete; v0.3.0-phase4)
- Phase 5 — Agent skill completion (complete; v0.4.0-phase5)
```

(Phases 6-7 unchanged.)

- [ ] **Step 2: Sanity check**

```bash
go test ./... -count=1
make build
make skill-doctor
```
Expected: tests pass, build succeeds, skill-doctor green.

- [ ] **Step 3: Commit**

```bash
git add docs/roadmap.md
git commit -m "docs: roadmap Phase 5 complete"
```

Verify no Co-Authored-By:
```bash
git log HEAD -1 --pretty=full | grep -i co-auth || echo "no Co-Authored-By trailer"
```

---

## Task 7: Acceptance verification + tag

**Files:** none new — runs the Phase 5 acceptance checklist.

- [ ] **Step 1: Run the full test suite with race detector**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```
Expected: PASS, no fmt drift.

- [ ] **Step 2: Build and run skill-doctor against live skill**

```bash
make build
make skill-doctor
```
Expected: build succeeds; `skill ok`.

- [ ] **Step 3: Verify the live skill has the expected files**

```bash
ls -la /Users/ipm/code/sophosfw/.claude/skills/sophos-firewall/
```
Expected: 5 markdown files visible through the symlink: `SKILL.md`, `examples.md`, `safety-checklist.md`, `api-patterns.md`, `audit-template.md`, `mcp-tools.md`.

```bash
grep -c "Phase 5" /Users/ipm/code/sophosfw/.claude/skills/sophos-firewall/SKILL.md
grep -c "host_ip_list" /Users/ipm/code/sophosfw/.claude/skills/sophos-firewall/mcp-tools.md
```
Expected: ≥3 "Phase 5" hits in SKILL.md, ≥1 "host_ip_list" in mcp-tools.md.

- [ ] **Step 4: Smoke test the cli still works end-to-end**

```bash
TMPHOME=$(mktemp -d) XDG_CONFIG_HOME=$TMPHOME ./bin/sophosfw --help 2>&1 | head -20
TMPHOME=$(mktemp -d) XDG_CONFIG_HOME=$TMPHOME ./bin/sophosfw skill path
```
Expected: help output includes auth/host/service/firewall/nat/object/raw/mcp/skill/version commands; `skill path` prints `.claude/skills/sophos-firewall`.

- [ ] **Step 5: Commit any fmt-induced or smoke-test-induced changes**

```bash
git status
# If clean, skip to Step 6.
git add -A
git commit -m "fix: phase 5 acceptance pass adjustments"
```

- [ ] **Step 6: Tag the milestone**

```bash
git tag -a v0.4.0-phase5 -m "Phase 5 complete (agent skill completion)"
git tag --list | grep -E "(foundation|phase3|phase4|phase5)"
```
Expected: all four tags listed.

- [ ] **Step 7: Push to GitHub**

```bash
git push origin main
git push origin v0.4.0-phase5
```

- [ ] **Step 8: Final sanity**

```bash
git log --oneline -10
```
Expected: linear history with the Phase 5 commits + Phase 4 + Phase 3 + foundation below.

---

## End of plan

This concludes Phase 5. Next is Phase 6 (safe mutations). Each future phase gets its own brainstorm → spec → plan → implementation cycle.

---

## Self-review checklist

- ✅ **Spec coverage:** every spec section maps to at least one task. Section 3 (SKILL.md edits) → T1. Section 4 (mcp-tools.md) → T2. Section 5 (examples.md) → T3. Sections 6-7 (safety-checklist + audit-template) → T4. Section 8 (skill-doctor) → T5. Section 10 (acceptance criteria) → T7. Docs updates → T6.
- ✅ **No placeholders.** Every step has actual content. Markdown rewrites have full before/after blocks. Go code is shown verbatim.
- ✅ **Type consistency.** `requiredCommandsInExamples` declared in T5 with 9 entries; tests in T5 use those exact strings.
- ✅ **No Co-Authored-By guard.** T5 step 7 and T6 step 3 each verify the absence of the trailer. Foundation/Phase 3/Phase 4 had recurring issues with implementer subagents adding it; the verification step catches it before next task starts.
- ⚠️ **Triple-backtick escaping.** Several Step blocks use ` ` ` (with spaces) as a stand-in for triple-backticks because they appear inside code fences. The implementer must replace each ` ` ` with three real backticks when writing the actual file. T1 step 3, T2 step 1, T3 step 3-7, T4 step 4 all need this attention.
- ✅ **Acceptance criteria mapping.** All 9 acceptance criteria from spec section 10 are verified by T7 steps.
