# sophosfw roadmap

## Status
- Phase 0 — Research and design (complete)
- Phase 1 — Foundation (complete; v0.1.0-foundation)
- Phase 2 — Generic API coverage (complete; covered by foundation)
- Phase 3 — First-class read-only commands (complete; v0.2.0-phase3)
- Phase 4 — MCP read-only server (complete; v0.3.0-phase4)
- Phase 5 — Agent skill completion (complete; v0.4.0-phase5)
- Phase 6 — Safe mutations (complete; v0.5.0-phase6)
- Phase 7 — FirewallRule draft workflow (complete; v0.6.0-phase7)
- Phase 8 — NATRule draft workflow (complete; v0.7.0-phase8)
- Phase 9 — Firewall + NAT rule create workflows (complete; v0.8.0-phase9)
- Phase 10 — MCP-native firewall and NAT rule mutating tools (complete; v0.9.0-phase10)
- Phase 11 — CI/CD + release polish (complete; v0.9.1)
- Phase 12 — Mutating coverage breadth (host groups, FQDN, MAC, services) (complete; v0.10.0)
- Phase 13 — Backup + drift detection (complete; v0.11.0)
- Phase 14 — Multi-firewall fan-out (complete; v0.12.0)

## Phase 13.x — Drift follow-ups (deferred)

Real-world finding from Phase 13 integration testing: Sophos firewalls
auto-populate `FQDNHost` cache entries from DNS resolution, so routine
`sophosfw drift` checks may report cache entries as added between
snapshots taken minutes apart. Three follow-ups under consideration
(none blocking):

- **Documentation.** Add a paragraph to `sophosfw drift --help` and to
  the README explaining the FQDNHost cache behavior and recommending
  `--exclude FQDNHost` for routine config-only drift checks.
- **`--exclude-dynamic` shortcut flag.** Convenience flag that maps to
  a maintained list of known-dynamic types (initially `FQDNHost`).
  Opt-in; preserves the safety default of "show everything".
- **Per-type exit-code suppression.** Optional flag (e.g.
  `--strict-types FirewallRule,NATRule,IPHost`) that exits 1 only when
  changes appear in those types. Lets cron exit 0 unless real config
  drifted. More aggressive — defer until real users ask.

Tracking decision: surface the behavior loudly via documentation, then
ship the `--exclude-dynamic` shortcut. Skip per-type exit-code
suppression unless real cron usage shows the noise.

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
