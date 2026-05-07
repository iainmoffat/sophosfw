# sophosfw — Phase 3 Design (First-class read-only commands)

**Status:** approved 2026-05-01. Implementation plan to follow.

**Predecessor:** Foundation (Phases 0-2), tagged `v0.1.0-foundation`. Spec at `docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md`.

## 1. Goal and scope

### 1.1 Goal

Phase 3 adds ergonomic, type-aware wrappers over the foundation's catalog-driven generic `object` commands for the highest-traffic Sophos object types: IPHost, Service, FirewallRule, NATRule. The wrappers earn the "first-class" label by:

1. Verb-noun command names that match how operators talk (`host ip show LAN-network` vs. `object get IPHost --name LAN-network`).
2. JSON output enriched with sophosfw-derived fields under a clear `derived` marker (CIDR, normalized kind, port-range summaries).
3. Multi-field client-side `search` for the rule-of-thumb "find anything called X".
4. Optional `--with-references` flag on usage queries that joins primary stats with a reference-graph scan ("where is this object used?") in a single command.
5. Catalog-defined table columns plus a `--columns` override flag for ad-hoc views.

### 1.2 In scope

- Four first-class command groups, parented under new top-level cobra commands:
  - `host ip` (list / show / search / usage)
  - `service` (list / show / search / usage)
  - `firewall rule` (list / show)
  - `nat rule` (list / show)
- Three new typed parsers in the catalog: `FQDNHost`, `MACHost`, `Zone`. All flat records.
- Six new catalog YAML entries: three typed (FQDNHost, MACHost, Zone) and three generic (FirewallRule, NATRule, ServiceGroup).
- Four new svc files: `internal/svc/hostip.go`, `service.go`, `firewallrule.go`, `natrule.go`. Each composes the foundation's `*ObjectSvc`.
- Four new cli files mirroring the svc ones.
- One reference-graph utility: `internal/svc/references.go` with a static referrer map and a substring-match scanner.
- Derived-field enrichment for IPHost (`derived.cidr`, `derived.kind`) and Service (`derived.protocol`, `derived.portRange`). Implemented in svc; called from cli before JSON emission.
- `--columns` flag on every new `list` command, plus a backport to the foundation's generic `object list`.
- `--with-references` flag on `host ip usage` and `service usage` only. Lenient failure mode: per-referrer errors recorded in a `referenceErrors` JSON block; exit code 0 unless the primary stats query fails.
- Multi-field client-side `search` for `host ip` and `service`. Substring match, case-insensitive.
- Fixture XML responses for FQDNHost, MACHost, Zone, FirewallRule (3 records), NATRule (2 records).
- Tests at the cli + svc layers using fakes for behavior, fixtures for parser correctness.
- Integration-tagged round-trip tests for each new typed wrapper.

### 1.3 Out of scope (deferred to later phases)

- IP/CIDR-aware `host ip search --ip <addr>`. Useful but adds client-side address parsing and CIDR-containment logic; cleanly separable. Explicitly noted as a Phase-3 follow-on enhancement, not a blocker for shipping Phase 3.
- Typed Go structs for FirewallRule and NATRule. Their structure is non-trivial (nested arrays for sources/destinations/services, schedule references, action/log fields with firmware-version drift) and locking in a typed shape before mutations need it would mean guessing. Phase 6 will define them when we know what mutating workflows actually need.
- First-class `host fqdn`, `host mac`, `service group`, `host group`, etc. commands. The corresponding catalog entries exist in Phase 3 (so `--with-references` can scan them and so users can hit them via generic `object`), but no first-class verb-noun surface.
- VPN, schedule, interface, certificate as `--with-references` referrer targets. The Phase-3 referrer map covers groups + rules; other referrer types are documented as future map additions.
- Mutating verbs anywhere (Phase 6).
- MCP tool surface for the new typed commands (Phase 4 lands the full read-only MCP suite).
- Updates to the agent skill `examples.md`, `safety-checklist.md`, etc. (Phase 5).
- Snapshot / draft / diff workflows (Phase 7).

### 1.4 Deliverable

Phase 3 ships as `v0.2.0-phase3` on `main`. Acceptance criteria mirror the foundation pattern: `go fmt ./... && go vet ./... && go test -race ./...` clean, `make build` produces a binary that exposes the new commands in `--help`, manual smoke commands return well-formed envelopes against a stub or real firewall, and `make skill-doctor` still passes (the agent skill update for Phase 3 commands lands in Phase 5; doctor's required-commands list is unchanged).

## 2. Architecture

### 2.1 Dependency direction

```
cli/hostip.go ──┐
cli/service.go ─┤
cli/firewallrule.go ┤  (cobra commands; thin)
cli/natrule.go ─┘
       │
       ▼
svc/hostip.go ──┐
svc/service.go ─┤
svc/firewallrule.go ┤  (typed wrappers; compose ObjectSvc)
svc/natrule.go ─┘
       │
       ▼
svc.ObjectSvc      (foundation; generic catalog-driven I/O)
       │
       ▼
sophos.Client + catalog.Catalog
```

Each typed-wrapper service holds an `*ObjectSvc` (composition, not inheritance) and dispatches to it. The wrapper's responsibilities are:

1. **Input narrowing** — typed function arguments instead of `tagOrAlias string`.
2. **Client-side filtering** — the multi-field `Search` operations.
3. **Enrichment** — adding `derived` fields to JSON items.
4. **Reference-graph queries** — `--with-references` is implemented in `references.go` and called from `Usage`.

The foundation's `ObjectSvc` does all I/O. The wrappers never construct envelopes or call the HTTP client directly.

### 2.2 Package layout (new files)

```
internal/
├── catalog/
│   ├── fqdnhost.go              # FQDNHost struct + parser
│   ├── fqdnhost_test.go
│   ├── machost.go
│   ├── machost_test.go
│   ├── zone.go
│   ├── zone_test.go
│   ├── objects.yaml             # MODIFIED: 6 new entries
│   └── register.go              # MODIFIED: 3 new RegisterParser calls
├── svc/
│   ├── hostip.go                # HostIPSvc + HostIP + HostIPDerived + HostIPList + HostIPUsage
│   ├── hostip_test.go
│   ├── service.go               # ServiceSvc + Service + ServiceDerived + ServiceList + ServiceUsage
│   ├── service_test.go
│   ├── firewallrule.go          # FirewallRuleSvc + FirewallRuleList (untyped items)
│   ├── firewallrule_test.go
│   ├── natrule.go               # NATRuleSvc + NATRuleList (untyped items)
│   ├── natrule_test.go
│   ├── references.go            # referenceTargets map + FindReferences + References struct
│   └── references_test.go
├── cli/
│   ├── hostip.go                # newHostCmd + host ip {list,show,search,usage}
│   ├── hostip_test.go
│   ├── service.go               # newServiceCmd + service {list,show,search,usage}
│   ├── service_test.go
│   ├── firewallrule.go          # newFirewallCmd + firewall rule {list,show}
│   ├── firewallrule_test.go
│   ├── natrule.go               # newNATCmd + nat rule {list,show}
│   ├── natrule_test.go
│   ├── columns.go               # resolveColumns helper used by all list commands
│   ├── object.go                # MODIFIED: --columns flag added to list, uses resolveColumns
│   ├── object_test.go           # MODIFIED: --columns flag test
│   └── root.go                  # MODIFIED: register 4 new commands
testdata/sophos/responses/
├── fqdnhost_get_one.xml
├── machost_get_one.xml
├── zone_get_one.xml
├── firewallrule_list_3.xml
└── natrule_list_2.xml
```

Total: 23 new files, 4 modified. Filename casing convention follows the foundation's lowercase-with-no-separator style (`hostip.go` not `host_ip.go`, matching the existing `iphost.go`).

### 2.3 Data flow: a representative call

`sophosfw host ip usage LAN-network --with-references --json --profile home`

1. Cobra parses args: subcommand path `host ip usage`, positional name `LAN-network`, `--with-references=true`, persistent `--json --profile home`.
2. `cli/hostip.go newHostIpUsageCmd` builds `s := &svc.HostIPSvc{Inner: &svc.ObjectSvc{...}}` from `RootDeps`.
3. `s.Usage(ctx, "home", "LAN-network", true)` runs:
   - Calls `s.Inner.Usage(ctx, "home", "IPHost", "LAN-network")` → returns `*ObjectUsage`.
   - Calls `svc.FindReferences(ctx, s.Inner, "home", "IPHost", "LAN-network")`:
     - Looks up `referenceTargets["IPHost"]` → `[]string{"IPHostGroup", "FirewallRule", "NATRule"}`.
     - For each referrer tag, calls `s.Inner.List(ctx, "home", tag, nil)`. Failures captured per-tag, never returned up.
     - For each successful list, scans every record's JSON for the string `"LAN-network"` appearing as an array element or scalar value.
     - Returns `*References{Refs: ..., Errors: ...}`.
   - Returns `*HostIPUsage{Profile, Name, Records, References}`.
4. `cli/hostip.go renderHostIpUsage` emits JSON envelope `sophosfw.v1.hostIpUsage`:
   ```json
   {
     "schema": "sophosfw.v1.hostIpUsage",
     "profile": "home",
     "name": "LAN-network",
     "records": [...],
     "references": {
       "IPHostGroup": ["LAN-group"],
       "FirewallRule": ["LAN-To-WAN", "LAN-Outbound"],
       "NATRule": []
     }
   }
   ```
   If the `FirewallRule` query had failed:
   ```json
   {
     ...
     "references": {
       "IPHostGroup": ["LAN-group"],
       "FirewallRule": null,
       "NATRule": []
     },
     "referenceErrors": {
       "FirewallRule": "permission_denied: sophos: permission denied"
     }
   }
   ```
5. Exit code 0 because the primary stats query succeeded.

## 3. Catalog changes

### 3.1 Three new typed entries (objects.yaml)

```yaml
- tag: FQDNHost
  aliases: [fqdn-host, host-fqdn]
  description: FQDN host objects (DNS-name targets).
  columns: [Name, FQDN, IPFamily]
  filterable: [Name, FQDN, IPFamily]
  usageTag: FQDNHostStatistics
  typedParser: FQDNHost

- tag: MACHost
  aliases: [mac-host, host-mac]
  description: MAC address host objects.
  columns: [Name, Type, MACAddress]
  filterable: [Name, Type, MACAddress]
  usageTag: MACHostStatistics
  typedParser: MACHost

- tag: Zone
  aliases: [zone]
  description: Network zones (LAN, WAN, DMZ, custom).
  columns: [Name, Type, Description]
  filterable: [Name, Type]
  typedParser: Zone
```

### 3.2 Three new generic entries (objects.yaml)

```yaml
- tag: FirewallRule
  aliases: [firewall-rule]
  description: Firewall rules.
  columns: [Name, Action, SourceZones, DestinationZones, Status]
  filterable: [Name, Action, Status]

- tag: NATRule
  aliases: [nat-rule]
  description: NAT rules.
  columns: [Name, OriginalSourceNetworks, TranslatedSource, Status]
  filterable: [Name, Status]

- tag: ServiceGroup
  aliases: [service-group]
  description: Service group objects (composed of Services).
  columns: [Name, Description]
  filterable: [Name]
  usageTag: ServiceGroupStatistics
```

`IPHostGroup` and `FQDNHostGroup` already exist in the foundation catalog as generic entries.

### 3.3 Typed parser source files

```go
// internal/catalog/fqdnhost.go
package catalog

import "encoding/json"

type FQDNHost struct {
    Name     string `json:"Name"`
    FQDN     string `json:"FQDN"`
    IPFamily string `json:"IPFamily,omitempty"`
}

func FQDNHostParser(raw json.RawMessage) (any, error) {
    var v FQDNHost
    if err := json.Unmarshal(raw, &v); err != nil {
        return nil, err
    }
    return v, nil
}
```

```go
// internal/catalog/machost.go
package catalog

import "encoding/json"

type MACHost struct {
    Name        string   `json:"Name"`
    Type        string   `json:"Type,omitempty"`
    MACAddress  string   `json:"MACAddress,omitempty"`
    MACAddressList []string `json:"MACAddressList,omitempty"` // for multi-MAC entries
}

func MACHostParser(raw json.RawMessage) (any, error) {
    var v MACHost
    if err := json.Unmarshal(raw, &v); err != nil {
        return nil, err
    }
    return v, nil
}
```

```go
// internal/catalog/zone.go
package catalog

import "encoding/json"

type Zone struct {
    Name        string `json:"Name"`
    Type        string `json:"Type,omitempty"`
    Description string `json:"Description,omitempty"`
}

func ZoneParser(raw json.RawMessage) (any, error) {
    var v Zone
    if err := json.Unmarshal(raw, &v); err != nil {
        return nil, err
    }
    return v, nil
}
```

`internal/catalog/register.go` `NewDefault()` adds three lines:

```go
cat.RegisterParser("FQDNHost", FQDNHostParser)
cat.RegisterParser("MACHost",  MACHostParser)
cat.RegisterParser("Zone",     ZoneParser)
```

(`IPHost` and `Services` parsers are already registered from the foundation.)

## 4. Service layer

### 4.1 HostIPSvc

```go
// internal/svc/hostip.go
package svc

type HostIP struct {
    catalog.IPHost                              // embedded raw record
    Derived HostIPDerived `json:"derived,omitempty"`
}

type HostIPDerived struct {
    CIDR string `json:"cidr,omitempty"`
    Kind string `json:"kind,omitempty"`
}

type HostIPList struct {
    Profile string
    Filter  *sophos.FilterClause
    Count   int
    Items   []HostIP
}

type HostIPUsage struct {
    Profile    string
    Name       string
    Records    []map[string]any
    References *References
}

type HostIPSvc struct {
    Inner *ObjectSvc
}

func (s *HostIPSvc) List(ctx context.Context, profile string, filter *sophos.FilterClause) (*HostIPList, error)
func (s *HostIPSvc) Get(ctx context.Context, profile, name string) (*HostIP, error)
func (s *HostIPSvc) Search(ctx context.Context, profile, query string) (*HostIPList, error)
func (s *HostIPSvc) Usage(ctx context.Context, profile, name string, withRefs bool) (*HostIPUsage, error)
```

`List` calls `Inner.List(ctx, profile, "IPHost", filter)`, then for each item type-asserts to `catalog.IPHost`, wraps in `HostIP`, and calls `enrichHostIP(&item)` to populate `Derived`.

`enrichHostIP` logic (pure, testable in isolation):

```go
var hostKindMap = map[string]string{
    "Network":  "network",
    "IP":       "host",
    "IPRange":  "iprange",
    "IPList":   "list",
}

func enrichHostIP(h *HostIP) {
    if k, ok := hostKindMap[h.HostType]; ok {
        h.Derived.Kind = k
    }
    if h.Derived.Kind == "network" && h.IPAddress != "" && h.Subnet != "" {
        if mask, err := subnetToPrefix(h.Subnet); err == nil {
            h.Derived.CIDR = fmt.Sprintf("%s/%d", h.IPAddress, mask)
        }
    }
}

// subnetToPrefix turns "255.255.255.0" → 24. Pure function. IPv4 only in
// Phase 3; IPv6 prefix is already a number in Sophos so no conversion needed.
func subnetToPrefix(mask string) (int, error) { /* parse + count bits */ }
```

`Search` calls `s.Inner.List(ctx, profile, "IPHost", nil)` then filters client-side:

```go
func matchesHostIP(h HostIP, q string) bool {
    qLower := strings.ToLower(q)
    return strings.Contains(strings.ToLower(h.Name), qLower) ||
           strings.Contains(strings.ToLower(h.IPAddress), qLower) ||
           strings.Contains(strings.ToLower(h.Subnet), qLower)
}
```

`Usage` calls `s.Inner.Usage(ctx, profile, "IPHost", name)` always. If `withRefs`, additionally calls `FindReferences(ctx, s.Inner, profile, "IPHost", name)` and attaches the result.

### 4.2 ServiceSvc

```go
// internal/svc/service.go
type Service struct {
    catalog.Service                             // existing flat fields
    Derived ServiceDerived `json:"derived,omitempty"`
}
type ServiceDerived struct {
    Protocol  string `json:"protocol,omitempty"`
    PortRange string `json:"portRange,omitempty"`
}
```

Same shape as HostIPSvc — `List/Get/Search/Usage` with `--with-references` on `Usage`.

`enrichService` synthesizes `Derived` from `ServiceDetails`:

- `derived.protocol` — single lowercase string for single-protocol services (`"tcp"`), comma-joined for multi-protocol (`"tcp,udp"`). For ICMP/IP types, the protocol name itself.
- `derived.portRange` — collapsed from per-protocol `DestinationPort` arrays. Algorithm:
  1. Collect all destination ports across all protocol entries.
  2. If a port is a range (e.g. `"80-443"`), preserve as-is.
  3. Sort scalars numerically; group contiguous runs into ranges; join non-contiguous with comma.
  4. Examples: `[80]` → `"80"`, `[80, 81, 82]` → `"80-82"`, `[80, 443]` → `"80,443"`, `[80, 81, 443, 444]` → `"80-81,443-444"`.
  5. For ICMP/IP types, `portRange` is omitted.

`matchesService` substring-matches Name and the synthesized `derived.portRange`. For Phase 3, the search index for services is just the synthesized portRange string, not the raw nested structure — keeps it simple and predictable.

### 4.3 FirewallRuleSvc

```go
// internal/svc/firewallrule.go
type FirewallRuleList struct {
    Profile string
    Filter  *sophos.FilterClause
    Count   int
    Items   []map[string]any
}

type FirewallRuleSvc struct {
    Inner *ObjectSvc
}

func (s *FirewallRuleSvc) List(ctx context.Context, profile string, filter *sophos.FilterClause) (*FirewallRuleList, error)
func (s *FirewallRuleSvc) Get(ctx context.Context, profile, name string) (map[string]any, error)
```

No `Search`, no `Usage`, no derived fields. Items are returned as `map[string]any` (the catalog has no typed parser for FirewallRule).

### 4.4 NATRuleSvc

Mirrors `FirewallRuleSvc`. Same minimal surface.

### 4.5 References utility

```go
// internal/svc/references.go
package svc

import (
    "context"
    "encoding/json"
)

// referenceTargets maps a primary tag to the catalog tags that may reference
// it. Order is the order results appear in JSON output. Adding a new referrer
// type later is a one-line change.
var referenceTargets = map[string][]string{
    "IPHost":   {"IPHostGroup", "FirewallRule", "NATRule"},
    "FQDNHost": {"FQDNHostGroup", "FirewallRule"},
    "MACHost":  {"FirewallRule"},
    "Service":  {"ServiceGroup", "FirewallRule", "NATRule"},
    "Zone":     {"FirewallRule"},
}

type References struct {
    Refs   map[string][]string `json:"refs"`
    Errors map[string]string   `json:"errors,omitempty"`
}

// FindReferences scans the listed referrer types for any record that
// contains `name` as a string value. Per-referrer failures are captured in
// References.Errors and never returned as a Go error from this function;
// only the primary `os.Stat`-equivalent failure (no referrers in the map at
// all) is treated as an error.
func FindReferences(ctx context.Context, inner *ObjectSvc, profile, primaryTag, name string) (*References, error)
```

Implementation:

1. Look up `referenceTargets[primaryTag]`. If missing (shouldn't happen for typed wrappers, but defensive), return a `*References` with empty maps and a typed error.
2. For each referrer tag, call `inner.List(ctx, profile, tag, nil)`. On error, populate `Errors[tag]` with the error-kind tag from `cli.ErrorKind` plus the message; continue with the next tag.
3. On success, iterate every item and scan it for `name` matches.
4. Scanning: each item from `inner.List` is either a typed struct or a `map[string]any`. Marshal to JSON, parse to `map[string]any`, recursively walk. A match is a string value (scalar or array element) that equals `name` exactly. Substring matches are NOT counted (avoids false positives where one object name is contained in another).
5. For each matched item, extract its display name from the parsed map's `"Name"` field (string). All catalog tags in `referenceTargets`'s value lists have a top-level `Name` field; any future addition that doesn't would need to provide a different extractor.
6. Append matched names to `Refs[referrerTag]`. If a referrer query succeeded but found zero matches, leave `Refs[referrerTag]` as an empty slice (not nil) so JSON output distinguishes "scanned, found none" (`[]`) from "didn't scan" (key absent or `null`).
7. Return the `*References`.

Item matching is exact-string equality, not substring. The walk is depth-first across maps and arrays; nested object structures are followed.

## 5. CLI surface

### 5.1 Command tree (added to `internal/cli/root.go`)

```go
cat, _ := catalog.NewDefault()
root.AddCommand(newVersionCmd(d))
root.AddCommand(newAuthCmd(d))
root.AddCommand(newObjectCmd(d, cat))
root.AddCommand(newRawCmd(d))
root.AddCommand(newMCPCmd(d, cat))
root.AddCommand(newSkillCmd(d))
root.AddCommand(newHostCmd(d, cat))           // NEW
root.AddCommand(newServiceCmd(d, cat))        // NEW
root.AddCommand(newFirewallCmd(d, cat))       // NEW
root.AddCommand(newNATCmd(d, cat))            // NEW
```

Each `newXCmd` is a parent with its real children:

- `newHostCmd` → `host` parent → adds `newHostIpCmd` → `ip` child → adds list/show/search/usage children.
- `newServiceCmd` → `service` parent → directly adds list/show/search/usage children (no intermediate noun, since `service list` is one level).
- `newFirewallCmd` → `firewall` parent → adds `newFirewallRuleCmd` → `rule` child → adds list/show.
- `newNATCmd` → `nat` parent → adds `newNATRuleCmd` → `rule` child → adds list/show.

### 5.2 Flag inventory per command

All commands inherit persistent flags from root (`--profile`, `--json`, `--timeout`, `--debug`, `--insecure-skip-verify`).

| Command | Local flags |
|---|---|
| `host ip list` | `--filter F:C:V`, `--columns Name,IPFamily,...` |
| `host ip show <name>` | (none) |
| `host ip search <query>` | `--columns` |
| `host ip usage <name>` | `--with-references` |
| `service list` | `--filter`, `--columns` |
| `service show <name>` | (none) |
| `service search <query>` | `--columns` |
| `service usage <name>` | `--with-references` |
| `firewall rule list` | `--filter`, `--columns` |
| `firewall rule show <name>` | (none) |
| `nat rule list` | `--filter`, `--columns` |
| `nat rule show <name>` | (none) |

### 5.3 JSON envelope schemas

| Command | Schema |
|---|---|
| `host ip list` / `host ip search` | `sophosfw.v1.hostIpList`, `sophosfw.v1.hostIpSearch` |
| `host ip show` | `sophosfw.v1.hostIp` |
| `host ip usage` | `sophosfw.v1.hostIpUsage` |
| `service list` / `service search` | `sophosfw.v1.serviceList`, `sophosfw.v1.serviceSearch` |
| `service show` | `sophosfw.v1.service` |
| `service usage` | `sophosfw.v1.serviceUsage` |
| `firewall rule list` | `sophosfw.v1.firewallRuleList` |
| `firewall rule show` | `sophosfw.v1.firewallRule` |
| `nat rule list` | `sophosfw.v1.natRuleList` |
| `nat rule show` | `sophosfw.v1.natRule` |

`list` and `search` use distinct schema names so consumers can tell what kind of operation produced the result. The payload shape is identical between them.

### 5.4 Table column resolution

The cli `--columns` flag overrides the catalog default. Helper in `internal/cli/columns.go`:

```go
func resolveColumns(cmd *cobra.Command, defaultCols []string) []string {
    if v, _ := cmd.Flags().GetString("columns"); v != "" {
        return strings.Split(v, ",")
    }
    return defaultCols
}
```

Default columns come from `cat.Resolve(tag).Columns` for each list command. Array-valued cells render as comma-joined strings (e.g. `"LAN, DMZ"`). Object-valued cells render as `<map>` placeholder (table view is a degraded view; users wanting the full structure pass `--json`).

For derived fields, the column name is `derived.<field>` (e.g. `--columns Name,derived.cidr,derived.kind`). The renderer detects the `derived.` prefix and looks up the field on the typed item's `Derived` struct via JSON tag name.

The same resolver is used by `object list` after the backport.

### 5.5 Generic-`object` backport

`internal/cli/object.go`'s `newObjectListCmd` adds:

```go
c.Flags().StringVar(&columns, "columns", "", "comma-separated column override")
```

`renderObjectList` uses `resolveColumns(cmd, entry.Columns)` instead of `entry.Columns` directly. One additional test in `object_test.go` verifies the override.

## 6. Data shapes — concrete JSON examples

### 6.1 `host ip list --json`

```json
{
  "schema": "sophosfw.v1.hostIpList",
  "profile": "home",
  "xmlTag": "IPHost",
  "count": 2,
  "items": [
    {
      "Name": "LAN-network",
      "IPFamily": "IPv4",
      "HostType": "Network",
      "IPAddress": "10.0.0.0",
      "Subnet": "255.255.255.0",
      "derived": {
        "cidr": "10.0.0.0/24",
        "kind": "network"
      }
    },
    {
      "Name": "Public-DNS",
      "IPFamily": "IPv4",
      "HostType": "IP",
      "IPAddress": "8.8.8.8",
      "derived": {
        "kind": "host"
      }
    }
  ]
}
```

### 6.2 `host ip usage LAN-network --with-references --json`

```json
{
  "schema": "sophosfw.v1.hostIpUsage",
  "profile": "home",
  "name": "LAN-network",
  "records": [...],
  "references": {
    "IPHostGroup": ["LAN-group"],
    "FirewallRule": ["LAN-To-WAN", "LAN-Outbound"],
    "NATRule": []
  }
}
```

With one referrer query failed:

```json
{
  "schema": "sophosfw.v1.hostIpUsage",
  "profile": "home",
  "name": "LAN-network",
  "records": [...],
  "references": {
    "IPHostGroup": ["LAN-group"],
    "FirewallRule": null,
    "NATRule": []
  },
  "referenceErrors": {
    "FirewallRule": "permission_denied: sophos: permission denied"
  }
}
```

### 6.3 `service list --json`

```json
{
  "schema": "sophosfw.v1.serviceList",
  "profile": "home",
  "count": 1,
  "items": [
    {
      "Name": "HTTP",
      "Type": "TCPorUDP",
      "ServiceDetails": { /* raw nested */ },
      "derived": {
        "protocol": "tcp",
        "portRange": "80"
      }
    }
  ]
}
```

### 6.4 `firewall rule list --json` (untyped items)

```json
{
  "schema": "sophosfw.v1.firewallRuleList",
  "profile": "home",
  "count": 1,
  "items": [
    {
      "Name": "LAN-To-WAN",
      "Action": "Accept",
      "SourceZones": ["LAN"],
      "DestinationZones": ["WAN"],
      "Sources": ["LAN-network"],
      "Services": ["HTTP", "HTTPS"],
      "Status": "Enable"
    }
  ]
}
```

No `derived` block. The columns rendered in table mode come from the catalog's `columns` field for `FirewallRule`.

## 7. Error handling

Phase 3 inherits the foundation's error model and `cli.HandleError` mapping unchanged.

| Condition | Behavior | Exit code |
|---|---|---|
| `host ip show <name>` for missing object | `sophos.ErrNotFound` propagated; `not_found` envelope | 1 |
| `host ip search <q>` with zero matches | `count: 0`, empty `items`, no error | 0 |
| `host ip usage <name> --with-references`, primary stats fails | error returned; envelope per `cli.ErrorKind` | non-zero |
| `host ip usage <name> --with-references`, all referrer queries succeed | full `references` block | 0 |
| `host ip usage <name> --with-references`, some referrer queries fail | partial `references`, `referenceErrors` populated | 0 |
| `host ip list` with `--filter` matching nothing | empty list, no error | 0 |
| `--columns Name,Foo` where Foo doesn't exist | empty cells in table, no error | 0 |
| Read-only profile | foundation rejects mutating envelopes; Phase 3 commands are all read-only so never trigger this | 0 (Phase 3 calls don't mutate) |

Per-referrer error tags use the same vocabulary as `cli.ErrorKind`: `auth_failed`, `permission_denied`, `network_error`, `tls_error`, `not_found`, `invalid_request`, `server_error`, `read_only_violation`, `unsupported_in_phase`, `generic`.

## 8. Testing strategy

### 8.1 Catalog parser tests (3 files, ~6 tests)

Each new typed parser gets a `_test.go` with two cases. Fixtures in `testdata/sophos/responses/` are referenced via the existing parser test pattern (the foundation's `iphost_test.go` is the model).

- `fqdnhost_test.go`: parses single FQDN entry; parses wildcard `*.example.com`.
- `machost_test.go`: parses single MAC; parses multi-MAC entry (multiple addresses in one MACHost).
- `zone_test.go`: parses built-in LAN zone; parses custom zone with description.

### 8.2 Reference-graph tests (`references_test.go`, ~4 tests)

- `TestFindReferences_AllSucceed`: 3 referrers, name found in 2 of them. Assert `Refs` populated with names, third is empty array, `Errors` is empty.
- `TestFindReferences_OneReferrerFails`: 3 referrers, one returns `ErrPermissionDenied`. Assert that one in `Errors`, others normal.
- `TestFindReferences_PrimaryNotInMap`: defensive case, asks for an unknown primary tag. Assert error returned (not panic).
- `TestFindReferences_ExactMatchOnly`: a referrer record contains "LAN-network-extra" but we asked for "LAN-network". Assert it's NOT counted (exact-match scanning, not substring).

### 8.3 Service tests (4 files, ~16 tests)

- `hostip_test.go`: `TestHostIPSvc_List_EnrichesCidr`, `TestHostIPSvc_List_OmitsCidrForNonNetwork`, `TestHostIPSvc_Get_ReturnsTyped`, `TestHostIPSvc_Search_MultiField`, `TestHostIPSvc_Search_NoMatches`, `TestHostIPSvc_Usage_NoRefs`, `TestHostIPSvc_Usage_WithRefs`. All use a fake `svc.Client`.
- `service_test.go`: parallel structure, including `TestServiceSvc_List_DerivedPortRange_SinglePort`, `_Range`, `_Multi`, `_NonContiguous`. Verifies the port-collapse algorithm.
- `firewallrule_test.go`: `TestFirewallRuleSvc_List_UntypedItems`, `_Get_ByName`, `_Get_NotFound`.
- `natrule_test.go`: parallel structure, smaller scope.

### 8.4 CLI tests (4 files, ~12 tests)

- `hostip_test.go`: `TestHostIp_List_TablePrintsCidrColumn`, `_List_JsonHasDerivedBlock`, `_Search_FiltersClientSide`, `_Usage_WithReferencesJsonShape`.
- `service_test.go`: parallel structure.
- `firewallrule_test.go`: `TestFirewallRule_List_DefaultColumns`, `_List_ColumnsOverride`, `_Show_ByName`, `_List_ArrayCellsCommaJoined`.
- `natrule_test.go`: smaller, mirrors firewallrule.
- `object_test.go`: ONE additional test, `TestObject_List_ColumnsOverride`, exercising the backported flag.

### 8.5 Integration tests (build-tagged)

Extend `internal/testutil/integration_test.go` (build tag `integration`) with one round-trip per new typed wrapper:

- `TestIntegration_HostIPList_RoundTrips` — calls the real firewall, asserts no error.
- `TestIntegration_ServiceList_RoundTrips`
- `TestIntegration_FirewallRuleList_RoundTrips`
- `TestIntegration_NATRuleList_RoundTrips`

These tests use the `IntegrationClient` wrapper from the foundation, which mechanically blocks mutating envelopes. They run with `make test-int` and require `SOPHOSFW_PROFILE` set.

### 8.6 Total

Approximately 35 new test functions across catalog, svc, and cli packages, plus 4 build-tagged integration tests. 5 new fixture XML files. 0 changes to existing tests except the one-line `TestObject_List_ColumnsOverride` addition in `object_test.go`. All tests deterministic; no new external dependencies.

## 9. Acceptance criteria

A Phase 3 implementation is acceptance-passing when:

1. `go fmt ./...` produces no output (clean).
2. `go vet ./...` produces no warnings.
3. `go test -race ./...` passes all tests, including the new ~25 added by this phase.
4. `make build` produces a binary that lists the new commands in `--help`:
   - `host` parent visible at root level.
   - `service`, `firewall`, `nat` parents visible at root level.
   - All subcommands (list/show/search/usage as applicable) visible.
5. Manual smoke commands return well-formed envelopes:
   - `sophosfw host ip list --json` — `sophosfw.v1.hostIpList` envelope, items with `derived` block on Network entries.
   - `sophosfw service list --json` — `sophosfw.v1.serviceList`, items with `derived` block where applicable.
   - `sophosfw firewall rule list --json` — `sophosfw.v1.firewallRuleList`, untyped items.
   - `sophosfw host ip usage NAME --with-references --json` — full `references` block populated (or `referenceErrors` if a referrer query failed).
6. `make skill-doctor` still passes. (The Phase 3 commands aren't yet referenced in `examples.md`; that lands in Phase 5. Doctor's required-commands list is unchanged.)
7. `SOPHOSFW_INTEGRATION=1 SOPHOSFW_PROFILE=home make test-int` passes the four new round-trip tests against a real or stub firewall.
8. No mutating envelopes are constructed anywhere in Phase 3 code (verified by code review and the `IntegrationClient` mechanical guard).
9. Tagged as `v0.2.0-phase3` on `main`.

## 10. Open questions deferred

- Should `host ip search --ip <addr>` (CIDR-containment) ship in Phase 3 as a follow-on, or wait? Currently deferred; revisit at end of Phase 3 implementation.
- Should the agent skill be updated for Phase 3 commands now or in Phase 5? Currently Phase 5; if Phase 3 ships and the skill doctor's required list grows, may need to backport.
- Should `firewall rule list --columns derived.something` work? Currently no — typed-derived fields only exist for IPHost and Service. Documented limitation.
- The catalog YAML entries for FQDNHost and MACHost use `usageTag: FQDNHostStatistics` and `usageTag: MACHostStatistics`. These names are inferred from Sophos's IPHost / IPHostStatistics naming convention. If the actual Sophos API uses different tag names (e.g. they may not have stats variants for all host types), the implementer should verify against live API docs or a real firewall during T-implementation and adjust the catalog YAML. This is a verification step, not a design ambiguity — `host fqdn usage` is not a Phase 3 first-class command, so the only consumer in Phase 3 is `object usage FQDNHost --name X` for users who want it via the generic surface.
