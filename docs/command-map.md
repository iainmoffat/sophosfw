# Command map

## Foundation phase (implemented)

### Authentication
- `sophosfw auth login [--profile <name>]` — prompt for credentials, validate against firewall, persist
- `sophosfw auth status [--json]` — show current profile and credential backend
- `sophosfw auth test [--json]` — test connectivity and credentials against firewall
- `sophosfw auth logout [--profile <name>]` — delete stored credentials

### Profiles
- `sophosfw auth profile add <name> --url <url>` — create a profile
- `sophosfw auth profile list` — list all profiles (active marked with *)
- `sophosfw auth profile use <name>` — set active profile
- `sophosfw auth profile remove <name>` — delete a profile

### Objects (catalog-driven)
- `sophosfw object list <tag> [--json] [--filter <expr>]` — list objects of a type
- `sophosfw object get <tag> [--name <name>] [--filter <expr>] [--json]` — retrieve specific object
- `sophosfw object usage <tag> --name <name> [--json]` — show where an object is used
- `sophosfw object schema <tag>` — print catalog metadata for a type

### Raw API
- `sophosfw raw get <tag> [--json]` — fetch any XML tag (bypasses catalog)
- `sophosfw raw request <file.xml> [--dry-run] [--json]` — send hand-authored XML (preview only in foundation)

### System
- `sophosfw version` — print version, commit, Go runtime
- `sophosfw skill path` — print path to agent skill
- `sophosfw skill doctor` — validate skill files exist and examples are complete
- `sophosfw mcp serve` — start MCP server (foundation: 0-tool scaffold)

## Planned: Phase 3+ (first-class commands)

First-class wrappers with ergonomic flags and typed output:
- `sophosfw host ip list [--json] [--filter <expr>]` — list IP hosts
- `sophosfw host ip show <name> [--json]` — get IP host details
- `sophosfw host ip search <pattern>` — search IP hosts by name
- `sophosfw host ip usage <name>` — show IP host usage
- `sophosfw service list [--json]` — list services
- `sophosfw service show <name> [--json]` — get service details
- Similar for firewall rules, NAT rules, zones

## Planned: Phase 4 (MCP tools)

Full MCP tool suite exposing all foundation capabilities:
- `get_auth_status`, `test_firewall_connection`, `list_profiles`, `get_current_profile`
- `raw_get`, `list_objects`, `get_object`, `search_objects`, `get_object_usage`
- `list_ip_hosts`, `get_ip_host`, `list_services`, `get_service`, etc.

## Planned: Phase 6+ (mutations)

Apply paths with safety gates:
- `sophosfw raw request <file.xml> --dry-run --yes` — apply mutating XML
- `sophosfw host ip create --name <name> --address <ip> --dry-run --yes`
- `sophosfw host ip update <name> --address <ip> --dry-run --yes`
- `sophosfw host ip delete <name> --dry-run --yes`
