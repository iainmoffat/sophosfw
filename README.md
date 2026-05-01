# sophosfw

Go CLI + MCP server for the Sophos Firewall XML API. Production-safe
read-only inspection by default; mutating workflows arrive in later phases.

## Status

**Foundation phase** (Phases 0-2 of the roadmap):
- Profile-based config with macOS Keychain (file fallback) credential storage
- Sophos XML API client with login injection and credential redaction
- Hybrid object catalog (12 tags; typed parsers for IPHost and Services)
- Generic `object list/get/usage/schema` and `raw get/request --dry-run`
- `mcp serve` scaffold (zero tools registered; Phase 4 lands the tool surface)
- Three-layer read-only safety enforcement
- Stable `sophosfw.v1.*` JSON envelope contract

See `docs/roadmap.md` for what's coming.

## Install

```bash
git clone https://github.com/iainmoffat/sophosfw   # not yet published
cd sophosfw
make build
./bin/sophosfw version
```

Or `make install` to copy to `$GOBIN`.

## Quick start

```bash
sophosfw auth profile add home --url https://fw.example.com:4444
sophosfw auth login --profile home
sophosfw auth test --json
sophosfw object list IPHost --json
sophosfw object get IPHost --filter Name:like:LAN --json
```

## Safety warning

This tool talks to live firewall infrastructure. The foundation phase ships
no apply path — all mutating raw XML is preview-only. Read `docs/safety-model.md`
before doing anything beyond inspection.

## Sophos API prerequisites

The Sophos API is **disabled by default**. To use this tool:
1. Enable API access in the firewall web admin UI.
2. Add the host running `sophosfw` to the API allowed-clients list.
3. Confirm the API endpoint is reachable: `https://<host>:<admin-port>/webconsole/APIController`.

## MCP setup (foundation: stub only)

```json
{
  "mcpServers": {
    "sophosfw": {
      "command": "sophosfw",
      "args": ["mcp", "serve"]
    }
  }
}
```
The Phase-4 release will add the real tool surface; for now this serves
zero tools.

## Agent skill

Detailed agent guidance lives at
[`.claude/skills/sophos-firewall/SKILL.md`](.claude/skills/sophos-firewall/SKILL.md)
(symlink to `ai-tooling/skillshare/skills/sophos-firewall/`).
