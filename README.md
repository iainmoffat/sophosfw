# sophosfw

[![CI](https://github.com/iainmoffat/sophosfw/actions/workflows/ci.yml/badge.svg)](https://github.com/iainmoffat/sophosfw/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/iainmoffat/sophosfw)](https://github.com/iainmoffat/sophosfw/releases/latest)
[![License](https://img.shields.io/github/license/iainmoffat/sophosfw)](LICENSE)

Go CLI + MCP server for the Sophos Firewall XML API. Production-safe
read-only inspection by default, with mutating workflows for IPHosts,
firewall rules, and NAT rules behind explicit confirm gates.

## Status

Phases 0-10 complete (foundation through MCP-native firewall + NAT rule
mutations). The MCP server registers 30 tools; the CLI covers
inspection, drafts, dry-run preview, and apply for the supported
object types. See `docs/roadmap.md` and `docs/api-coverage.md` for the
exact surface.

## Install

**Homebrew** (macOS / Linux):

```bash
brew install iainmoffat/sophosfw/sophosfw
```

This installs the binary plus shell completions for bash, zsh, and fish.

**From source:**

```bash
git clone https://github.com/iainmoffat/sophosfw
cd sophosfw
make build
./bin/sophosfw version
```

Or `make install` to copy to `$GOBIN`. For shell completion when
installed from source, run `sophosfw completion <shell>` and source
the output (`sophosfw completion --help` shows per-shell instructions).

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
