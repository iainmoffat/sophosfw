# sophosfw

[![CI](https://github.com/iainmoffat/sophosfw/actions/workflows/ci.yml/badge.svg)](https://github.com/iainmoffat/sophosfw/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/iainmoffat/sophosfw)](https://github.com/iainmoffat/sophosfw/releases/latest)
[![License](https://img.shields.io/github/license/iainmoffat/sophosfw)](LICENSE)

Go CLI + MCP server for the Sophos Firewall XML API. Production-safe
read-only inspection by default, with mutating workflows for IPHosts,
firewall rules, and NAT rules behind explicit confirm gates.

## Status

Phases 0-15 complete. The CLI covers read, draft, and mutating
operations across IP hosts, firewall rules, NAT rules, host/service
groups, FQDN/MAC hosts, services, and site-to-site IPsec VPN. The MCP
server registers 62 tools mirroring the CLI surface, plus
multi-firewall fan-out (`--profile-set`), config backup, and drift
detection. See `docs/roadmap.md` and `docs/api-coverage.md` for the
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

This tool talks to live firewall infrastructure. Mutating commands gate
on `--yes` and (where applicable) `--expected-diff-hash` for optimistic
concurrency. Profiles can be marked `readOnly: true` for client-side
mutation refusal. See `docs/safety-model.md` before doing anything
beyond inspection.

## Firewall-side setup

The Sophos XML API is **disabled by default** and the user account you
authenticate as needs explicit API permission — even if it's an admin
in the web console. See [`docs/firewall-setup.md`](docs/firewall-setup.md)
for the full procedure (enable API, create user, grant role permissions,
allowed-IP list, troubleshooting `auth_failed` 534, password length
gotchas).

## MCP setup

Configure your MCP host (Claude Desktop, Claude Code, mcp-inspector)
to spawn the sophosfw MCP server over stdio:

```json
{
  "mcpServers": {
    "sophosfw": {
      "command": "sophosfw",
      "args": ["mcp", "serve", "--profile", "prod"]
    }
  }
}
```

For Claude Code specifically, the easiest path is:

```bash
claude mcp add sophosfw -- sophosfw mcp serve --profile prod
```

The `--profile` flag sets the server's default profile. Each MCP tool
also accepts an optional `profile` argument that overrides the
server-default per call. After adding the server, restart your MCP
host so the tool list reloads.

## Agent skill

Detailed agent guidance lives at
[`.claude/skills/sophos-firewall/SKILL.md`](.claude/skills/sophos-firewall/SKILL.md)
(symlink to `ai-tooling/skillshare/skills/sophos-firewall/`).
