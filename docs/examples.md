# Examples

For detailed examples and workflows, see the agent skill:

[`.claude/skills/sophos-firewall/examples.md`](./../.claude/skills/sophos-firewall/examples.md)

## Quick reference

### Authentication
```bash
sophosfw auth profile add home --url https://fw.example.com:4444
sophosfw auth login --profile home
sophosfw auth status --json
sophosfw auth test --json
```

### List objects
```bash
sophosfw object list IPHost --json
sophosfw object list Services --json
sophosfw object list FirewallRule --json
```

### Get details
```bash
sophosfw object get IPHost --filter Name:like:LAN --json
sophosfw object get IPHost --name "LAN-network" --json
sophosfw object usage IPHost --name "LAN-network" --json
```

### Raw API escape hatch
```bash
sophosfw raw get Zone --json
echo '<Get><Zone/></Get>' > /tmp/req.xml
sophosfw raw request /tmp/req.xml --dry-run --json
```

See the full skill documentation for additional patterns and safety guidelines.
