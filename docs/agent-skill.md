# Agent skill

## Skill location

The agent skill for `sophosfw` is **not** part of this repository. It is
managed through `skillshare`, a multi-project skill distribution system,
and lives in a separate `ai-tooling/skillshare` repo. Each developer's
local `~/code/ai-tooling/skillshare/skills/sophos-firewall/` is the
canonical source.

For local development, `skillshare` symlinks the skill into
`.claude/skills/sophos-firewall/` (gitignored — never published from
this repo). If you've cloned this repo and want the skill, install
`skillshare` and run its sync; the skill will appear at
`.claude/skills/sophos-firewall/` automatically.

## Why skillshare

The skill content is shared across multiple projects (sophosfw, tdx,
others) and updated as one source of truth. Keeping it out of any
single project repo avoids divergence and the "broken symlink on
clone" problem that comes from tracking a path-dependent symlink.

## Skill files

The skill directory contains:
- `SKILL.md` — The main agent instructions and operating rules
- `examples.md` — Real implemented commands and workflows
- `safety-checklist.md` — Pre-flight safety checks
- `api-patterns.md` — Common API interaction patterns
- `audit-template.md` — Template for mutation audit logs

## Validation

Run `make skill-doctor` (or `sophosfw skill doctor`) to validate:
- `SKILL.md` exists
- `examples.md` exists
- Examples document the four required commands: auth login, object list, object get, raw get

This is asserted as part of the foundation acceptance criteria (criterion 14).

## References

See the main README at [README.md](../README.md#agent-skill) for the skill link.
For skill maintenance and updates, edit files under
`/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/` and sync
back to this project with `make skill-doctor` or skillshare tooling.
