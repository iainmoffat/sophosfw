# Agent skill

## Skill location

The agent skill for `sophosfw` is managed through skillshare, a multi-project
skill distribution system:

```
.claude/skills/sophos-firewall/                    (symlink)
    → /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/  (canonical)
```

## Why skillshare

The canonical skill source lives in `ai-tooling/skillshare/skills/sophos-firewall/`
so it can be shared across projects and updated as one source of truth. Claude Code
symlinks it into the project's `.claude/skills/` tree for local reference.

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
