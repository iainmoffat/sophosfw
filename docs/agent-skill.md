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

## Schedules

Schedule commands are `sophosfw schedule list`, `show`, `create`, `update`,
and `delete`. MCP exposes `schedule_list`, `schedule_show`,
`schedule_create`, `schedule_update`, and `schedule_delete`.

Only Recurring schedules are writable. The accepted, case-sensitive `Days`
values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday`,
`Saturday`, `Week Days`, `Weekdays Including Saturday`, and `All Days of week`.
SFOS would accept lowercase day names and normalize them, but sophosfw rejects
lowercase values; use the exact capitalization shown here.

`StartTime` and `StopTime` must be on the 15-minute grid (`:00`, `:15`, `:30`,
or `:45`). `StopTime` may also be exactly `23:59`. Periods must not cross
midnight. Split a bedtime period into `Sunday 19:45-23:59` plus
`Monday 00:00-06:00`.

Example create body (`--body` accepts YAML):

```yaml
Type: Recurring
Description: Overnight WAN block
ScheduleDetails:
  ScheduleDetail:
    - Days: Sunday
      StartTime: "19:45"
      StopTime: "23:59"
    - Days: Monday
      StartTime: "00:00"
      StopTime: "06:00"
```

For update and delete, obtain `_diffHash` with `schedule show` or
`object get Schedule` and pass it as `--expected-diff-hash`; it is required
even for dry-run. `--ignore-diff-hash` skips this check.

Deletes are refused when a firewall-rule reference is found at delete time.
The check is scan-time only: it scans firewall rules when deletion is
requested, and a clean scan only describes references found at that time.

Whether the minute 23:59–00:00 is covered by a period ending at 23:59 is unverified; it will be measured on sophos01 (see #12).
