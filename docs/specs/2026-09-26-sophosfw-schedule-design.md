# sophosfw — Schedule object support (design)

- Issue: iainmoffat/sophosfw#12 (`agent-plan`)
- Date: 2026-09-26
- Status: draft, awaiting owner approval

## Goal

First-class support for the SFOS `Schedule` object:

- a catalog entry, so `object list/get/schema Schedule` work;
- `sophosfw schedule list|show|create|update|delete`;
- MCP tools `schedule_list/show/create/update/delete`.

Writes follow the house mutating contract used by the group commands. The
motivating case is the sys_admin bedtime WAN block: two Recurring schedules,
Sun–Thu 19:45–06:00 and Fri–Sat 20:00–06:00, referenced by a firewall rule.

## Non-goals

- **OneTime writes.** OneTime records are still listed and shown, because
  read paths pass them through unchanged. `create`/`update` with any `Type`
  other than `Recurring` is rejected client-side.
- **Automatically splitting cross-midnight periods.** The tool rejects them
  and says how to split them (see Validation).
- **The prod write privilege.** The prod API account returns 599 ("Not having
  privilege to add/modify configuration") on any `Set`. That is an SFOS admin
  change owned by sys_admin. This feature surfaces it as `permission_denied`
  and does nothing else about it.

## Decisions taken with the owner

| Question | Decision |
|---|---|
| CLI input shape for periods | `--body` only (JSON/YAML, `@file`, `-`), the same as host/service/FQDN groups. MCP takes the same map. |
| `Days` vocabulary | A closed list of the exact strings SFOS stores, compared case-sensitively. Anything else is rejected client-side. |
| OneTime | Out of scope for writes. Read passthrough only. |
| Cross-midnight | Decided by a testvm probe (below): SFOS itself rejects it, so the tool rejects it client-side with a message suggesting a split. |

## Probe results (testvm, 2026-09-26)

Method: `sophosfw raw request … --profile testvm --yes --confirm-mutating`.
Probe objects were named `sophosfw-probe-*`, and every one was deleted
afterwards. Readback confirmed only the 6 built-in schedules remain. Each
rejection below was checked against a control that differs from it in only one
field.

| Probe | Result |
|---|---|
| Sunday 23:00→01:00 (Stop < Start) | **501** "Configuration parameters validation failed" |
| Control: Sunday 22:00→23:00 | ok |
| Start == Stop (10:00→10:00) | 501 |
| StopTime `24:00` | 501 |
| StartTime 10:05, 10:10; StopTime 11:14, 11:59 | 501 |
| Minutes :00, :15, :30, :45 (start and stop) | ok |
| StopTime `23:59` | ok (the built-ins use it too) |
| `Days: Weekend` | 501 |
| `Days: All Days of week` | ok |
| `Days: sunday` (lowercase) | ok, **stored as `Sunday`** |
| Two `<ScheduleDetail>` siblings in one `<ScheduleDetails>` | ok; read back as an array |
| `Set operation="update"` on an existing Schedule | ok; readback shows the new times |
| `Remove` | ok |
| `Get ScheduleStatistics` | **529** "Input request module is Invalid", so there is no usage tag |

Read shape: `ScheduleDetails.ScheduleDetail` is an object when there is one
period and an array when there are several. `Days` values seen on
sophos01/testvm: the seven day names, `Week Days`, `Weekdays Including
Saturday`, `All Days of week`.

**Not probed:** whether SFOS refuses to `Remove` a Schedule that a FirewallRule
still references. The delete guard below does not depend on the answer.

Consequence for the bedtime case: Sun–Thu 19:45–06:00 has to be expressed as
per-day periods, e.g. `Sunday 19:45–23:59` plus `Monday 00:00–06:00`, and so on
for each day. A single `Week Days 19:45–06:00` period is not accepted.

**Open for sys_admin's boundary measurement** (to be posted on #12): whether
`StopTime` is inclusive, and so whether the `23:59` period leaves the minute
23:59–00:00 uncovered, is being measured on sophos01. The spec does not depend
on it. The docs will record the measured answer and the recommended split idiom.

## Architecture

The work follows the existing seams, one unit per concern:

### 1. Catalog entry (`internal/catalog/objects.yaml`)

```yaml
  - tag: Schedule
    aliases: [schedule]
    description: "Time schedules (Recurring / OneTime) referenced by rules"
    columns: [Name, Type, ScheduleDetails]
    filterable: [Name, Type]
    usageTag: ""            # SFOS has no ScheduleStatistics (529)
    typedParser: schedule
    mutable: true
```

`object usage Schedule` keeps its existing "no Statistics tag" error. Reference
scanning goes through `schedule show --with-references`, described below.

### 2. Typed parser `schedule` (`internal/catalog/schedule.go`)

The parser normalizes `ScheduleDetails.ScheduleDetail` to **always be an
array** and leaves every other field untouched, so OneTime fields pass through
unchanged. `ObjectSvc.Get` computes `_diffHash` over the parser's output, which
means every read path hashes the normalized shape: `object get`, `schedule
show`, and the mutate pipeline's live fetch, which must call
`ObjectSvc.Get`. That consistency is required so a hash from `object get` works
as `--expected-diff-hash` for `schedule update`.

The parser returns `map[string]any`, not a struct, so unknown and OneTime
fields survive the round trip. It is registered in `register.go`.

### 3. Validation (`internal/svc/schedule_validate.go`)

A pure function, `validateScheduleBody(body map[string]any) (map[string]any,
error)`. It returns the normalized body, with `ScheduleDetail` always an array,
or an `ErrInvalidRequest` naming the offending period by its index:

- `Name` is required and non-empty. `Type` is required and must equal
  `Recurring`; any other value is rejected with "only Recurring schedules are
  writable".
- `ScheduleDetails.ScheduleDetail` is required and may be given as an object
  or an array. It must contain at least one period.
- `Days` must be in {Sunday … Saturday, `Week Days`, `Weekdays Including
  Saturday`, `All Days of week`}, compared case-sensitively. When a value
  matches case-insensitively, the error suggests the correct spelling.
- `StartTime` and `StopTime` must match `^([01]\d|2[0-3]):(00|15|30|45)$`.
  `StopTime` may also be exactly `23:59`.
- `StartTime` must be strictly earlier than `StopTime`. When it is not, the
  error reads: "period N crosses midnight or is empty; SFOS rejects this. Split
  it into <Days> <Start>–23:59 and <next day> 00:00–<Stop>". For an aggregate
  `Days`, the error says to list the individual days instead of naming a next
  day.
- `Description` is optional and passed through.
- Duplicate periods are not checked. SFOS accepts them, and deduplicating is
  not the tool's job.

Validation runs for both `create` and `update`, before the hash gate and before
any envelope is built. Dry-run validates too.

### 4. `ScheduleSvc` (`internal/svc/schedule.go`)

Create, update and delete mirror `ServiceGroupSvc.mutate` exactly: profile
lookup, audit skeleton, read-only check, catalog `Mutable` check, validation,
live fetch plus hash gate, envelope build, dry-run short-circuit, apply, then a
refetch that produces the new hash. The audit ops are
`schedule_{create,update,delete}` with ObjectType `Schedule`. The envelope
marshals the normalized array as repeated `<ScheduleDetail>` elements; probe
p3 confirms SFOS accepts that shape.

List and show delegate to `ObjectSvc.List` and `ObjectSvc.Get`.

**Delete reference guard.** This is new behavior; no current delete path
checks references. Before building the `Remove`, including on dry-run, the
service scans FirewallRule records for the schedule's name, **matching only
values under a key named `Schedule`**. Unlike generic `recordContains`, this
matcher cannot false-positive on a schedule whose name happens to equal some
other field value. Outcomes:

- references found: refuse with `ErrInvalidRequest` ("schedule %q is
  referenced by firewall rules: …") and list the rules in the error details.
  There is no override flag.
- the scan itself fails (auth, network): refuse. This fails closed, and the
  error says the scan could not complete.
- no references: proceed.

The dry-run preview carries `referencedBy: []`.

`referenceTargets` gains `"Schedule": {"FirewallRule"}`, paired with a
per-primary-tag key filter, so `FindReferences` stays the single scanner.
Other primaries keep their current any-leaf matching.

### 5. CLI (`internal/cli/schedule.go`, `schedule_mutation.go`)

A top-level `schedule` group:

- `list [--filter …]`: table columns Name, Type, and Periods. Periods is a
  summary such as `Sunday 19:45–23:59; Monday 00:00–06:00`, following the group
  member-list summarizing added in 6f23bec.
- `show <name> [--with-references]`: the record including `_diffHash`, plus
  `referencedBy` when the flag is set.
- `create <name> --body … [--yes]`.
- `update <name> --body … [--expected-diff-hash H | --ignore-diff-hash]
  [--yes]`.
- `delete <name> [--expected-diff-hash H | --ignore-diff-hash] [--yes]`.

Flags, help text and the dry-run default are copied from
`servicegroup_mutation.go`. `<name>` must equal `body.Name` when both are
given, and fills it in when it is absent, the same as
`servicegroup_mutation.go:57`. There are no renames: SFOS keys Schedule by
`Name`, so a rename is delete plus create. `update` is a full replacement of
the record: fields left out of the body are not preserved. The intended
workflow is `show` → edit → `update --expected-diff-hash`.

### 6. MCP (`internal/mcp/schedule.go`)

Five tools: `schedule_list`, `schedule_show` (with an optional
`withReferences`), `schedule_create`, `schedule_update` and `schedule_delete`.
The mutating tools take `confirm: true`, `dryRun`, `expectedDiffHash` and
`ignoreExpectedDiffHash`, matching `servicegroup_mutation.go`. They are
registered in `server.go`, and the tool-count assertion in `server_test.go` is
updated.

### 7. Docs

- `docs/api-coverage.md`: Schedule row.
- `docs/command-map.md`: the new commands and tools.
- `docs/agent-skill.md`: a Schedule section containing the split-period idiom,
  the 15-minute grid, `23:59`, the Days list, the rule that deletes are refused
  while a schedule is referenced, and the lowercase-normalization note.
- `README.md`: command list.
- `docs/roadmap.md`: a one-line entry.

## Error handling

| Condition | Kind |
|---|---|
| Validation failure (any rule in §3) | `invalid_request`, before any network call |
| Read-only profile | `read_only_violation` |
| Delete of a schedule a rule still references, or a failed reference scan | `invalid_request` with details `{referencedBy}` / `{scanError}` |
| Hash mismatch | `diff_hash_mismatch` (existing) |
| SFOS 599 (prod account: "Not having privilege…") | **Currently `server_error`**: `statusToError` maps only 535 to `ErrPermissionDenied`, and 599 falls outside the 500–530 invalid-request band. Proposed fold-in: map 599 → `ErrPermissionDenied`, with a status test. This affects every mutating command, not only Schedule (owner decision; see open questions). |
| Any residual SFOS 501 | `invalid_request` carrying the SFOS message (existing mapping) |

## Testing

- **Parser:** fixtures captured from testvm/sophos01 read shapes, one
  single-object and one array. Assert the output is an array and that other
  fields pass through untouched. Include an OneTime-shaped record.
- **Validation:** a table test built from the probe matrix above. Every 501
  case must be rejected client-side, and every ok case must pass. This is the
  contract that keeps the client and SFOS aligned.
- **Diff-hash consistency:** a single-period record fetched through
  `ObjectSvc.Get` and through the mutate live-fetch gives the same hash.
- **Service:** fake-client tests mirroring `servicegroup_test.go`: dry-run,
  read-only, hash gate, audit entries, envelope shape with repeated
  `<ScheduleDetail>`, and all three delete-guard outcomes.
- **CLI and MCP:** mirror `servicegroup_mutation_test.go` and the MCP
  equivalent.
- **Integration (read-only):** `schedule list/show` against testvm through
  `testutil.IntegrationClient`. It blocks mutations by design, per AGENTS.md.
- **Manual smoke, documented in the plan:** on testvm, create → show → update
  with the hash → delete, run with the built binary, then check the readback
  and the audit log. This is the round trip the issue asks for. It stays manual
  because integration tests must not mutate.

## Rollout

Feature branch `feat/schedule-object` → PR → release through the repo's
existing release process. Prod use additionally needs the API-account
privilege change, which is outside this repo.
