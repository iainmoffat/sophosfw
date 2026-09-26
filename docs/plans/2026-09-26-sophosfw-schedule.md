# Schedule Object Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use ultrapowers:subagent-driven-development (recommended) or ultrapowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add first-class SFOS `Schedule` support to sophosfw: a catalog entry, `schedule list|show|create|update|delete`, and five MCP tools, under the house mutating contract. This is issue iainmoffat/sophosfw#12.

**Architecture:** The work follows the existing seams. A catalog YAML entry and a typed parser normalize the one-or-many `ScheduleDetail` shape, so every read path hashes the same thing. A pure validation function encodes the SFOS rules measured on testvm. `ScheduleSvc` mirrors `ServiceGroupSvc.mutate` and adds a fail-closed FirewallRule reference guard on delete. The CLI and MCP layers are thin wrappers that mirror the ServiceGroup equivalents.

**Tech Stack:** Go (module `github.com/iainmoffat/sophosfw`), cobra, `github.com/modelcontextprotocol/go-sdk/mcp`, testify.

Format: contract-grade

**Probe:** literal-code count: 60 lines. Skeleton fraction: 1.0 (YAML catalog entry, JSON fixtures, Go type/const/signature skeletons; nothing branches on runtime data). Probed fraction: 1.0 (2026-09-26, in a throwaway worktree at base 88b38f7): the YAML was spliced into objects.yaml; the 3 fixtures parsed with `python3 -m json.tool`; the Go skeletons were added with stub bodies and `go vet ./...` was clean; `go test ./internal/catalog/` and `go test ./...` passed. The task Run commands exercise executor-written code and are checked at execution, not at plan time.

**Spec:** `docs/specs/2026-09-26-sophosfw-schedule-design.md` (approved 2026-09-26). Where this plan and the spec differ, the plan's pinned choices win. Each one is marked **(pin)**.

## Global Constraints

- Never contact a firewall from unit tests. Use the fake clients the neighbouring `*_test.go` files already use. Integration tests use `testutil.IntegrationClient` only (build tag `integration`), which panics on mutating envelopes.
- Never run a mutating command against any profile other than `testvm`, and never against `prod`. Executors do not run live mutations at all; the controller does the manual smoke run (see the end of this plan).
- Every validation and guard error wraps `sophos.ErrInvalidRequest`, so it renders with kind `invalid_request`.
- Days, a closed and case-sensitive list: `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday`, `Saturday`, `Week Days`, `Weekdays Including Saturday`, `All Days of week`.
- Time format: `StartTime` and `StopTime` match `^([01][0-9]|2[0-3]):(00|15|30|45)$`. `StopTime` may also equal exactly `23:59`.
- **(pin)** Every human-readable period uses ASCII hyphen-minus (`Sunday 19:45-23:59`), never an en dash.
- Audit operation names: `schedule_create`, `schedule_update`, `schedule_delete`. ObjectType: `Schedule`.
- JSON envelope schemas follow `sophosfw.v1.<name>`.
- `make test` (`go test -race ./...`) and `make vet` must be green at the end of every task. Run `make lint` if golangci-lint is installed.
- Commit only product files. Never `git add -f` an ignored path. Commit subjects use the repo style (`feat(svc): …`, `fix(sophos): …`, `docs: …`), and every body ends with `Refs #12`.

---

### Task 1: Map SFOS 599 to permission_denied

**Files:**
- Modify: `internal/sophos/status.go` (`statusToError`)
- Supersedes: `internal/sophos/status_test.go` `TestStatusToError_GenericServerError`, which currently asserts that 599 maps to the server-error sentinel. Change that test to use code 531, which remains a server error, in this task.
- Test: `internal/sophos/status_test.go`

**Interfaces:**
- Consumes: nothing (existing code used: statusToError, ErrPermissionDenied in internal/sophos/status.go)
- Produces: nothing new (behavior change only)

**Invariants & constraints:**
- Exact value: status code 599 maps to a `*StatusError` whose sentinel is `ErrPermissionDenied`, whatever the message. This was the owner's decision.
- Boundaries: 535 still maps to `ErrPermissionDenied`, 500–530 to `ErrInvalidRequest`, 531–598 and ≥600 to `ErrServerError`. The StatusError keeps its `Code` and `Message`.

**Test intentions:**
- 599 is permission denied. Mutation: delete the 599 case, so `errors.Is(err, ErrPermissionDenied)` is false and the test fails.
- 531 is still a generic server error. Mutation: widen the new case to `code >= 531`, so 531 becomes permission denied and the test fails.
- 599 keeps its code and message. Mutation: construct the 599 StatusError without `Code`/`Message`, so the equality asserts fail.

- [ ] **Step 1:** Write the three tests, and change `TestStatusToError_GenericServerError` to use 531.
- [ ] **Step 2:** Run `go test ./internal/sophos/ -run TestStatusToError -v`. Expected: the new 599 permission-denied test FAILS, because 599 currently maps to server error.
- [ ] **Step 3:** Add the 599 case to `statusToError`.
- [ ] **Step 4:** Run `go test ./internal/sophos/ -v`. Expected: PASS. Then run `make test` and expect PASS.
- [ ] **Step 5:** Commit `fix(sophos): map status 599 to permission_denied`.

---

### Task 2: Catalog entry and `schedule` typed parser

**Files:**
- Modify: `internal/catalog/objects.yaml` (append the entry below after the `ServiceGroup` entry)
- Modify: `internal/catalog/register.go` (register the parser in `NewDefault`)
- Create: `internal/catalog/schedule.go`
- Create: `internal/catalog/schedule_test.go`
- Create: `internal/catalog/testdata/schedule_single.json`, `internal/catalog/testdata/schedule_multi.json`, `internal/catalog/testdata/schedule_onetime_nodetail.json`
- Supersedes: nothing

**Interfaces:**
- Consumes: nothing (existing code used: Catalog.RegisterParser, TypedParser in internal/catalog/catalog.go)
- Produces: `ScheduleParser` (package `catalog`, signature func(raw json.RawMessage) (any, error), returns a map[string]any) and the catalog tag `Schedule` (alias `schedule`, `mutable: true`, `typedParser: schedule`, empty `usageTag`).

Catalog entry (verbatim):

```yaml
  - tag: Schedule
    aliases: [schedule]
    description: "Time schedules (Recurring / OneTime) referenced by rules"
    columns: [Name, Type, ScheduleDetails]
    filterable: [Name, Type]
    usageTag: ""
    typedParser: schedule
    mutable: true
```

Skeleton:

```go
// ScheduleParser is the typed-parser callback for the "schedule"
// identifier in objects.yaml. It returns map[string]any (not a struct) so
// unknown and OneTime fields survive the round trip.
func ScheduleParser(raw json.RawMessage) (any, error)
```

Fixtures, captured from the testvm read shape. `schedule_single.json`:

```json
{"Description":"All Time on Sunday","Name":"All Time on Sunday","ScheduleDetails":{"ScheduleDetail":{"Days":"Sunday","StartTime":"00:00","StopTime":"23:59"}},"Type":"Recurring"}
```

`schedule_multi.json`:

```json
{"Description":"All Time on Weekends","Name":"All Time on Weekends","ScheduleDetails":{"ScheduleDetail":[{"Days":"Sunday","StartTime":"00:00","StopTime":"23:59"},{"Days":"Saturday","StartTime":"00:00","StopTime":"23:59"}]},"Type":"Recurring"}
```

`schedule_onetime_nodetail.json` is synthetic, since no OneTime record has been observed:

```json
{"Name":"probe-onetime","Type":"OneTime","StartDate":"2026-10-01","EndDate":"2026-10-02"}
```

**Invariants & constraints:**
- Format: when `ScheduleDetails.ScheduleDetail` is a JSON object, the output holds a one-element `[]any` containing that object. When it is an array, the output keeps it as the same array.
- Boundaries: when `ScheduleDetails` is absent or null, or `ScheduleDetail` is absent or null, the parser leaves that shape exactly as received. It does not add an empty array. It never rejects a well-formed JSON object, including one with an unexpected `Type`.
- Every other key, top-level and inside `ScheduleDetails`, passes through with an unchanged value.
- Failure semantics: invalid JSON, or a JSON value that is not an object, returns a non-nil error.
- The `usageTag` is empty because SFOS returns 529 for `ScheduleStatistics`. `object usage Schedule` keeps the existing "does not support usage queries" error.

**Test intentions:**
- A single-object detail becomes a one-element array. Mutation: return the parsed map without wrapping, so the `[]any` type assertion fails.
- A multi-element array keeps its length (2) and order (Sunday first). Mutation: re-wrap an array inside another array, so the length becomes 1.
- A record with no `ScheduleDetails` comes out with no `ScheduleDetails` key. Mutation: insert `ScheduleDetails: {ScheduleDetail: []}` when it is absent, so the key-absence assert fails.
- A present `ScheduleDetails` with `"ScheduleDetail": null` keeps the null. Mutation: turn null into `[]any{}`, so the `Nil` assert fails.
- The OneTime fixture's `StartDate` and `EndDate` pass through. Mutation: drop unknown keys by decoding into a struct, so the equality assert fails.
- Invalid JSON (`{`) returns an error. Mutation: return `map[string]any{}` and nil on a decode error, so `require.Error` fails.
- `NewDefault()` resolves `Schedule` and `schedule` to an entry with `Mutable == true`, and `Parse("Schedule", single fixture)` yields the array shape. Mutation: omit the `RegisterParser("schedule", …)` line, so Parse returns an error or an unnormalized shape.

- [ ] **Step 1:** Add the fixtures and write the tests.
- [ ] **Step 2:** Run `go test ./internal/catalog/ -run Schedule -v`. Expected: FAILS on the undefined `ScheduleParser`.
- [ ] **Step 3:** Add the YAML entry, `schedule.go`, and the register line.
- [ ] **Step 4:** Run `go test ./internal/catalog/ -v`, then `make test`. Expected: PASS. The existing `TestIntegration_CatalogTagsAllRoundTrip` picks up the new tag automatically; do not run integration tests.
- [ ] **Step 5:** Commit `feat(catalog): add Schedule entry and typed parser`.

---

### Task 3: Schedule body validation

**Files:**
- Create: `internal/svc/schedule_validate.go`
- Create: `internal/svc/schedule_validate_test.go`
- Supersedes: nothing

**Interfaces:**
- Consumes: nothing (existing code used: sophos.ErrInvalidRequest)
- Produces: `validateScheduleBody` (signature func(body map[string]any) (map[string]any, error)) and `scheduleDays` (the ordered []string of valid Days values).

Skeleton:

```go
// scheduleDays is the closed, case-sensitive Days vocabulary, verified
// against SFOS on testvm 2026-09-26.
var scheduleDays = []string{
	"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
	"Week Days", "Weekdays Including Saturday", "All Days of week",
}

// validateScheduleBody checks a create/update body against the SFOS
// Schedule rules and returns a NEW normalized map: _diffHash removed,
// ScheduleDetails.ScheduleDetail always a []any of map[string]any. The
// caller's map is never mutated. Errors wrap sophos.ErrInvalidRequest.
func validateScheduleBody(body map[string]any) (map[string]any, error)
```

**Invariants & constraints:**
- Order: checks run in this order, and the **first** failure is returned (pin: errors are not aggregated). The order is `Name`, `Type`, `ScheduleDetails` structure, then each period in index order: key presence and type, `Days`, `StartTime` format, `StopTime` format, ordering.
- Exact error messages (pin). `%d` is the 1-based period index; `<next>` is the following weekday (Saturday→Sunday):
  - `Name must be a non-empty string`. This covers missing, non-string, and blank after `strings.TrimSpace`. The value is sent untrimmed.
  - `only Recurring schedules are writable (got %q)`. This covers a missing or non-string Type, which is formatted as `""`.
  - `ScheduleDetails must be an object containing ScheduleDetail`
  - `ScheduleDetail must be an object or a non-empty array of objects`
  - `period %d: %s must be a string`, where `%s` is the key name. This covers a missing key.
  - `period %d: Days %q is not a valid SFOS value (did you mean %q?)` when a case-insensitive match exists. Otherwise: `period %d: Days %q is not a valid SFOS value; valid values: ` followed by `scheduleDays` joined with `, `.
  - `period %d: StartTime %q must be HH:MM on a 15-minute boundary (:00, :15, :30, :45)`
  - `period %d: StopTime %q must be HH:MM on a 15-minute boundary (:00, :15, :30, :45) or 23:59`
  - Equal times: `period %d is empty (StartTime equals StopTime)`
  - Crossing, single day, StopTime ≠ `00:00`: `period %d crosses midnight; SFOS rejects this. Split it into %s %s-23:59 and %s 00:00-%s` (Days, Start, next day, Stop).
  - Crossing, single day, StopTime = `00:00`: `period %d crosses midnight; SFOS rejects this. Use %s %s-23:59 instead` (Days, Start).
  - Crossing, aggregate Days: `period %d crosses midnight; SFOS rejects this. %q is an aggregate: list the individual days and split each at midnight (<day> %s-23:59 plus <next day> 00:00-%s)` (Days, Start, Stop).
- Time comparison: compare `HH:MM` strings lexically, which is valid because both are zero-padded. A period is valid only when Start < Stop.
- Pass-through: unknown top-level and per-period keys are copied unchanged. `Description` is optional and copied. Duplicate periods are allowed.
- Days is case-sensitive: `sunday` is rejected even though SFOS accepts and normalizes it. This was the owner's decision.

**Test intentions — validation table (one row per case; each row asserts the error substring or success):**

| Behavior | Mutation |
|---|---|
| The testvm-ok periods pass: `Sunday 22:00-23:00`, `All Days of week 10:00-11:00`, `Sunday 10:15-12:00`, `Sunday 10:30-12:00`, `Sunday 10:00-11:15`, `Sunday 10:00-11:45`, `Sunday 00:00-23:45`, `Sunday 19:45-23:59` | Drop `:15` from the minute set, so the 10:15 row errors |
| Two periods (Sunday 19:45-23:59, Monday 00:00-06:00) pass, and the result's ScheduleDetail has length 2 | Keep only the first element, so the length is 1 |
| A single-object ScheduleDetail is returned as a one-element `[]any` | Return the input shape unchanged, so the type assert fails |
| Cross-midnight `Sunday 23:00-01:00` is rejected with `Split it into Sunday 23:00-23:59 and Monday 00:00-01:00` | Change the ordering check from `Start < Stop` to `Start != Stop`, so the row passes validation |
| Start == Stop `10:00-10:00` is rejected with `is empty (StartTime equals StopTime)` | Use `<=` in place of `<` for the ordering check, so the row passes |
| Crossing that ends at 00:00 (`Friday 20:00-00:00`) gives `Use Friday 20:00-23:59 instead` | Always use the two-part split message, so the substring is missing |
| Crossing on an aggregate (`Week Days 19:45-06:00`) gives `is an aggregate` | Treat aggregates as single days, so the message names a bogus next day |
| Saturday's next day is Sunday (`Saturday 20:00-06:00` → `and Sunday 00:00-06:00`) | Make next-day `index+1` without wrap, so it panics or mis-names the day |
| StopTime `24:00` is rejected (StopTime format message) | Widen the hour regex to `2[0-4]`, so the row passes |
| Off-grid `10:05`, `10:10` (start) and `11:14`, `11:59` (stop) are rejected | Allow any minute `[0-5][0-9]`, so the rows pass |
| StopTime `23:59` accepted, StartTime `23:59` rejected (format) | Allow `23:59` for StartTime too, so the start row passes |
| `Weekend` rejected with `valid values:` | Accept any non-empty Days, so the row passes |
| `sunday` rejected with `did you mean "Sunday"` | Compare Days case-insensitively, so the row passes |
| Type `OneTime` rejected with `only Recurring schedules are writable` | Skip the Type check, so the row passes |
| Missing Type rejected (`got ""`) | Default a missing Type to Recurring, so the row passes |
| Name `"   "` rejected; Name `42` (number) rejected | Check `!= ""` without trimming, so the blank row passes |
| `ScheduleDetails` as a string rejected; `ScheduleDetail: null` rejected; `ScheduleDetail: []` rejected; `ScheduleDetail: ["x"]` rejected | Treat an empty array as valid, so that row passes |
| Missing `StopTime` in period 2 is rejected with `period 2: StopTime must be a string` | Use 0-based indexes, so the substring says `period 1` |
| The first failure wins: period 1 has bad Days and period 2 bad times; the error names period 1 Days | Validate times of every period before Days, so the error names period 2 |
| `_diffHash` is removed from the result and unknown keys (`Foo` top-level, `Bar` in a period) are kept | Copy `_diffHash` through, so the absence assert fails |
| The caller's map is not mutated (the input still has the object-shaped detail and `_diffHash` after the call) | Normalize in place, so the input assert fails |

- [ ] **Step 1:** Write the table test.
- [ ] **Step 2:** Run `go test ./internal/svc/ -run TestValidateScheduleBody -v`. Expected: FAILS on the undefined `validateScheduleBody`.
- [ ] **Step 3:** Implement `schedule_validate.go`.
- [ ] **Step 4:** Run `go test ./internal/svc/ -run TestValidateScheduleBody -v`, then `make test`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(svc): validate Schedule bodies against SFOS rules`.

---

### Task 4: Key-scoped reference matching and skipped-record reporting

**Files:**
- Modify: `internal/svc/references.go`: `referenceTargets`, the `References` struct, `FindReferences`, and a new matcher.
- Supersedes: nothing is deleted. `FindReferences`'s two silent `continue` branches on marshal/unmarshal failure now also record a skip; existing `recordContains` stays for the other primaries.
- Test: `internal/svc/references_test.go`

**Interfaces:**
- Consumes: nothing (existing code used: FindReferences, References, recordContains in internal/svc/references.go)
- Produces: `References.Skipped` (a map[string]int field, JSON `skipped,omitempty`, nil when nothing was skipped), `referenceKeyFilter` (a map[string]string from primary tag to the key name that scopes matching), and `recordContainsUnderKey` (signature func(v any, key, name string) bool).

Skeleton:

```go
// referenceKeyFilter scopes matching for primaries whose name could
// collide with unrelated field values. When a primary has an entry, only
// values under a key with that name count as references.
var referenceKeyFilter = map[string]string{
	"Schedule": "Schedule",
}

// recordContainsUnderKey reports whether any key named `key`, at any
// depth, has a string value exactly equal to `name`.
func recordContainsUnderKey(v any, key, name string) bool
```

**Invariants & constraints:**
- `referenceTargets` gains `"Schedule": {"FirewallRule"}`.
- Matching: a primary with a `referenceKeyFilter` entry uses `recordContainsUnderKey`. Every other primary keeps `recordContains` unchanged. The match is an exact, case-sensitive string compare; a value nested in an array under a matching key does **not** count (pin: the key's direct value must be the string).
- Skipped: `Skipped[ref]` counts the records of referrer `ref` that (a) fail JSON marshal or unmarshal, or (b) **match** but have no non-empty string `Name`. Non-matching nameless records are not counted. `Skipped` is nil when every count is 0, mirroring how `Errors` is niled.
- The existing JSON renderers (`HostIPUsageEnvelope` and the service usage one) are not changed. Skipped counts are additive data that only the Schedule guard consumes.

**Test intentions:**
- A FirewallRule whose `NetworkPolicy.Schedule` equals the name is found. Mutation: match only top-level keys, so the nested key is missed.
- A FirewallRule whose `Description` equals the schedule name, with a different `Schedule`, is **not** found for primary `Schedule`. Mutation: use `recordContains` for Schedule, so it is reported.
- The same Description-collision record **is** still found for primary `IPHost`, which keeps any-leaf matching. Mutation: apply the key filter to every primary, so it is missed.
- A matching record with no `Name` increments `Skipped["FirewallRule"]` to 1 and is not in Refs. Mutation: keep the silent `continue`, so Skipped is nil.
- A non-matching record with no `Name` leaves `Skipped` nil. Mutation: count every nameless record, so Skipped is 1.
- A `Schedule` key whose value is the array `["X"]` does not match `X`. Mutation: recurse into arrays under the key, so it matches.
- A referrer list error still lands in `Errors` and gives an empty `Refs` slice, as today. Mutation: return a Go error instead, so `require.NoError` fails.

- [ ] **Step 1:** Write the tests, using the fake ObjectSvc client pattern already in `references_test.go`.
- [ ] **Step 2:** Run `go test ./internal/svc/ -run TestFindReferences -v`. Expected: the new Schedule tests FAIL (unknown primary tag `Schedule`).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./internal/svc/ -v`, then `make test`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(svc): scope Schedule reference matching and report skipped records`.

---

### Task 5: ScheduleSvc (list, show, create, update, delete with reference guard)

**Files:**
- Create: `internal/svc/schedule.go`
- Create: `internal/svc/schedule_test.go`
- Supersedes: nothing

**Interfaces:**
- Consumes: `ScheduleParser`, `validateScheduleBody`, `References.Skipped` (existing code used: ObjectSvc, AuditLog, AuditEntry, ObjectMutationResult, DiffHash, marshalObjectBody, sophos.BuildSetEnvelope, sophos.BuildRemoveEnvelope, FindReferences, ErrorKind, ErrDiffHashMismatch)
- Produces: `ScheduleSvc` (struct with fields Inner *ObjectSvc, Audit *AuditLog, Now func() time.Time), `ScheduleShow` (struct), and the methods `ScheduleSvc.List`, `ScheduleSvc.Show`, `ScheduleSvc.Create`, `ScheduleSvc.Update`, `ScheduleSvc.Delete`.

Skeleton:

```go
type ScheduleSvc struct {
	Inner *ObjectSvc
	Audit *AuditLog
	Now   func() time.Time
}

// ScheduleShow is the show result. References is non-nil only when the
// caller asked for them; it lives beside the record, never inside it.
type ScheduleShow struct {
	Object     *Object
	References *References
}

func (s *ScheduleSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*ObjectList, error)
func (s *ScheduleSvc) Show(ctx context.Context, profileName, name string, withReferences bool) (*ScheduleShow, error)
func (s *ScheduleSvc) Create(ctx context.Context, profileName, name string, body map[string]any, dryRun bool) (*ObjectMutationResult, error)
func (s *ScheduleSvc) Update(ctx context.Context, profileName, name string, body map[string]any, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error)
func (s *ScheduleSvc) Delete(ctx context.Context, profileName, name, expectedHash string, ignoreHash, dryRun bool) (*ObjectMutationResult, error)
```

**Invariants & constraints:**
- The pipeline mirrors `ServiceGroupSvc.mutate` in `internal/svc/servicegroup.go` step for step, with tag `Schedule` and audit op `schedule_<op>`. Its order is profile lookup, audit skeleton plus deferred error audit, read-only check, catalog `Mutable` check, **`validateScheduleBody`** (create and update; this replaces the required-fields check, and the normalized map is what gets marshalled), live fetch through `Inner.Get` plus hash gate (update and delete), **reference guard** (delete only), creds load, envelope build, dry-run short-circuit, apply, best-effort refetch.
- Hash gate: as in the template, a missing hash on update/delete fails **even on dry-run** unless `ignoreHash` is set. The message is `expectedDiffHash is required (or set ignoreExpectedDiffHash: true)`.
- Refetch: as in the template, a failed refetch after a successful apply returns success with an empty `NewDiffHash`.
- Envelope: the normalized periods marshal as repeated `<ScheduleDetail>` siblings inside one `<ScheduleDetails>`. Delete sends `<Remove><Schedule><Name>…</Name></Schedule></Remove>` with the name XML-escaped.
- Reference guard (delete, including dry-run), run after the hash gate:
  - `FindReferences(ctx, s.Inner, profileName, "Schedule", name)`. A Go error from it is returned as-is.
  - If `Errors["FirewallRule"]` is non-empty, or `Skipped["FirewallRule"] > 0`, refuse with `schedule %q: reference scan could not complete (%s); refusing to delete`. The `%s` is the error text, or `%d FirewallRule records could not be examined`.
  - If `Refs["FirewallRule"]` is non-empty, refuse with `schedule %q is referenced by firewall rules: %s`, with the names in scan order joined by `, `.
  - Both refusals wrap `sophos.ErrInvalidRequest`, and both are audited through the deferred error path (`Result` = `error:invalid_request`).
- `Show` with `withReferences=false` performs no FirewallRule query. With true, it returns the partial References, including Errors and Skipped, and **never** fails because of the scan.
- `List` and `Show` never write audit entries.

**Test intentions:**

1. A dry-run create with a single-object detail returns a Preview whose redacted XML contains exactly one `<ScheduleDetail>`, and nothing is sent. Mutation: skip the dry-run short-circuit, so the fake client records a send.
2. A create with two periods builds XML with two `<ScheduleDetail>` siblings. Mutation: marshal the un-normalized input body, so a single-object input yields a nested shape.
3. A create with an invalid body (`Weekend`) fails with `invalid_request` before any client call, and writes an audit entry with `error:invalid_request`. Mutation: validate after the envelope build, so the fake client sees a call.
4. A read-only profile is refused with `ErrReadOnlyViolation`. Mutation: drop the read-only check, so no error.
5. Hash consistency: the `_diffHash` returned by `Inner.Get` for the single-object fixture is accepted by `Update(..., expectedHash=that, dryRun=true)`. Mutation: have the live fetch bypass `ScheduleParser` by using a raw Get, so a hash mismatch is returned.
6. Update with a wrong hash returns `ErrDiffHashMismatch`. Mutation: skip the hash compare, so no error.
7. A dry-run update without a hash and without `ignoreHash` is refused. Mutation: move the dry-run short-circuit before the hash gate, so it succeeds.
8. A delete of a schedule referenced by FirewallRule `R1` is refused with `referenced by firewall rules: R1`, including on dry-run, and nothing is sent. Mutation: run the guard only when `!dryRun`, so the dry-run succeeds.
9. A delete is refused when the FirewallRule list query errors (`reference scan could not complete`). Mutation: ignore `Errors`, so the delete proceeds.
10. A delete is refused when a matching FirewallRule has no Name (`could not be examined`). Mutation: ignore `Skipped`, so the delete proceeds.
11. A delete with no references proceeds: the Remove envelope contains the escaped name, and an audit `ok` entry is written. Mutation: always refuse, so the success assert fails.
12. A successful apply whose refetch fails returns success with an empty `NewDiffHash`. Mutation: propagate the refetch error, so `require.NoError` fails.
13. `Show(withReferences=true)` returns References with `Refs["FirewallRule"]` populated. When the scan query errors, it still returns the Object with non-nil `References.Errors`. Mutation: return the scan error from Show, so `require.NoError` fails.
14. `Show(withReferences=false)` issues no FirewallRule Get. Mutation: always scan, so the fake client's recorded tags include FirewallRule.

- [ ] **Step 1:** Write the tests, mirroring the fake-client setup in `internal/svc/servicegroup_test.go`.
- [ ] **Step 2:** Run `go test ./internal/svc/ -run TestScheduleSvc -v`. Expected: FAILS on the undefined `ScheduleSvc`.
- [ ] **Step 3:** Implement `schedule.go`.
- [ ] **Step 4:** Run `go test ./internal/svc/ -v`, then `make test`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(svc): add ScheduleSvc with delete reference guard`.

---

### Task 6: `schedule` CLI command group

**Files:**
- Create: `internal/cli/schedule.go` (group, list, show, render helpers)
- Create: `internal/cli/schedule_mutation.go` (create, update, delete)
- Create: `internal/cli/schedule_test.go`, `internal/cli/schedule_mutation_test.go`
- Create: `internal/render/schedule.go`, `internal/render/schedule_test.go`
- Modify: `internal/cli/root.go` (add `root.AddCommand(newScheduleCmd(d, cat))` after `newServiceCmd`)
- Modify: `internal/cli/object.go` (`summarizeList` becomes a wrapper)
- Supersedes: `internal/cli/object.go` `summarizeList` body. Its logic moves into `summarizeCell(items, noun)`, and `summarizeList(items)` becomes `return summarizeCell(items, "members")`. The existing `object_render_test.go` expectations stay unchanged.

**Interfaces:**
- Consumes: `ScheduleSvc`, `ScheduleShow`, `ScheduleSvc.List`, `ScheduleSvc.Show`, `ScheduleSvc.Create`, `ScheduleSvc.Update`, `ScheduleSvc.Delete` (existing code used: LoadBody, resolveTargetProfiles, AddProfileSetFlag, printObjectMutation, printFanout, svc.Run, render.WriteTable, render.marshalEnvelope)
- Produces: `newScheduleCmd` (signature func(d RootDeps, cat *catalog.Catalog) *cobra.Command), `schedulePeriodsCell` (signature func(record map[string]any) string), `summarizeCell` (signature func(items []any, noun string) string), `ScheduleListEnvelope` (package render, signature func(l *svc.ObjectList) ([]byte, error)), and `ScheduleShowEnvelope` (package render, signature func(s *svc.ScheduleShow) ([]byte, error)).

**Invariants & constraints:**
- Commands: `schedule list [--filter F] [--columns …]`, `schedule show <name> [--with-references]`, `schedule create <name> --body B [--yes]`, `schedule update <name> --body B [--expected-diff-hash H | --ignore-diff-hash] [--yes]`, `schedule delete <name> [--expected-diff-hash H | --ignore-diff-hash] [--yes]`. Mutating commands carry `AddProfileSetFlag` and the fan-out path, exactly as `servicegroup_mutation.go`. The fan-out op names are `schedule_create`, `schedule_update` and `schedule_delete`.
- Dry-run is the default and `--yes` applies. The help text for `--expected-diff-hash` on update and delete is exactly `hash from a prior schedule show / object get; required for update and delete, including dry-run, unless --ignore-diff-hash`.
- Body Name rule (create and update): if `body["Name"]` is present and is not a string, or is blank after trimming, return `body Name must be a non-empty string`. If it is a non-blank string that differs from `<name>`, return the existing `body Name %q does not match positional arg %q`. Otherwise set `body["Name"] = name`.
- List table: headers `NAME`, `TYPE`, `PERIODS`. The PERIODS cell is `schedulePeriodsCell(record)`: each period renders as `<Days> <Start>-<Stop>`. Zero periods, or an absent or null ScheduleDetail, renders `-`. One period renders the bare string. Two or more go through `summarizeCell(periods, "periods")`, e.g. `2 periods: Sunday 00:00-23:59, Saturday 00:00-23:59`.
- JSON list: `sophosfw.v1.scheduleList` with payload `{profile, count, items}`, where the items are the unmodified parsed records.
- JSON show: `sophosfw.v1.schedule` with payload `{profile, name, data}`, where `data` is the record with `_diffHash`. When References is non-nil, it adds `references` (Refs), `referenceErrors` (only if non-empty) and `referenceSkipped` (only if non-empty) as **siblings of `data`**.
- Text show (pin) prints `Name: …`, `Type: …`, `Description: …` (omitted when absent), then `Periods:` with one `  <Days> <Start>-<Stop>` line per period, then `DiffHash: …`. With references it adds `Referenced by FirewallRule: a, b` (or `none`), and adds `Reference scan errors: …` when present.

**Test intentions:**
- `schedulePeriodsCell` gives `Sunday 00:00-23:59` for the single fixture. Mutation: use an en dash, so string equality fails.
- `schedulePeriodsCell` gives `2 periods: Sunday 00:00-23:59, Saturday 00:00-23:59` for the multi fixture. Mutation: call `summarizeList`, so the text says `members`.
- `schedulePeriodsCell` gives `-` for the OneTime no-detail fixture. Mutation: return `""`, so equality fails.
- The existing `object_render_test.go` still passes. Mutation: change the noun default in `summarizeList`, so those tests fail.
- `schedule show --json --with-references` has `references` beside `data`, and `data` has no `references` key. Mutation: merge the refs into the data map, so the `data.references` absence assert fails.
- `schedule create X --body '{"Name":"Y",…}'` errors with `does not match positional arg`. Mutation: overwrite without checking, so no error.
- `schedule create X --body '{"Name":"  ",…}'` errors with `body Name must be a non-empty string`. Mutation: treat blank as absent, so no error.
- `schedule create` without `--yes` renders a dry-run mutation (`applied: false`). Mutation: invert the `!yes` flag, so `applied: true`.
- `schedule delete X --yes` with a referenced schedule surfaces `referenced by firewall rules` and a non-zero exit. Mutation: swallow the error, so the exit is 0.
- `sophosfw schedule --help` lists `list show create update delete`. Mutation: omit `AddCommand` in root.go, so the command is unknown.

- [ ] **Step 1:** Write the render and CLI tests, following the harness patterns in `servicegroup_mutation_test.go` and `object_render_test.go`.
- [ ] **Step 2:** Run `go test ./internal/cli/ ./internal/render/ -run 'Schedule|Summarize' -v`. Expected: FAILS on the undefined `newScheduleCmd` / `schedulePeriodsCell`.
- [ ] **Step 3:** Implement. Do the `summarizeList` → `summarizeCell` refactor first and run `go test ./internal/cli/ -run Render -v` to confirm it is green before adding the schedule code.
- [ ] **Step 4:** Run `make test`, then `make build && ./bin/sophosfw schedule --help`. Expected: PASS, and the help lists the five subcommands.
- [ ] **Step 5:** Commit `feat(cli): add schedule command group`.

---

### Task 7: MCP schedule tools

**Files:**
- Create: `internal/mcp/schedule.go` (`schedule_list`, `schedule_show`)
- Create: `internal/mcp/schedule_mutation.go` (`schedule_create`, `schedule_update`, `schedule_delete`)
- Create: `internal/mcp/schedule_test.go`, `internal/mcp/schedule_mutation_test.go`
- Modify: `internal/mcp/server.go` (call `s.registerSchedule()` after `s.registerServiceGroup()`)
- Modify: `internal/mcp/server_test.go`: the tool count `62` → `67` in `TestServer_RegistersAllTools` (both the require.Len value and its message), plus the five names if the test lists names.
- Supersedes: the count literal `62` in `server_test.go`, replaced in this task.

**Interfaces:**
- Consumes: `ScheduleSvc`, `ScheduleSvc.List`, `ScheduleSvc.Show`, `ScheduleSvc.Create`, `ScheduleSvc.Update`, `ScheduleSvc.Delete`, `ScheduleListEnvelope`, `ScheduleShowEnvelope` (existing code used: resolveTargetProfilesMcp, errorEnvelopeResult, renderObjectMutation, renderFanoutResult, svc.Run)
- Produces: `registerSchedule` (a method on *Server) and the input types `ScheduleListInput`, `ScheduleShowInput`, `ScheduleCreateInput`, `ScheduleUpdateInput`, `ScheduleDeleteInput`.

Skeleton (field tags are part of the wire contract):

```go
type ScheduleListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty" jsonschema_description:"Field:Criteria:Value"`
}

type ScheduleShowInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required"`
	WithReferences bool   `json:"withReferences,omitempty" jsonschema_description:"When true, scan FirewallRule records for this schedule and include them beside the record"`
}
```

`ScheduleCreateInput`, `ScheduleUpdateInput` and `ScheduleDeleteInput` have exactly the fields and JSON tags of `ServiceGroupCreateInput`, `ServiceGroupUpdateInput` and `ServiceGroupDeleteInput` in `internal/mcp/servicegroup_mutation.go`. Every "ServiceGroup" in the descriptions is replaced by "Schedule". The create and update `body` descriptions are exactly: `the Schedule body. Required keys: Name, Type (must be Recurring), ScheduleDetails.ScheduleDetail (object or array of {Days, StartTime, StopTime}). Times are HH:MM on a 15-minute grid; StopTime may be 23:59; StartTime must be before StopTime (split periods at midnight).`

**Invariants & constraints:**
- Handlers mirror `handleServiceGroup{Create,Update,Delete}`. That covers: `confirm: true` required for all three mutating tools, including dry-run, with the existing message; the profile/profileSet resolution; the fan-out ops `schedule_create`, `schedule_update` and `schedule_delete`; and the rendering through `renderObjectMutation` / `renderFanoutResult`.
- The body Name rule is identical to Task 6: non-string or blank gives `body Name must be a non-empty string`, and a mismatch gives the existing mismatch message. Both are returned through `errorEnvelopeResult` with `invalid_request`.
- `schedule_show` returns `ScheduleShowEnvelope` output, and `schedule_list` returns `ScheduleListEnvelope` output. These are the same schemas as the CLI JSON (`sophosfw.v1.schedule`, `sophosfw.v1.scheduleList`).
- Tool descriptions for `schedule_delete` state: `Refused while any firewall rule references the schedule, or if the reference scan cannot complete.`

**Test intentions:**
- The server registers 67 tools, including the five `schedule_*` names. Mutation: skip `registerSchedule()`, so the count is 62.
- `schedule_create` without `confirm` returns an `invalid_request` envelope. Mutation: drop the confirm check, so a mutation result is returned.
- `schedule_create` with `dryRun: true, confirm: true` returns a preview and sends nothing. Mutation: pass `!in.DryRun`, so the fake records a send.
- `schedule_create` with a blank body Name returns `body Name must be a non-empty string`. Mutation: reuse the old `bn != ""` check only, so it passes.
- `schedule_delete` on a referenced schedule returns an error envelope containing `referenced by firewall rules`. Mutation: map the error to success rendering, so no error envelope.
- `schedule_show` with `withReferences: true` has a `references` field beside `data`. Mutation: ignore `WithReferences`, so the field is absent.
- `schedule_list` returns schema `sophosfw.v1.scheduleList`. Mutation: reuse the object-list envelope, so the schema string differs.

- [ ] **Step 1:** Write the tests, mirroring `internal/mcp/servicegroup_mutation_test.go` and `internal/mcp/service_test.go`.
- [ ] **Step 2:** Run `go test ./internal/mcp/ -run 'Schedule|RegistersAllTools' -v`. Expected: FAILS (undefined inputs; the count is still 62).
- [ ] **Step 3:** Implement and register.
- [ ] **Step 4:** Run `go test ./internal/mcp/ -v`, then `make test`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(mcp): add schedule_* tools`.

---

### Task 8: Documentation

**Files:**
- Modify: `docs/api-coverage.md` (a Schedule row in the same table format as the ServiceGroup row)
- Modify: `docs/command-map.md` (the five commands and five MCP tools, in the file's existing layout)
- Modify: `docs/agent-skill.md` (a new `## Schedules` section)
- Modify: `README.md` (add `schedule` to the command list)
- Modify: `docs/roadmap.md` (one line: `- Schedule objects (list/show/create/update/delete + MCP) — #12`)
- Supersedes: nothing

**Interfaces:**
- Consumes: `newScheduleCmd`, `registerSchedule`
- Produces: nothing

**Invariants & constraints:**
- The `docs/agent-skill.md` Schedules section states all of the following:
  - Only Recurring schedules are writable.
  - The exact Days list from Global Constraints. It is case-sensitive, and SFOS would accept lowercase, but sophosfw rejects it.
  - The 15-minute grid, with `23:59` allowed as StopTime.
  - Periods must not cross midnight. The split idiom is written out with the bedtime example: `Sunday 19:45-23:59` plus `Monday 00:00-06:00`.
  - Deletes are refused when a firewall-rule reference is found at delete time. The check is scan-time only.
  - Update and delete need the diff hash even for dry-run.
  - It carries this caveat verbatim: `Whether the minute 23:59–00:00 is covered by a period ending at 23:59 is unverified; it will be measured on sophos01 (see #12).`
- One `create` example body, in YAML, matching the brainstorm-approved shape: Type, Description, `ScheduleDetails.ScheduleDetail` list.
- No other doc files change.

**Test intentions:**
- `make skill-doctor` still passes if `.claude/skills/sophos-firewall` exists locally. It is not tracked in git; skip it when absent and say so in the report. Mutation: n/a (a docs task, verified by doctor or review).
- `grep -n "unverified" docs/agent-skill.md` finds the caveat line. Mutation: omit the caveat, so grep exits 1.
- `grep -n "schedule_delete" docs/command-map.md` finds the tool. Mutation: omit it, so grep exits 1.

- [ ] **Step 1:** Edit the five docs.
- [ ] **Step 2:** Run `grep -n "unverified" docs/agent-skill.md && grep -n "schedule_delete" docs/command-map.md`. Expected: both print a line, exit 0.
- [ ] **Step 3:** Run `make test`. Expected: PASS.
- [ ] **Step 4:** Commit `docs: document Schedule commands and SFOS period rules`.

---

## Controller-only: manual testvm smoke (after Task 8, before the PR)

This is not an executor task. Integration tests must not mutate, so the controller runs it by hand with the built binary. **Always pass `--profile testvm`.**

1. `make build`
2. `./bin/sophosfw schedule create sophosfw-smoke --profile testvm --body @smoke.yaml`: a dry-run preview showing two `<ScheduleDetail>`. `smoke.yaml` is Type Recurring with the periods Sunday 19:45-23:59 and Monday 00:00-06:00.
3. The same command with `--yes`, which should print `applied: true` and a new diff hash.
4. `./bin/sophosfw schedule show sophosfw-smoke --profile testvm --json`: two periods, plus `_diffHash`.
5. `schedule update` with the edited body (change Monday to 00:00-05:00) and `--expected-diff-hash <hash> --yes`, then `show` to confirm 05:00.
6. `schedule create sophosfw-smoke-bad --profile testvm --body` with a period crossing midnight: rejected client-side with the split message, and no request is sent.
7. `schedule delete sophosfw-smoke --expected-diff-hash <hash> --yes`, then `raw get Schedule --profile testvm` to confirm it is gone, with only the built-ins left.
8. `tail -5 ~/.config/sophosfw/audit.log`, which should show `schedule_create`/`schedule_update`/`schedule_delete` entries with the `ok` results.
9. `make test-int` with `SOPHOSFW_PROFILE=testvm`, which runs the read-only catalog round trip, now including Schedule.

A referenced-delete refusal against a real rule is **not** part of the smoke run; it needs a firewall rule on testvm. Unit tests cover the guard.
