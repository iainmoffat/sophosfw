# Phase 14 — Multi-firewall fan-out (design)

**Date:** 2026-05-03
**Status:** Design (pre-implementation)
**Goal:** Enable fan-out of mutating commands, backup, and drift across N firewall profiles in one invocation. Add named profile groups in config. Pre-flight + sequential apply with fail-fast reporting. Ship as `v0.12.0`.

---

## 1. Motivation

After Phase 13 sophosfw can manage one firewall comprehensively. Real fleets have N firewalls (branch offices, SD-WAN endpoints, lab + prod pairs) where the same configuration change needs to land on multiple devices — same firewall rule, same shared IPHost, same NATRule across stores.

Today the user runs the same command N times by hand:
```bash
for p in edge-a edge-b store-1; do
  sophosfw firewall rule push my-rule --profile $p --expected-diff-hash $hash --yes
done
```

This has three real problems:
1. **No pre-flight gate.** A typo or schema mismatch on profile #2 of 5 means profiles 1-2 mutated, 3-5 untouched, partial-state mess.
2. **No grouping.** Repeating the same `--profile` list for every command (or shell-aliasing it) is error-prone.
3. **No aggregated reporting.** After 5 sequential commands the user has 5 separate result envelopes; no consolidated "what landed where" table.

Phase 14 ships a fan-out primitive that addresses all three: config-level profile groups, pre-flight gate across all targets, sequential apply with fail-fast and per-profile result reporting.

This is **distributed-systems-aware** fan-out: it does NOT pretend to be transactional (Sophos has no two-phase commit). It IS structured to minimize partial-state risk by failing before any mutation if the fleet won't accept the change uniformly.

## 2. Architecture

Three additions:

1. **Config schema extension**: new top-level `profileSets` map (`<name> → []string`). Each set names a list of profile names. Validated at load time.
2. **Fan-out orchestrator**: new `internal/svc/fanout.go` with `Run(ctx, profiles, op)` helper. Phase 1: parallel pre-flight (dry-run on each profile). Phase 2: sequential apply, fail-fast.
3. **CLI + MCP integration**: every existing mutating command, `backup`, and `drift` gains a `--profile-set <name|csv>` flag (CLI) / optional `profileSet` arg (MCP). Mutually exclusive with `--profile` / `profile`. New CLI sub-commands `sophosfw auth profile set add/list/remove` for set management. New MCP tool `auth_profile_set_list` for agent discovery.

No new mutating MCP tool surface. Tool count: 51 → 52 (just the read-only set lister).

## 3. Components

### 3.1 Config schema extension

`internal/config/config.go`:

```go
type Config struct {
    Version          int                  `yaml:"version"`
    CurrentProfile   string               `yaml:"currentProfile,omitempty"`
    Defaults         Defaults             `yaml:"defaults"`
    Profiles         map[string]Profile   `yaml:"profiles"`
    ProfileSets      map[string][]string  `yaml:"profileSets,omitempty"`  // NEW
}
```

Example config YAML:

```yaml
version: 1
currentProfile: edge-a
profiles:
  edge-a: {url: "https://edge-a:4444", ...}
  edge-b: {url: "https://edge-b:4444", ...}
  store-1: {url: "https://store-1:4444", ...}
  testvm: {url: "https://192.168.1.2:4444", ...}
profileSets:
  production:
    - edge-a
    - edge-b
    - store-1
  staging:
    - testvm
```

Validation at config-load time:
- Set names use the same allowlist as profile names (`^[A-Za-z0-9_-]+$`).
- Set names MUST NOT collide with profile names (resolver disambiguation).
- Each member must reference an existing profile — load fails with `ErrInvalidRequest` otherwise.
- Empty sets are allowed (rare but valid — placeholder).
- Same profile may appear in multiple sets; one set may contain duplicates (collapsed at resolve time, with no warning).

New methods on `*Config`:
```go
func (c *Config) AddProfileSet(name string, members []string) error
func (c *Config) RemoveProfileSet(name string) error
func (c *Config) ResolveProfileSet(nameOrCSV string) ([]string, error)
```

`ResolveProfileSet` accepts:
- A bare set name (`"production"`) → list of member profile names
- A CSV (`"edge-a,edge-b,store-1"`) → list of member profile names (no config lookup)
- A single profile name (`"edge-a"`) → single-element list (allows fan-out flag to gracefully accept single profiles too)

The resolver determines which form by trying CSV split first; if exactly one element AND it matches a known set name, treat as set; if it matches a profile name, treat as single profile; otherwise error.

### 3.2 Fan-out orchestrator

`internal/svc/fanout.go`:

```go
package svc

import (
    "context"
    "errors"
    "sort"
    "sync"
    "time"
)

// FanoutOp is the per-profile operation closure.
// preflight=true means dry-run; preflight=false means apply.
type FanoutOp func(ctx context.Context, profile string, preflight bool) (any, error)

type FanoutProfileResult struct {
    Profile        string
    Phase          string    // "preflight" | "apply" | "skipped"
    Status         string    // "ok" | "error"
    Error          string    // populated when Status == "error"
    PreflightResult any      // populated on successful preflight
    ApplyResult    any       // populated on successful apply
    DurationMs     int64
    StartedAt      time.Time
}

type FanoutResult struct {
    Operation        string
    Profiles         []string                 // input profile list, ordered
    Mutating         bool                     // false if --dry-run requested
    PreflightOK      bool                     // all preflights passed
    Aborted          bool                     // pre-flight failed and apply was skipped
    Results          []FanoutProfileResult    // per-profile, in input order
    StartedAt, EndedAt time.Time
}

// Run executes op against each profile in two phases: parallel pre-flight,
// then (if mutating and pre-flight passed) sequential apply with fail-fast.
//
// dryRunOnly=true: pre-flight only; no apply phase. This is the natural
//   shape for backup/drift fan-out, which are read-only (preflight=true is
//   the actual operation).
//
// dryRunOnly=false: pre-flight gate, then apply if all pre-flights pass.
//   On first apply failure, stop subsequent applies and mark them
//   "skipped"; return non-nil result with Aborted=false (apply phase
//   started) but the trailing profiles unmutated.
func Run(ctx context.Context, operation string, profiles []string, op FanoutOp, dryRunOnly bool) *FanoutResult {
    result := &FanoutResult{
        Operation: operation,
        Profiles:  profiles,
        Mutating:  !dryRunOnly,
        StartedAt: time.Now().UTC(),
        Results:   make([]FanoutProfileResult, len(profiles)),
    }

    // Phase 1: parallel pre-flight.
    var wg sync.WaitGroup
    for i, profile := range profiles {
        i, profile := i, profile
        wg.Add(1)
        go func() {
            defer wg.Done()
            r := FanoutProfileResult{Profile: profile, Phase: "preflight", StartedAt: time.Now().UTC()}
            out, err := op(ctx, profile, true)
            r.DurationMs = time.Since(r.StartedAt).Milliseconds()
            if err != nil {
                r.Status = "error"
                r.Error = err.Error()
            } else {
                r.Status = "ok"
                r.PreflightResult = out
            }
            result.Results[i] = r
        }()
    }
    wg.Wait()

    result.PreflightOK = true
    for _, r := range result.Results {
        if r.Status != "ok" {
            result.PreflightOK = false
            break
        }
    }

    if dryRunOnly {
        result.EndedAt = time.Now().UTC()
        return result
    }

    if !result.PreflightOK {
        // Mark untouched apply phase entries
        result.Aborted = true
        result.EndedAt = time.Now().UTC()
        return result
    }

    // Phase 2: sequential apply. Fail-fast.
    for i, profile := range profiles {
        // The pre-flight slot is the existing entry; we append a new entry for apply.
        // Actually keep it cleaner: replace the slot with apply outcome (preflight result preserved in PreflightResult field).
        startedAt := time.Now().UTC()
        out, err := op(ctx, profile, false)
        durMs := time.Since(startedAt).Milliseconds()
        applyResult := result.Results[i]
        applyResult.Phase = "apply"
        applyResult.StartedAt = startedAt
        applyResult.DurationMs = durMs
        if err != nil {
            applyResult.Status = "error"
            applyResult.Error = err.Error()
            result.Results[i] = applyResult
            // Mark trailing profiles as skipped
            for j := i + 1; j < len(profiles); j++ {
                result.Results[j].Phase = "skipped"
                result.Results[j].Status = "skipped"
            }
            result.EndedAt = time.Now().UTC()
            return result
        }
        applyResult.Status = "ok"
        applyResult.ApplyResult = out
        result.Results[i] = applyResult
    }

    result.EndedAt = time.Now().UTC()
    return result
}
```

Key behaviors:
- Pre-flight runs in parallel (no wait between profiles). Catches bad-input or per-firewall-state issues quickly.
- Apply runs sequentially. First failure stops further applies. Trailing profiles are explicitly marked "skipped" with no Status="ok".
- `dryRunOnly=true` mode (used for backup/drift fan-out) skips Phase 2 entirely.
- Result is always returned (even on abort) so callers can render the per-profile table.

Open question for implementation: should we expose `--parallel N` for apply phase? Spec says no — sequential is correct for fail-fast semantics. Defer until users ask.

### 3.3 CLI integration

**`--profile-set` flag** added to:
- All Phase 6/9-12 mutating commands (host_ip, firewall_rule, nat_rule, host_group, host_fqdn, host_fqdn-group, host_mac, service, service group)
- `sophosfw raw request` (the apply path of raw XML)
- `sophosfw backup` (no `--profile`, only `--profile-set`)
- `sophosfw drift`

The flag is mutually exclusive with `--profile`:

```go
// internal/cli/profileset.go
func resolveTargetProfiles(cmd *cobra.Command, cfg *config.Config) ([]string, error) {
    profile, _ := cmd.Flags().GetString("profile")
    profileSet, _ := cmd.Flags().GetString("profile-set")
    if profile != "" && profileSet != "" {
        return nil, fmt.Errorf("%w: --profile and --profile-set are mutually exclusive", sophos.ErrInvalidRequest)
    }
    if profileSet != "" {
        return cfg.ResolveProfileSet(profileSet)
    }
    if profile != "" {
        return []string{profile}, nil
    }
    // Default to current profile
    _, name, err := cfg.ActiveProfile("")
    if err != nil {
        return nil, err
    }
    return []string{name}, nil
}
```

Each mutating command's `RunE` swaps `profile := profileFromFlags(cmd)` for `profiles, err := resolveTargetProfiles(cmd, cfg)`. If `len(profiles) == 1`, behavior is identical to today (single-profile path, no fan-out overhead). If `len(profiles) > 1`, the command builds a `FanoutOp` closure and calls `svc.Run`.

**Single-profile fast path**: when `len(profiles) == 1`, the command's RunE may bypass fanout entirely and call the existing per-profile method directly. This keeps the existing log/output behavior for the common case unchanged. Recommended; avoid wrapping single-profile calls in fanout machinery.

**Profile set management** — new sub-commands under `sophosfw auth profile set`:

```bash
sophosfw auth profile set add production edge-a,edge-b,store-1   # CSV members
sophosfw auth profile set add production --member edge-a --member edge-b --member store-1  # repeated flag
sophosfw auth profile set list
sophosfw auth profile set list --json
sophosfw auth profile set remove production
```

`add` overwrites if the set name already exists.

### 3.4 MCP integration

Every existing mutating MCP tool gains an optional `profileSet` field on its Input struct. Mutually exclusive with `profile`. The handler resolves profiles via the same `ResolveProfileSet` helper, then runs fanout if `len(profiles) > 1`.

Affected tools (per Phase 6/10/12):
- `host_ip_create / _update / _delete`
- `firewall_rule_create / _update / _delete`
- `nat_rule_create / _update / _delete`
- `host_group_*`, `host_fqdn_*`, `host_fqdn_group_*`, `host_mac_*`, `service_*`, `service_group_*` (all `_create/_update/_delete`)
- `backup_create`
- `drift_check`

That's ~24 mutating tools + backup_create + drift_check = ~26 input types gaining the field. Mechanical change.

**New tool**: `auth_profile_set_list` (read-only) for agent discovery.

```go
type AuthProfileSetListInput struct {
    // No inputs.
}
// Output: sophosfw.v1.profileSetList
//   { schema, sets: [{name, members: [...]}] }
```

Tool count: 51 → 52.

**No** `auth_profile_set_add / _remove` MCP tools — set management is operator-driven (config write, sensitive). CLI-only.

### 3.5 Output format

**CLI default** (human):

```
Operation: firewall_rule_push
Profile set: production (3 profiles)

  Pre-flight:
    [edge-a]   OK   (412ms)
    [edge-b]   OK   (387ms)
    [store-1]  OK   (456ms)

  Apply:
    [edge-a]   OK   (1.21s)
    [edge-b]   OK   (1.14s)
    [store-1]  OK   (1.08s)

3 succeeded, 0 failed, 0 skipped.
```

On failure:

```
  Pre-flight:
    [edge-a]   OK   (412ms)
    [edge-b]   ERR  (387ms)  invalid_request: body field "Schedule" is empty
    [store-1]  OK   (456ms)

Pre-flight failed on 1 profile. Aborting (no mutations applied).

1 failed (edge-b: invalid_request).
```

**CLI `--json`**:

```json
{
  "schema": "sophosfw.v1.fanoutResult",
  "operation": "firewall_rule_push",
  "profiles": ["edge-a", "edge-b", "store-1"],
  "mutating": true,
  "preflightOK": true,
  "aborted": false,
  "startedAt": "...",
  "endedAt": "...",
  "results": [
    {"profile": "edge-a", "phase": "apply", "status": "ok", "durationMs": 1214, "applyResult": {...}},
    {"profile": "edge-b", "phase": "apply", "status": "ok", "durationMs": 1141, "applyResult": {...}},
    {"profile": "store-1", "phase": "apply", "status": "ok", "durationMs": 1083, "applyResult": {...}}
  ]
}
```

`applyResult` per profile is the same envelope shape that the single-profile path would have returned (e.g. `sophosfw.v1.firewallRulePush` for firewall rule push).

### 3.6 Exit codes

| Outcome | Exit code |
|---|---|
| All profiles succeeded (including dry-run-only mode if all pre-flights passed) | 0 |
| Pre-flight failed on any profile (no apply attempted) | 1 |
| Apply succeeded on some profiles but failed on at least one | 2 |
| Other error (config load, network catastrophic) | 3+ (existing) |

Distinct exit codes for pre-flight-failure (clean partial state — no mutation) vs apply-failure (some mutations landed) lets cron/CI react appropriately.

### 3.7 Confirmation

One `--yes` / `confirm: true` covers the entire fleet. Asking per-profile breaks automation without adding safety (the user already opted in to "mutate this set"). The tool description on each MCP mutating tool gains a sentence: "When `profileSet` is set, `confirm: true` authorizes mutation across ALL profiles in the set."

## 4. Data flow

```
sophosfw firewall rule push my-rule --profile-set production --expected-diff-hash <hash> --yes
  ↓
resolveTargetProfiles → [edge-a, edge-b, store-1]
  ↓
build FanoutOp closure (captures rule name, body source, expected-hash, dry-run flag)
  ↓
svc.Run(ctx, "firewall_rule_push", profiles, op, dryRunOnly=false)
  ↓ Phase 1: parallel
    op(edge-a, preflight=true)   →  dry-run XML envelope, no DoRaw
    op(edge-b, preflight=true)   →  ...
    op(store-1, preflight=true)  →  ...
  ↓ Phase 2 (only if all preflights OK): sequential
    op(edge-a, preflight=false)  →  DoRaw, mutation lands
    op(edge-b, preflight=false)  →  DoRaw
    op(store-1, preflight=false) →  DoRaw
  ↓
Render FanoutResult → human or JSON
  ↓
Exit code from Summary
```

## 5. Errors

No new sentinels:
- `sophos.ErrInvalidRequest` — `--profile` and `--profile-set` both set; unknown set name; empty set; member references non-existent profile; set name collides with profile name
- `sophos.ErrNotFound` — set or member doesn't exist
- Any underlying op error wraps through `FanoutProfileResult.Error` as the error message string (caller receives the FanoutResult; the error sentinel is preserved per-profile)

## 6. Testing strategy

### Unit tests

- `internal/config/config_test.go`:
  - `TestConfig_AddProfileSet_Persists`
  - `TestConfig_AddProfileSet_RejectsCollisionWithProfileName`
  - `TestConfig_AddProfileSet_RejectsMissingMember`
  - `TestConfig_RemoveProfileSet`
  - `TestConfig_ResolveProfileSet_BareName`
  - `TestConfig_ResolveProfileSet_CSV`
  - `TestConfig_ResolveProfileSet_SingleProfileName`
  - `TestConfig_ResolveProfileSet_UnknownErrors`

- `internal/svc/fanout_test.go`:
  - `TestFanout_AllPreflightOK_AppliesAll`
  - `TestFanout_PreflightFails_AbortsBeforeApply`
  - `TestFanout_ApplyFailsMidFleet_StopsAndMarksSkipped`
  - `TestFanout_DryRunOnlyMode_SkipsApply`
  - `TestFanout_PreflightRunsInParallel` (timing assertion: total preflight ≈ slowest, not sum)
  - `TestFanout_ApplyRunsSequentially` (timing assertion: total apply ≈ sum, not slowest)
  - `TestFanout_PreservesProfileOrder`

- `internal/cli/profileset_test.go`:
  - `TestResolveTargetProfiles_ProfileFlag`
  - `TestResolveTargetProfiles_ProfileSetFlag`
  - `TestResolveTargetProfiles_BothRejected`
  - `TestResolveTargetProfiles_DefaultsToActive`

- `internal/cli/profileset_mgmt_test.go` (new commands):
  - `TestCmd_AuthProfileSetAdd`, `_List`, `_Remove`

- `internal/render/fanout_test.go`:
  - `TestFanoutHumanText_TableShape`
  - `TestFanoutEnvelope_JSONShape`
  - `TestFanoutHumanText_ErrorReporting`
  - `TestFanoutHumanText_SkippedReporting`

- Per-affected mutating command: extend existing `*_mutation_test.go` with one test that exercises the `--profile-set` path. Pattern: use 2-profile fake set, assert both got the call.

- Per-affected MCP tool: extend existing `*_mutation_test.go` with handler test for `profileSet` arg.

### Integration tests (build-tagged, against testvm)

The user has only one testvm. Integration tests for fan-out require ≥2 profiles. Options:
- (a) Skip integration testing for fan-out until a second test target exists. Document that the path is unit-covered.
- (b) Use a second "profile" pointing at the same testvm with a different alias — exercises the resolver + orchestrator end-to-end but with degenerate fan-out (same firewall, called twice).

Recommend (b). Add `SOPHOSFW_TEST_PROFILE_2` env var to point at the second alias; tests skip if unset.

```go
func TestIntegration_Fanout_FirewallRulePushDryRun(t *testing.T) {
    // Requires SOPHOSFW_PROFILE and SOPHOSFW_TEST_PROFILE_2 set.
    // Builds a 2-profile set, runs firewall_rule_push --dry-run, asserts both pre-flights OK.
}
```

### Manual smoke

```bash
# Define a set
sophosfw auth profile set add staging testvm,testvm-alias

# Fan-out backup
sophosfw backup --profile-set staging

# Fan-out drift
sophosfw drift --profile-set staging --latest

# Fan-out push (dry-run first)
sophosfw firewall rule push my-rule --profile-set staging --expected-diff-hash <h> --yes --dry-run
```

## 7. Acceptance

- [ ] Config schema gains `profileSets`; load-time validation enforces allowlist + member existence + name collision check.
- [ ] `svc.Run` orchestrator passes all 7 unit tests including parallel-vs-sequential timing.
- [ ] Every Phase 6/10/12 mutating command + raw-request + backup + drift gains the `--profile-set` flag.
- [ ] `auth profile set add/list/remove` CLI sub-commands work.
- [ ] `auth_profile_set_list` MCP tool registered (tool count 51 → 52).
- [ ] Per-tool MCP `profileSet` field on every existing mutating tool + backup_create + drift_check.
- [ ] CLI default human output renders per-profile table; `--json` emits `sophosfw.v1.fanoutResult`.
- [ ] Exit codes: 0 (all OK), 1 (pre-flight failed), 2 (apply failed mid-fleet).
- [ ] At least one integration test passes against the testvm using a 2-profile set.
- [ ] `docs/api-coverage.md` unchanged (no API surface change to the firewall side). `docs/roadmap.md` updated.
- [ ] `v0.12.0` tagged + released; `brew upgrade sophosfw` reports 0.12.0.

## 8. Out of scope

- **`--parallel N` for apply phase.** Sequential-only in v1. Add later if real fleets push for it.
- **Cross-firewall comparison drift.** "Did firewall A and firewall B converge to the same state?" is a separate use case from "did firewall A drift from its own snapshot?" Defer.
- **Set management via MCP.** Agents can read sets (list) but cannot create/destroy them. Operator-controlled; CLI-only.
- **Bulk profile-add.** Adding 50 profiles to config is still a manual edit. A `sophosfw auth profile import <yaml-file>` is a separate convenience.
- **Per-profile credentials caching across fan-out.** Each profile loads its own credentials at op invocation time. No new caching layer.
- **Templated payloads.** `sophosfw firewall rule push --body @template.yaml.tmpl --profile-set production` with per-profile substitutions is interesting but adds templating engine dependency. Defer.
- **Set-of-sets / hierarchical groups.** A set named "everything" referencing `[production, staging]` is rejected by the validator (members must be profile names, not set names). Flat groups only.
- **Restore.** Not added in this phase (Phase 13's deferred restore stays deferred).

## 9. Risks

- **Pre-flight passing ≠ apply succeeding.** Network blip, rate limits, mid-window concurrent edit — apply can fail even after green pre-flight. Mitigation: documented in help text; result table makes the outcome unambiguous.
- **Sequential apply on a 50-firewall fleet is slow.** A 1-second apply across 50 firewalls = 50 seconds. Acceptable for `firewall rule push` cron; painful for one-off operator commands. `--parallel N` deferred to follow-up.
- **Set-name vs profile-name collision.** Validator rejects at config load time. Resolver disambiguates by checking sets first, then profiles. Document the precedence.
- **Stale `expectedDiffHash` across the fleet.** Each firewall has its own diff hash for "the same" rule. A single `--expected-diff-hash` value passed to fan-out cannot match all profiles' hashes simultaneously. **Mitigation**: when fan-out is detected (`len(profiles) > 1`), the `expectedDiffHash` flag becomes per-profile-resolved: pre-flight fetches each profile's current hash and treats `expected-diff-hash` as "expected to be SOME current hash" (i.e. the rule must exist on all targets), OR the user passes `--ignore-hash` to opt out. Spec: when profileSet is set AND expectedDiffHash is empty, the orchestrator pre-resolves per-profile hashes during pre-flight. Document.
- **Fail-fast leaves some mutated, some not.** This is the explicit cost of distributed-systems-aware fan-out. The result table is unambiguous; exit code 2 indicates partial state. Operators must reconcile manually. Don't try to roll back.
- **Profile sets in config drift from reality.** A set member might be removed from the profile list by another command. Validator catches at load (load fails) — but if config is hand-edited mid-session, the state is stale. Acceptable; fix by reload.

## 10. Decision log

- **Q1 — Fan-out attachment: config-level groups + per-command flag (option B).** Config-level groups solve repeated-fleet ergonomics; CSV flag covers ad-hoc; uniform across commands. Generic-wrapper command (option C) is too clever; per-command-only (option A) makes group reuse painful.
- **Q2 — Atomicity: pre-flight + sequential apply, fail-fast (option B).** Matches Terraform/Ansible plan-then-apply philosophy. Rollback intent (option C) adds complexity for marginal benefit; v1 punts to "operator reconciles partial state".
- **Q3 — Scope: mutating + backup + drift (option B).** Three high-value fleet workflows. Read-command aggregation produces ambiguous output (whose IPHost named "LAN"?); separate feature space.
- **Q4 — MCP exposure: per-tool `profileSet` field on existing mutating tools (Option 1).** No wrapper tools; consistent with existing patterns. New `auth_profile_set_list` (read-only) for agent discovery. Set management stays CLI-only.
- **Defaults**: one `--yes` / `confirm: true` covers the fleet; pre-flight parallel + apply sequential; per-profile result table by default + `--json`; exit codes 0/1/2 distinguishing all-OK / pre-flight-failed / mid-fleet-apply-failed; profile-set name collision with profile name rejected at load.
- **Release tag**: `v0.12.0` (minor bump — new user-visible config schema + flag surface; backwards-compatible).

## 11. References

- Existing config: `internal/config/config.go`
- Existing profile resolution: `internal/config/config.go::ActiveProfile`
- Existing per-command profile flag handling: `internal/cli/firewallrule_mutation.go` (or any of the Phase 12 _mutation files)
- Mutating MCP tool pattern: `internal/mcp/firewallrule_mutation.go`
- Backup orchestration (parallel-safe read-only fan-out precedent): `internal/svc/backup.go`
- Render envelope conventions: `internal/render/object_mutation.go`
- HandleError → exit code mapping: `internal/cli/errors.go` + `cmd/sophosfw/main.go`
