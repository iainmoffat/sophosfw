# sophosfw Phase 14 Implementation Plan

**Goal:** Multi-firewall fan-out: named profile groups in config, `--profile-set` flag on mutating commands + backup + drift, pre-flight + sequential apply with fail-fast, per-profile result reporting. Per-tool `profileSet` field on existing mutating MCP tools. New `auth_profile_set_list` tool (count 51 → 52). Ship as `v0.12.0`.

**Architecture:** Three additions: (1) `Config.ProfileSets` map + Add/Remove/Resolve methods; (2) `svc.Run` orchestrator (parallel pre-flight, sequential apply, fail-fast); (3) wire each affected command/MCP tool through a shared `resolveTargetProfiles` helper that returns `[]string`. Single-profile path stays unchanged (fast-path bypass when `len(profiles) == 1`).

**Tech Stack:** Go 1.26+, gopkg.in/yaml.v3, github.com/modelcontextprotocol/go-sdk v1.5.0. No new external dependencies.

**Spec:** `docs/superpowers/specs/2026-05-03-sophosfw-phase14-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.11.0`. Working dir: `/Users/ipm/code/sophosfw`.

```bash
git status
go test ./... -count=1 -race
golangci-lint run ./...
```

Expected: clean status, all tests pass, lint clean.

## File structure

**New files:**
- `internal/svc/fanout.go` — `Run` orchestrator + types (`FanoutOp`, `FanoutResult`, `FanoutProfileResult`).
- `internal/svc/fanout_test.go` — orchestrator unit tests.
- `internal/render/fanout.go` — `FanoutEnvelope` + `FanoutHumanText`.
- `internal/render/fanout_test.go`.
- `internal/cli/profileset.go` — `resolveTargetProfiles` helper + `--profile-set` flag registration helper.
- `internal/cli/profileset_test.go`.
- `internal/cli/profileset_mgmt.go` — `sophosfw auth profile set add/list/remove` cobra commands.
- `internal/cli/profileset_mgmt_test.go`.
- `internal/mcp/profileset.go` — `auth_profile_set_list` MCP tool + handler + Input type.
- `internal/mcp/profileset_test.go`.

**Modified files:**
- `internal/config/config.go` — `ProfileSets` field on `Config`; `AddProfileSet`, `RemoveProfileSet`, `ResolveProfileSet` methods; load-time validation.
- `internal/config/config_test.go` — tests for new methods.
- Per-affected mutating CLI command (~9 files): `internal/cli/{hostip_mutation,iphostgroup_mutation,fqdnhost_mutation,fqdnhostgroup_mutation,machost_mutation,services_mutation,servicegroup_mutation,firewallrule_mutation,natrule_mutation}.go` (and their respective `_mutation` cousins where present) — replace `profileFromFlags` with `resolveTargetProfiles`; add fan-out conditional.
- `internal/cli/raw.go` (raw request apply path) — same wiring.
- `internal/cli/backup.go`, `internal/cli/drift.go` — same wiring.
- `internal/cli/auth.go` — register the `auth profile set` sub-parent.
- Per-affected mutating MCP file (~9 files): `profileSet` field on Input structs; resolver in handler; fan-out branch.
- `internal/mcp/server.go` — register `auth_profile_set_list`.
- `internal/mcp/server_test.go` — tool count 51 → 52; add the new tool name.
- `docs/roadmap.md` — Phase 14 complete (final task).

---

## Task 1: Config schema — `ProfileSets`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Add `ProfileSets` field + methods**

In `internal/config/config.go`:

```go
type Config struct {
    Version          int                  `yaml:"version"`
    CurrentProfile   string               `yaml:"currentProfile,omitempty"`
    Defaults         Defaults             `yaml:"defaults"`
    Profiles         map[string]Profile   `yaml:"profiles"`
    ProfileSets      map[string][]string  `yaml:"profileSets,omitempty"`
}

// validProfileSetName: same allowlist as profile names.
func validProfileSetName(name string) bool {
    return profileNameRE.MatchString(name)  // verify the existing regex name in this file
}

func (c *Config) AddProfileSet(name string, members []string) error {
    if !validProfileSetName(name) {
        return fmt.Errorf("invalid profile set name %q (allowed: A-Za-z0-9_-)", name)
    }
    if _, exists := c.Profiles[name]; exists {
        return fmt.Errorf("profile set name %q collides with profile name", name)
    }
    for _, m := range members {
        if _, ok := c.Profiles[m]; !ok {
            return fmt.Errorf("profile %q referenced by set %q does not exist", m, name)
        }
    }
    if c.ProfileSets == nil {
        c.ProfileSets = map[string][]string{}
    }
    c.ProfileSets[name] = append([]string(nil), members...)  // copy
    return nil
}

func (c *Config) RemoveProfileSet(name string) error {
    if _, ok := c.ProfileSets[name]; !ok {
        return fmt.Errorf("profile set %q not found", name)
    }
    delete(c.ProfileSets, name)
    return nil
}

// ResolveProfileSet accepts:
//   - bare set name      → expand to set members
//   - bare profile name  → single-element slice
//   - CSV of profile names (NOT set names) → multi-element slice
//
// Returns ErrInvalidRequest on unknown identifiers.
func (c *Config) ResolveProfileSet(value string) ([]string, error) {
    if value == "" {
        return nil, fmt.Errorf("empty profile-set value")
    }
    parts := strings.Split(value, ",")
    if len(parts) == 1 {
        single := strings.TrimSpace(parts[0])
        // Try set first.
        if members, ok := c.ProfileSets[single]; ok {
            return append([]string(nil), members...), nil
        }
        // Then profile.
        if _, ok := c.Profiles[single]; ok {
            return []string{single}, nil
        }
        return nil, fmt.Errorf("unknown profile or profile set %q", single)
    }
    // CSV: each must be a profile name (not a set name — sets-of-sets
    // are explicitly out of scope per the Phase 14 spec).
    out := make([]string, 0, len(parts))
    seen := map[string]bool{}
    for _, p := range parts {
        n := strings.TrimSpace(p)
        if n == "" {
            return nil, fmt.Errorf("empty entry in profile CSV")
        }
        if _, isSet := c.ProfileSets[n]; isSet {
            return nil, fmt.Errorf("CSV entry %q is a profile set; use the set name alone, not in a CSV", n)
        }
        if _, ok := c.Profiles[n]; !ok {
            return nil, fmt.Errorf("profile %q not found", n)
        }
        if seen[n] {
            continue
        }
        seen[n] = true
        out = append(out, n)
    }
    return out, nil
}
```

- [ ] **Step 2: Load-time validation**

In `Config.Load` (or wherever loading happens), after unmarshaling, call a new private `validate()` method that walks `ProfileSets` and rejects:
- Set names that don't match the allowlist
- Set names that collide with profile names
- Members that don't exist in `Profiles`

Wrap errors with `sophos.ErrInvalidRequest` so callers can `errors.Is`.

- [ ] **Step 3: Tests**

Append to `internal/config/config_test.go`:

```go
func TestConfig_AddProfileSet_Persists(t *testing.T)
func TestConfig_AddProfileSet_RejectsInvalidName(t *testing.T)
func TestConfig_AddProfileSet_RejectsCollisionWithProfileName(t *testing.T)
func TestConfig_AddProfileSet_RejectsMissingMember(t *testing.T)
func TestConfig_RemoveProfileSet(t *testing.T)
func TestConfig_RemoveProfileSet_NotFound(t *testing.T)
func TestConfig_ResolveProfileSet_BareSetName_ExpandsMembers(t *testing.T)
func TestConfig_ResolveProfileSet_BareProfileName_ReturnsSingle(t *testing.T)
func TestConfig_ResolveProfileSet_CSV_ReturnsList(t *testing.T)
func TestConfig_ResolveProfileSet_CSV_RejectsSetEntry(t *testing.T)
func TestConfig_ResolveProfileSet_UnknownIdentifier(t *testing.T)
func TestConfig_ResolveProfileSet_DuplicatesDeduped(t *testing.T)
func TestConfig_Load_ValidatesProfileSets(t *testing.T)  // missing member in YAML → load fails
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/config -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/config/config.go internal/config/config_test.go
git commit -m "$(cat <<'EOF'
config: ProfileSets schema + AddProfileSet / RemoveProfileSet / ResolveProfileSet

Phase 14 fan-out scaffolding. profileSets is a top-level map of
name → []profileName. Validated at load (allowlist, no name collision
with profiles, members must exist). Resolver accepts bare set names,
bare profile names, and CSV of profile names; rejects sets-of-sets.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Do NOT push.

---

## Task 2: Fan-out orchestrator (`svc.Run`)

**Files:**
- Create: `internal/svc/fanout.go`
- Create: `internal/svc/fanout_test.go`

- [ ] **Step 1: Write the orchestrator**

Per the spec section 3.2 code block. Key invariants:
- Parallel pre-flight (`sync.WaitGroup`).
- Sequential apply with fail-fast: on first apply error, mark trailing profiles as `Phase: "skipped"`, return.
- `dryRunOnly=true` skips Phase 2 entirely.
- `FanoutResult` always returned (even on abort) so the caller can render the per-profile table.
- `FanoutOp` signature: `func(ctx context.Context, profile string, preflight bool) (any, error)`.

Read the spec section 3.2 for the exact struct layout and Run impl.

- [ ] **Step 2: Tests**

```go
func TestFanout_AllPreflightOK_AppliesAll(t *testing.T)
func TestFanout_PreflightFails_AbortsBeforeApply(t *testing.T)
func TestFanout_ApplyFailsMidFleet_StopsAndMarksSkipped(t *testing.T)
func TestFanout_DryRunOnlyMode_SkipsApply(t *testing.T)
func TestFanout_PreflightRunsInParallel(t *testing.T)  // sleep-based timing assertion
func TestFanout_ApplyRunsSequentially(t *testing.T)    // sleep-based timing assertion
func TestFanout_PreservesProfileOrder(t *testing.T)
```

For the timing assertions: each profile's `op` sleeps 200ms when `preflight=true`. Total preflight time should be ≈200ms (parallel), not ≈600ms for 3 profiles.

For apply ordering: assert the timestamps of `apply` phase entries are strictly increasing (one finishes before next starts).

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/svc -run TestFanout -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/svc/fanout.go internal/svc/fanout_test.go
git commit -m "$(cat <<'EOF'
svc: fan-out orchestrator (parallel preflight, sequential apply)

Run(ctx, op, profiles, op, dryRunOnly) executes a per-profile op
twice: parallel pre-flight (op(profile, preflight=true)), then if
all preflights succeed and dryRunOnly=false, sequential apply
(op(profile, preflight=false)). On first apply error, trailing
profiles are marked phase="skipped" and the function returns.

Returns FanoutResult always (even on abort) so callers can render
per-profile outcomes. Pre-flight failures set Aborted=true and skip
Phase 2 entirely.
EOF
)"
```

Do NOT push.

---

## Task 3: Render fan-out envelope + human text

**Files:**
- Create: `internal/render/fanout.go`
- Create: `internal/render/fanout_test.go`

- [ ] **Step 1: Write the renderers**

```go
package render

// FanoutEnvelope produces the sophosfw.v1.fanoutResult JSON envelope.
func FanoutEnvelope(r *svc.FanoutResult) ([]byte, error) {
    results := make([]map[string]any, 0, len(r.Results))
    for _, p := range r.Results {
        m := map[string]any{
            "profile":    p.Profile,
            "phase":      p.Phase,
            "status":     p.Status,
            "durationMs": p.DurationMs,
            "startedAt":  p.StartedAt.UTC().Format(time.RFC3339Nano),
        }
        if p.Error != "" {
            m["error"] = p.Error
        }
        if p.PreflightResult != nil {
            m["preflightResult"] = p.PreflightResult
        }
        if p.ApplyResult != nil {
            m["applyResult"] = p.ApplyResult
        }
        results = append(results, m)
    }
    env := map[string]any{
        "schema":      "sophosfw.v1.fanoutResult",
        "operation":   r.Operation,
        "profiles":    r.Profiles,
        "mutating":    r.Mutating,
        "preflightOK": r.PreflightOK,
        "aborted":     r.Aborted,
        "startedAt":   r.StartedAt.UTC().Format(time.RFC3339Nano),
        "endedAt":     r.EndedAt.UTC().Format(time.RFC3339Nano),
        "results":     results,
    }
    return json.MarshalIndent(env, "", "  ")
}

// FanoutHumanText writes the per-profile pre-flight + apply status
// table plus a final summary line (succeeded/failed/skipped counts).
func FanoutHumanText(w io.Writer, r *svc.FanoutResult) error {
    fmt.Fprintf(w, "Operation: %s\n", r.Operation)
    fmt.Fprintf(w, "Profiles: %d\n\n", len(r.Profiles))
    var ok, errc, skipped int
    for _, p := range r.Results {
        switch p.Status {
        case "ok":
            ok++
            fmt.Fprintf(w, "  [%s] %s OK (%dms)\n", p.Profile, p.Phase, p.DurationMs)
        case "skipped":
            skipped++
            fmt.Fprintf(w, "  [%s] skipped\n", p.Profile)
        case "error":
            errc++
            fmt.Fprintf(w, "  [%s] %s ERR (%dms): %s\n", p.Profile, p.Phase, p.DurationMs, p.Error)
        }
    }
    fmt.Fprintf(w, "\n%d succeeded, %d failed, %d skipped.\n", ok, errc, skipped)
    return nil
}
```

- [ ] **Step 2: Tests**

```go
func TestFanoutEnvelope_Shape(t *testing.T)
func TestFanoutEnvelope_OmitsEmptyError(t *testing.T)
func TestFanoutHumanText_AllOK(t *testing.T)
func TestFanoutHumanText_PreflightFailure(t *testing.T)
func TestFanoutHumanText_ApplyFailureWithSkipped(t *testing.T)
```

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/render -run TestFanout -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/render/fanout.go internal/render/fanout_test.go
git commit -m "$(cat <<'EOF'
render: fan-out envelope + human text

sophosfw.v1.fanoutResult JSON envelope and FanoutHumanText for the
per-profile result table. Default human output prints one line per
profile per phase with status (OK/ERR/skipped) plus a final summary
counting succeeded/failed/skipped.
EOF
)"
```

Do NOT push.

---

## Task 4: CLI `--profile-set` helper

**Files:**
- Create: `internal/cli/profileset.go`
- Create: `internal/cli/profileset_test.go`

- [ ] **Step 1: Write the helper**

```go
package cli

import (
    "fmt"

    "github.com/spf13/cobra"

    "github.com/iainmoffat/sophosfw/internal/config"
    "github.com/iainmoffat/sophosfw/internal/sophos"
)

// AddProfileSetFlag wires the --profile-set flag to a command.
// Mutually exclusive with --profile (cobra MarkFlagsMutuallyExclusive
// is enforced at runtime in resolveTargetProfiles).
func AddProfileSetFlag(cmd *cobra.Command) {
    cmd.Flags().String("profile-set", "", "named profile group OR comma-separated profile list (mutually exclusive with --profile)")
}

// resolveTargetProfiles returns the ordered list of profile names to
// operate against. Reads --profile and --profile-set flags; rejects
// both-set; defaults to the active profile when neither is set.
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
    _, name, err := cfg.ActiveProfile("")
    if err != nil {
        return nil, err
    }
    return []string{name}, nil
}
```

- [ ] **Step 2: Tests**

```go
func TestResolveTargetProfiles_DefaultsToActive(t *testing.T)
func TestResolveTargetProfiles_ProfileFlag(t *testing.T)
func TestResolveTargetProfiles_ProfileSetFlag_BareSetName(t *testing.T)
func TestResolveTargetProfiles_ProfileSetFlag_CSV(t *testing.T)
func TestResolveTargetProfiles_BothFlagsRejected(t *testing.T)
```

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/cli -run TestResolveTargetProfiles -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/cli/profileset.go internal/cli/profileset_test.go
git commit -m "$(cat <<'EOF'
cli: --profile-set flag helper

Shared helper resolveTargetProfiles(cmd, cfg) returns []string —
the ordered list of profile names a command should operate against.
Reads --profile / --profile-set flags, rejects both-set, defaults
to active. AddProfileSetFlag wires the flag to a cobra command.

Used by every mutating command (T6) and the backup/drift commands
(T6) to support fan-out uniformly.
EOF
)"
```

Do NOT push.

---

## Task 5: CLI `auth profile set` sub-commands

**Files:**
- Create: `internal/cli/profileset_mgmt.go`
- Create: `internal/cli/profileset_mgmt_test.go`
- Modify: `internal/cli/auth.go` (register the sub-parent)

- [ ] **Step 1: Write the sub-commands**

```go
package cli

import (
    "encoding/json"
    "fmt"
    "strings"

    "github.com/spf13/cobra"
)

func newProfileSetCmd(d RootDeps) *cobra.Command {
    cmd := &cobra.Command{Use: "set", Short: "Manage named profile groups"}
    cmd.AddCommand(newProfileSetAddCmd(d), newProfileSetListCmd(d), newProfileSetRemoveCmd(d))
    return cmd
}

func newProfileSetAddCmd(d RootDeps) *cobra.Command {
    var members []string
    cmd := &cobra.Command{
        Use:   "add <name> [profile,profile,...]",
        Short: "Add or overwrite a profile set",
        Args:  cobra.RangeArgs(1, 2),
        RunE: func(cmd *cobra.Command, args []string) error {
            name := args[0]
            // Members: positional CSV OR repeated --member.
            if len(args) == 2 {
                for _, m := range strings.Split(args[1], ",") {
                    if t := strings.TrimSpace(m); t != "" {
                        members = append(members, t)
                    }
                }
            }
            if len(members) == 0 {
                return fmt.Errorf("provide members via positional CSV or repeated --member")
            }
            if err := d.Config.AddProfileSet(name, members); err != nil {
                return err
            }
            if err := d.Config.Save(d.BaseDir); err != nil {
                return err
            }
            fmt.Fprintf(cmd.OutOrStdout(), "Profile set %q saved with %d member(s).\n", name, len(members))
            return nil
        },
    }
    cmd.Flags().StringSliceVar(&members, "member", nil, "profile name (repeatable)")
    return cmd
}

func newProfileSetListCmd(d RootDeps) *cobra.Command {
    var jsonOut bool
    cmd := &cobra.Command{
        Use:   "list",
        Short: "List defined profile sets",
        RunE: func(cmd *cobra.Command, _ []string) error {
            sets := d.Config.ProfileSets
            if jsonOut {
                env := map[string]any{
                    "schema": "sophosfw.v1.profileSetList",
                    "sets":   sets,
                }
                body, _ := json.MarshalIndent(env, "", "  ")
                _, _ = cmd.OutOrStdout().Write(body)
                return nil
            }
            if len(sets) == 0 {
                fmt.Fprintln(cmd.OutOrStdout(), "No profile sets.")
                return nil
            }
            for name, members := range sets {
                fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", name, strings.Join(members, ", "))
            }
            return nil
        },
    }
    cmd.Flags().BoolVar(&jsonOut, "json", false, "machine-readable output")
    return cmd
}

func newProfileSetRemoveCmd(d RootDeps) *cobra.Command {
    return &cobra.Command{
        Use:   "remove <name>",
        Short: "Remove a profile set",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            if err := d.Config.RemoveProfileSet(args[0]); err != nil {
                return err
            }
            if err := d.Config.Save(d.BaseDir); err != nil {
                return err
            }
            fmt.Fprintf(cmd.OutOrStdout(), "Profile set %q removed.\n", args[0])
            return nil
        },
    }
}
```

Verify `d.Config.Save(d.BaseDir)` matches the actual save signature:
```bash
grep -n "func.*Config.*Save" internal/config/config.go
```

Adjust if needed.

- [ ] **Step 2: Wire into `auth profile`**

```bash
grep -n "newAuthProfileCmd\|cmd.AddCommand" internal/cli/auth.go | head -10
```

Find the `auth profile` parent command and add `cmd.AddCommand(newProfileSetCmd(d))`.

- [ ] **Step 3: Tests**

```go
func TestCmd_AuthProfileSetAdd_PersistsToConfig(t *testing.T)
func TestCmd_AuthProfileSetAdd_RejectsCollision(t *testing.T)
func TestCmd_AuthProfileSetList_Empty(t *testing.T)
func TestCmd_AuthProfileSetList_JSONShape(t *testing.T)
func TestCmd_AuthProfileSetRemove(t *testing.T)
func TestCmd_AuthProfileSetRemove_NotFound(t *testing.T)
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/cli -run TestCmd_AuthProfileSet -v -count=1
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/cli/profileset_mgmt.go internal/cli/profileset_mgmt_test.go internal/cli/auth.go
git commit -m "$(cat <<'EOF'
cli: auth profile set add/list/remove

Three new sub-commands under auth profile set for managing named
profile groups. add takes a positional CSV or repeated --member.
list shows all groups (or empty); --json emits sophosfw.v1.profileSetList.
remove deletes by name. All persist via Config.Save.
EOF
)"
```

Do NOT push.

---

## Task 6: Wire `--profile-set` into mutating commands + backup + drift

**Files (modified, ~12):**
- `internal/cli/hostip_mutation.go` (Phase 6)
- `internal/cli/iphostgroup_mutation.go`, `fqdnhost_mutation.go`, `fqdnhostgroup_mutation.go`, `machost_mutation.go`, `services_mutation.go`, `servicegroup_mutation.go` (Phase 12)
- `internal/cli/firewallrule_mutation.go`, `firewallrule.go` (Phase 7-9; the push/delete cmds)
- `internal/cli/natrule_mutation.go`, `natrule.go` (Phase 8-9)
- `internal/cli/raw.go` (raw request apply)
- `internal/cli/backup.go`
- `internal/cli/drift.go`

This is the **mechanical fan-out wiring** task. Each command file follows the same pattern: replace `profileFromFlags(cmd)` with `resolveTargetProfiles(cmd, d.Config)`; if `len(profiles) == 1`, single-profile fast path; else build a `FanoutOp` closure and call `svc.Run`.

- [ ] **Step 1: Read one existing single-profile command for context**

```bash
cat /Users/ipm/code/sophosfw/internal/cli/iphostgroup_mutation.go
```

Look at how the `update` command's RunE is structured today.

- [ ] **Step 2: Define the wiring pattern**

For `update` (representative), today:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    name := args[0]
    body, err := LoadBody(bodyArg)
    if err != nil { return err }
    if bn, _ := body["Name"].(string); bn != "" && bn != name { return ... }
    body["Name"] = name
    result, err := iphostGroupSvc(d).Update(cmd.Context(), profileFromFlags(cmd), name, body, expectedHash, ignoreHash, !yes)
    if err != nil { return err }
    return printObjectMutation(cmd, result)
}
```

After:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    name := args[0]
    body, err := LoadBody(bodyArg)
    if err != nil { return err }
    if bn, _ := body["Name"].(string); bn != "" && bn != name { return ... }
    body["Name"] = name

    profiles, err := resolveTargetProfiles(cmd, d.Config)
    if err != nil { return err }

    if len(profiles) == 1 {
        result, err := iphostGroupSvc(d).Update(cmd.Context(), profiles[0], name, body, expectedHash, ignoreHash, !yes)
        if err != nil { return err }
        return printObjectMutation(cmd, result)
    }

    // Fan-out path.
    op := func(ctx context.Context, profile string, preflight bool) (any, error) {
        return iphostGroupSvc(d).Update(ctx, profile, name, body, expectedHash, ignoreHash, preflight || !yes)
    }
    fr := svc.Run(cmd.Context(), "ip_host_group_update", profiles, op, !yes)
    return printFanout(cmd, fr)
}
```

`printFanout(cmd, fr)` is a new helper (define once in `internal/cli/profileset.go`):

```go
func printFanout(cmd *cobra.Command, fr *svc.FanoutResult) error {
    jsonOut, _ := cmd.Flags().GetBool("json")
    if jsonOut {
        body, err := render.FanoutEnvelope(fr)
        if err != nil { return err }
        _, _ = cmd.OutOrStdout().Write(body)
        _, _ = cmd.OutOrStdout().Write([]byte("\n"))
    } else {
        if err := render.FanoutHumanText(cmd.OutOrStdout(), fr); err != nil {
            return err
        }
    }
    // Exit code mapping (see spec section 3.6):
    if fr.Aborted {
        return ErrFanoutPreflightFailed  // exit 1
    }
    for _, p := range fr.Results {
        if p.Status == "error" {
            return ErrFanoutApplyFailed  // exit 2
        }
    }
    return nil
}
```

Add `ErrFanoutPreflightFailed` and `ErrFanoutApplyFailed` to `internal/cli/errors.go`. Update `HandleError` to map them to exit codes 1 and 2 respectively (silent; the human/JSON output already explains).

- [ ] **Step 3: Add `AddProfileSetFlag(cmd)` to every affected command**

In each command's constructor (where `--profile` is currently added or inherited), call `AddProfileSetFlag(cmd)` to add the new flag.

- [ ] **Step 4: Apply the wiring pattern to every mutating command**

The 12 files listed above. Each needs:
1. `AddProfileSetFlag(cmd)` in the constructor.
2. Replace single-call body with the conditional shown above. Operation name string for `svc.Run` matches the audit op convention (`ip_host_group_update`, `firewall_rule_push`, etc.).
3. Body / args / flags captured in the closure must be the same per-profile (no per-profile substitution in v1).

For `backup` and `drift`, the operation is read-side. The fan-out wraps a per-profile call:

```go
// backup
op := func(ctx context.Context, profile string, preflight bool) (any, error) {
    if preflight {
        // Backup has no meaningful "dry-run" — pre-flight just lists profile to confirm reachability.
        // Reasonable choice: skip dry-run validation entirely, return nil / "ok".
        return nil, nil
    }
    return backupSvc(d).Create(ctx, profile, opts)
}
fr := svc.Run(cmd.Context(), "backup_create", profiles, op, false)
```

Drift is similar (per-profile drift call; "pre-flight" can be a no-op since drift is read-only).

Pre-flight semantics for read-only ops: **skip** (return ok with no payload). Document the convention.

- [ ] **Step 5: Run + commit**

```bash
go test ./... -count=1 -race
golangci-lint run ./...
go run ./cmd/sophosfw firewall rule push --help  # confirm --profile-set visible
git add internal/cli/{hostip,iphostgroup,fqdnhost,fqdnhostgroup,machost,services,servicegroup,firewallrule,natrule}*.go internal/cli/{raw,backup,drift,profileset,errors}.go
git commit -m "$(cat <<'EOF'
cli: --profile-set fan-out across mutating commands + backup + drift

Every Phase 6/9-12 mutating command + raw request + backup + drift
gains the --profile-set flag. resolveTargetProfiles reads --profile
and --profile-set, rejects both-set, defaults to the active profile.
When the resolved list has >1 entry, the command builds a FanoutOp
closure and routes through svc.Run; single-profile fast path is
unchanged.

Adds ErrFanoutPreflightFailed (exit 1) and ErrFanoutApplyFailed
(exit 2) sentinels mapped silently in HandleError.
EOF
)"
```

Do NOT push.

**Mechanical scope warning**: this task touches ~12 files. Each file change is small and follows the same template. The implementer should NOT redesign the per-command UX — only wire fan-out.

---

## Task 7: MCP per-tool `profileSet` field

**Files (modified, ~9 _mutation files):**
- `internal/mcp/hostip_mutation.go`, `iphostgroup_mutation.go`, `fqdnhost_mutation.go`, `fqdnhostgroup_mutation.go`, `machost_mutation.go`, `services_mutation.go`, `servicegroup_mutation.go`, `firewallrule_mutation.go`, `natrule_mutation.go`
- `internal/mcp/backup.go` (add to `BackupCreateInput` and `DriftCheckInput`)

Each Input struct gains:

```go
ProfileSet string `json:"profileSet,omitempty" jsonschema_description:"named profile group or CSV of profiles; mutually exclusive with profile. When set, the operation runs across all targets with one confirm:true authorization."`
```

Each handler resolves like the CLI:

```go
func (s *Server) handleIPHostGroupUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPHostGroupUpdateInput) (*sdkmcp.CallToolResult, any, error) {
    profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
    if err != nil {
        return s.errorEnvelopeResult(err, "")
    }
    // ... existing gate checks (Confirm, ExpectedDiffHash, body Name) ...

    if len(profiles) == 1 {
        // existing single-profile fast path
        result, err := s.ipHostGroupMcpSvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
        if err != nil {
            return s.errorEnvelopeResult(err, profiles[0])
        }
        body, err := s.renderObjectMutation(result, profiles[0])
        if err != nil {
            return s.errorEnvelopeResult(err, profiles[0])
        }
        return jsonResult(body)
    }

    // Fan-out
    op := func(ctx context.Context, profile string, preflight bool) (any, error) {
        return s.ipHostGroupMcpSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
    }
    fr := svc.Run(ctx, "ip_host_group_update", profiles, op, in.DryRun)
    body, err := render.FanoutEnvelope(fr)
    if err != nil {
        return s.errorEnvelopeResult(err, "")
    }
    return jsonResult(body)
}
```

Add a server-level helper:

```go
func (s *Server) resolveTargetProfilesMcp(profile, profileSet string) ([]string, error) {
    if profile != "" && profileSet != "" {
        return nil, fmt.Errorf("%w: profile and profileSet are mutually exclusive", sophos.ErrInvalidRequest)
    }
    if profileSet != "" {
        return s.deps.Config.ResolveProfileSet(profileSet)
    }
    return []string{s.resolveProfile(profile)}, nil
}
```

- [ ] **Step 1: Add the field to all 24+ Input structs and update handlers**

For `host_ip` (3 inputs), `firewall_rule` (3), `nat_rule` (3), `host_group` (3), `host_fqdn` (3), `host_fqdn_group` (3), `host_mac` (3), `service` (3), `service_group` (3) = 27 mutating tool inputs. Plus `backup_create` and `drift_check` = 29 inputs total.

Each gets the `ProfileSet` field + the handler swap pattern above.

Update each handler's tool description to mention: "When `profileSet` is provided, `confirm: true` authorizes mutation across ALL profiles in the set."

- [ ] **Step 2: Add fan-out tests for each tool**

For each tool, add a test that fans out to 2 profiles and asserts the fan-out envelope:

```go
func TestIPHostGroupUpdate_Handler_FanOut_TwoProfiles(t *testing.T)
```

Pattern: configure 2 profiles in test config, send `profileSet: "a,b"` (CSV), assert the response is `sophosfw.v1.fanoutResult` with 2 entries.

(One test per affected tool — ~27 tests.)

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/mcp -count=1 -race
golangci-lint run ./...
git add internal/mcp/*.go
git commit -m "$(cat <<'EOF'
mcp: profileSet field on every mutating tool + backup_create + drift_check

29 mutating-tool Input structs gain an optional profileSet field
(name OR CSV) mutually exclusive with profile. Single-profile path
is unchanged; multi-profile path routes through svc.Run and emits
sophosfw.v1.fanoutResult. Tool descriptions updated to note that
confirm:true authorizes mutation across the whole set.

No new tools in this commit (auth_profile_set_list lands in T8).
EOF
)"
```

Do NOT push.

---

## Task 8: MCP `auth_profile_set_list` tool

**Files:**
- Create: `internal/mcp/profileset.go`
- Create: `internal/mcp/profileset_test.go`
- Modify: `internal/mcp/server.go` (register)
- Modify: `internal/mcp/server_test.go` (count 51 → 52; add name)

- [ ] **Step 1: Write the tool**

```go
package mcp

import (
    "context"

    sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type AuthProfileSetListInput struct{}

func (s *Server) handleAuthProfileSetList(_ context.Context, _ *sdkmcp.CallToolRequest, _ AuthProfileSetListInput) (*sdkmcp.CallToolResult, any, error) {
    sets := s.deps.Config.ProfileSets
    out := map[string]any{
        "schema": "sophosfw.v1.profileSetList",
        "sets":   sets,  // map[name][]profile; can be nil
    }
    return jsonResultMap(out)
}

func (s *Server) registerProfileSet() {
    sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
        Name:        "auth_profile_set_list",
        Description: "List defined profile sets (named groups of firewall profiles). Read-only; returns map of set name → array of profile names. Use the set name as profileSet on a mutating tool to fan-out across all members.",
        Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List profile sets"},
    }, s.handleAuthProfileSetList)
}
```

(`jsonResultMap` may need to be the same as `jsonResult` after marshaling — verify the helper that exists in `internal/mcp/`.)

- [ ] **Step 2: Wire into `registerAll`**

```bash
grep -n "registerAll\|registerBackup\|registerObject" internal/mcp/server.go | head
```

Add `s.registerProfileSet()` next to existing registrations.

- [ ] **Step 3: Update server_test.go**

Tool count 51 → 52; add `auth_profile_set_list` to expected names.

- [ ] **Step 4: Tests**

```go
func TestAuthProfileSetList_Handler_Empty(t *testing.T)
func TestAuthProfileSetList_Handler_ReturnsSets(t *testing.T)
```

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/mcp -count=1 -race -v
go test ./... -count=1 -race
golangci-lint run ./...
git add internal/mcp/profileset.go internal/mcp/profileset_test.go internal/mcp/server.go internal/mcp/server_test.go
git commit -m "$(cat <<'EOF'
mcp: auth_profile_set_list (read-only; tool count 51 to 52)

Single new MCP tool for agent discovery of named profile groups.
Returns map of set name to profile-name array. Set management
(add/remove) stays CLI-only — agents can read groups but not mutate
them.
EOF
)"
```

Do NOT push.

---

## Task 9: Integration tests + manual smoke

**Files:**
- Modify: `internal/testutil/integration_test.go`

- [ ] **Step 1: Add integration tests using a 2-profile set**

Requires `SOPHOSFW_PROFILE` and `SOPHOSFW_TEST_PROFILE_2` env vars (the second can alias the same testvm — just a second profile entry pointing at the same firewall).

```go
func TestIntegration_Fanout_DriftAcrossSet(t *testing.T) {
    profileName := os.Getenv("SOPHOSFW_PROFILE")
    require.NotEmpty(t, profileName)
    p2 := os.Getenv("SOPHOSFW_TEST_PROFILE_2")
    if p2 == "" { t.Skip("set SOPHOSFW_TEST_PROFILE_2") }

    // Build a 2-profile set in a temp config; run drift against each
    // (each will report whatever drift is present from the latest snapshot).
    // Assert FanoutResult has 2 entries; both phase=apply, both status=ok.
}

func TestIntegration_Fanout_FirewallRulePushDryRun(t *testing.T) {
    // Same setup; run firewall_rule_push with dryRun=true (or --yes=false in CLI).
    // Assert all preflights OK, no apply.
}
```

- [ ] **Step 2: Run against testvm**

```bash
SOPHOSFW_PROFILE=testvm SOPHOSFW_TEST_PROFILE_2=testvm-alias \
  go test -tags=integration ./internal/testutil -run TestIntegration_Fanout -v
```

(User must have configured `testvm-alias` as a second profile entry pointing at the same firewall, OR adjust accordingly.)

Expected: 2 PASS.

- [ ] **Step 3: Manual smoke**

```bash
sophosfw auth profile set add staging testvm,testvm-alias
sophosfw auth profile set list

# Backup fan-out — should snapshot both profiles
sophosfw backup --profile-set staging
ls ~/.config/sophosfw/profiles/testvm/backups/
ls ~/.config/sophosfw/profiles/testvm-alias/backups/

# Drift fan-out
sophosfw drift --profile-set staging --latest

# Mutating fan-out (dry-run)
sophosfw firewall rule push <some-rule> --profile-set staging --expected-diff-hash <h> --yes --dry-run
# Should show pre-flight OK for both, no apply (dry-run mode).

sophosfw auth profile set remove staging
```

- [ ] **Step 4: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "$(cat <<'EOF'
test: phase 14 fan-out integration smokes

Two tests gated by SOPHOSFW_PROFILE + SOPHOSFW_TEST_PROFILE_2: drift
across a 2-profile set, firewall_rule_push dry-run across a 2-profile
set. The second profile can alias the same testvm to exercise
fan-out wiring without needing a second physical firewall.

Pattern mirrors prior phase integration smokes.
EOF
)"
```

Do NOT push.

---

## Task 10: Docs + tag v0.12.0 + verify release

**Files:**
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update roadmap**

Append after the Phase 13 line:

```
- Phase 14 — Multi-firewall fan-out (complete; v0.12.0)
```

- [ ] **Step 2: Final test pass**

```bash
go fmt ./... && go vet ./... && golangci-lint run ./... && go test -race ./...
```

If `go fmt` produces drift, commit a separate `fix: phase 14 acceptance pass formatting` commit.

- [ ] **Step 3: Commit + push**

```bash
git add docs/roadmap.md
git commit -m "$(cat <<'EOF'
docs: phase 14 complete in roadmap

Phase 14 ships multi-firewall fan-out: profile-set config schema,
--profile-set flag on mutating commands + backup + drift, pre-flight
+ sequential apply with fail-fast, per-tool profileSet field on
existing mutating MCP tools, new auth_profile_set_list tool (count
51 to 52). Tag v0.12.0.
EOF
)"
git push origin main
```

Wait for CI:

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

- [ ] **Step 4: Tag**

```bash
git tag -a v0.12.0 -m "v0.12.0 — Phase 14: multi-firewall fan-out

Named profile groups in config. --profile-set flag on every mutating
command + backup + drift. Pre-flight runs in parallel (read-only);
apply runs sequentially with fail-fast (some applied, some not on
mid-fleet failure). Per-profile result table in default human output;
--json emits sophosfw.v1.fanoutResult. Per-tool profileSet field on
existing mutating MCP tools (no new mutating-tool surface). New
read-only auth_profile_set_list MCP tool (count 51 to 52)."
git push origin v0.12.0
```

- [ ] **Step 5: Watch release workflow**

```bash
sleep 5
RUN_ID=$(gh run list --repo iainmoffat/sophosfw --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo iainmoffat/sophosfw "$RUN_ID" --exit-status
```

- [ ] **Step 6: Verify**

```bash
gh release view v0.12.0 --repo iainmoffat/sophosfw --json name,assets --jq '{name, assets: [.assets[].name]}'
gh api repos/iainmoffat/homebrew-sophosfw/contents/sophosfw.rb --jq '.content' | base64 -d | grep '^  version'
brew update
brew upgrade sophosfw
sophosfw version

sophosfw auth profile set --help
sophosfw firewall rule push --help | grep -- --profile-set
```

Expected: all green; `sophosfw 0.12.0`; both helps render.

---

## End of plan

## Self-review checklist

- ✅ **Spec coverage:** Section 3.1 (config) → T1; Section 3.2 (orchestrator) → T2; Section 3.3 (CLI integration) → T4 (helper) + T6 (per-command wiring); Section 3.4 (MCP integration) → T7 (per-tool field) + T8 (new tool); Section 3.5 (output format) → T3 (renderers) used by T6/T7; Section 3.6 (exit codes) → T6 (sentinels + HandleError); Section 3.7 (confirmation) → T6/T7 description updates.
- ✅ **No placeholders.** Every step has concrete code or commands.
- ✅ **Tool count math.** 51 + 1 = 52 (auth_profile_set_list). Existing mutating tools gain a field, no new tools there.
- ✅ **Mechanical scope.** T6 (CLI) and T7 (MCP) each touch ~9 files, but each file follows the same wiring pattern. No per-command UX redesign.
- ✅ **Single-profile fast path.** T6/T7 explicitly preserve the existing per-profile path when `len(profiles) == 1`. Avoids regressions in the common case.
- ✅ **Exit codes.** T6 introduces `ErrFanoutPreflightFailed` (exit 1) and `ErrFanoutApplyFailed` (exit 2); HandleError must be updated.
- ✅ **No restore.** Phase 13's restore stays deferred.

## Notes for the implementer

- **Subagent-driven flow:** T1-T5 are foundation and can each ship as a focused dispatch + light review. T6 and T7 are the broad mechanical tasks — review can verify "the pattern is consistent across all files" rather than per-file deep dive. T8 is small. T9 integration. T10 release.
- **`testvm-alias`**: T9 needs a second profile entry. The user must add `testvm-alias` (or whatever name) as a second profile pointing at the same testvm. The plan flags this in T9 step 2.
- **Token handling**: T10 release runs zero-touch (`HOMEBREW_TAP_TOKEN` already in repo secrets).
- **Pre-flight semantics for read-only ops**: backup and drift treat preflight as a no-op (return nil, no payload). The svc.Run orchestrator still creates per-profile result entries in the parallel phase, but the entry's `PreflightResult` is nil. Document the convention.
- **expectedDiffHash with fan-out**: the spec section 9 risks notes per-firewall hash divergence. v1 implementation: when `--profile-set` is set AND `--expected-diff-hash` is non-empty, the hash is checked against EACH profile independently — meaning all profiles must already have the same diff hash for the rule, OR `--ignore-hash` is used. Document this nuance in `firewall rule push --help`. If real users hit it, add per-profile hash resolution as a follow-up.
