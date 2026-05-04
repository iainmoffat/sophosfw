// Package svc fan-out orchestrator.
//
// Run executes a per-profile operation across multiple Sophos Firewall profiles
// in two phases: parallel pre-flight (dry-run) followed by sequential apply with
// fail-fast semantics. The orchestrator is consumed by both the CLI's
// --profile-set flag and the MCP server's profileSet tool field; it always
// returns a *FanoutResult so callers can render a per-profile outcome table
// even when the apply phase is aborted.
package svc

import (
	"context"
	"sync"
	"time"
)

// FanoutOp is the per-profile operation closure invoked by Run.
//
// preflight=true means dry-run (validation / diff only); preflight=false means
// apply (mutating). The closure captures any operation-specific arguments
// (e.g. rule name, body source, expected-hash) and returns an opaque payload
// that Run stores in FanoutProfileResult.PreflightResult or .ApplyResult so
// callers can surface per-profile detail in the rendered output.
type FanoutOp func(ctx context.Context, profile string, preflight bool) (any, error)

// FanoutProfileResult is the per-profile outcome for one phase.
//
// When the apply phase replaces the pre-flight slot, PreflightResult is
// preserved alongside ApplyResult so callers can render both. Phase is
// "preflight" if Run aborted before apply, "apply" if the apply phase
// completed (success or error), or "skipped" if a trailing apply was
// short-circuited by an earlier failure.
type FanoutProfileResult struct {
	Profile         string
	Phase           string // "preflight" | "apply" | "skipped"
	Status          string // "ok" | "error" | "skipped"
	Error           string // populated when Status == "error"
	PreflightResult any    // populated on successful preflight
	ApplyResult     any    // populated on successful apply
	DurationMs      int64
	StartedAt       time.Time
}

// FanoutResult is the aggregate outcome for one Run invocation.
//
// Result is always returned (even on abort) so callers can render the
// per-profile table. Aborted=true means pre-flight failed and the apply phase
// was skipped entirely; Aborted=false with one or more apply-phase errors
// means apply ran and stopped on first failure with trailing profiles marked
// "skipped".
type FanoutResult struct {
	Operation   string
	Profiles    []string              // input profile list, ordered
	Mutating    bool                  // false if dryRunOnly requested
	PreflightOK bool                  // all preflights passed
	Aborted     bool                  // pre-flight failed and apply was skipped
	Results     []FanoutProfileResult // per-profile, in input order
	StartedAt   time.Time
	EndedAt     time.Time
}

// Run executes op against each profile in two phases.
//
// Phase 1 (parallel pre-flight): one goroutine per profile invokes
// op(ctx, profile, true). All goroutines run concurrently; Run waits for all
// to complete before evaluating pass/fail.
//
// Phase 2 (sequential apply): only entered when dryRunOnly=false and all
// pre-flights returned ok. Iterates profiles in input order, calling
// op(ctx, profile, false). On the first apply error, trailing profiles are
// marked Phase="skipped" / Status="skipped" and Run returns; their op is not
// called.
//
// dryRunOnly=true: pre-flight only; no apply phase. This is the natural
// shape for read-only fan-out (backup/drift), where preflight=true is the
// actual operation.
//
// dryRunOnly=false with a pre-flight failure: Aborted=true is set and Phase 2
// is skipped entirely.
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
			r := FanoutProfileResult{
				Profile:   profile,
				Phase:     "preflight",
				StartedAt: time.Now().UTC(),
			}
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
		result.Aborted = true
		result.EndedAt = time.Now().UTC()
		return result
	}

	// Phase 2: sequential apply with fail-fast.
	for i, profile := range profiles {
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
			// Mark trailing profiles as skipped.
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
