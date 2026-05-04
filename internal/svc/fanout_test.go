package svc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFanout_AllPreflightOK_AppliesAll(t *testing.T) {
	t.Parallel()
	profiles := []string{"a", "b", "c"}
	var preflightCalls, applyCalls int32
	op := func(_ context.Context, profile string, preflight bool) (any, error) {
		if preflight {
			atomic.AddInt32(&preflightCalls, 1)
			return "preflight-" + profile, nil
		}
		atomic.AddInt32(&applyCalls, 1)
		return "apply-" + profile, nil
	}

	res := Run(context.Background(), "test_op", profiles, op, false)

	if res == nil {
		t.Fatal("Run returned nil result")
	}
	if got := atomic.LoadInt32(&preflightCalls); got != 3 {
		t.Errorf("expected 3 preflight calls, got %d", got)
	}
	if got := atomic.LoadInt32(&applyCalls); got != 3 {
		t.Errorf("expected 3 apply calls, got %d", got)
	}
	if !res.PreflightOK {
		t.Error("expected PreflightOK=true")
	}
	if res.Aborted {
		t.Error("expected Aborted=false")
	}
	if !res.Mutating {
		t.Error("expected Mutating=true")
	}
	if res.Operation != "test_op" {
		t.Errorf("expected Operation=test_op, got %q", res.Operation)
	}
	if len(res.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(res.Results))
	}
	for i, r := range res.Results {
		if r.Profile != profiles[i] {
			t.Errorf("Results[%d].Profile=%q, want %q", i, r.Profile, profiles[i])
		}
		if r.Phase != "apply" {
			t.Errorf("Results[%d].Phase=%q, want apply", i, r.Phase)
		}
		if r.Status != "ok" {
			t.Errorf("Results[%d].Status=%q, want ok", i, r.Status)
		}
		if r.PreflightResult != "preflight-"+profiles[i] {
			t.Errorf("Results[%d].PreflightResult=%v, want preflight-%s", i, r.PreflightResult, profiles[i])
		}
		if r.ApplyResult != "apply-"+profiles[i] {
			t.Errorf("Results[%d].ApplyResult=%v, want apply-%s", i, r.ApplyResult, profiles[i])
		}
	}
	if res.EndedAt.Before(res.StartedAt) {
		t.Error("EndedAt before StartedAt")
	}
}

func TestFanout_PreflightFails_AbortsBeforeApply(t *testing.T) {
	t.Parallel()
	profiles := []string{"a", "b", "c"}
	var applyCalls int32
	op := func(_ context.Context, profile string, preflight bool) (any, error) {
		if !preflight {
			atomic.AddInt32(&applyCalls, 1)
			return nil, nil
		}
		if profile == "b" {
			return nil, errors.New("boom")
		}
		return "ok", nil
	}

	res := Run(context.Background(), "test_op", profiles, op, false)

	if got := atomic.LoadInt32(&applyCalls); got != 0 {
		t.Errorf("apply must not run when preflight fails, got %d apply calls", got)
	}
	if res.PreflightOK {
		t.Error("expected PreflightOK=false")
	}
	if !res.Aborted {
		t.Error("expected Aborted=true")
	}
	if res.Results[0].Status != "ok" || res.Results[0].Phase != "preflight" {
		t.Errorf("Results[0]: phase=%q status=%q, want preflight/ok", res.Results[0].Phase, res.Results[0].Status)
	}
	if res.Results[1].Status != "error" || res.Results[1].Phase != "preflight" {
		t.Errorf("Results[1]: phase=%q status=%q, want preflight/error", res.Results[1].Phase, res.Results[1].Status)
	}
	if res.Results[1].Error != "boom" {
		t.Errorf("Results[1].Error=%q, want boom", res.Results[1].Error)
	}
	if res.Results[2].Status != "ok" || res.Results[2].Phase != "preflight" {
		t.Errorf("Results[2]: phase=%q status=%q, want preflight/ok", res.Results[2].Phase, res.Results[2].Status)
	}
}

func TestFanout_ApplyFailsMidFleet_StopsAndMarksSkipped(t *testing.T) {
	t.Parallel()
	profiles := []string{"p1", "p2", "p3"}
	var applyCalls []string
	var mu sync.Mutex
	op := func(_ context.Context, profile string, preflight bool) (any, error) {
		if preflight {
			return "pf-" + profile, nil
		}
		mu.Lock()
		applyCalls = append(applyCalls, profile)
		mu.Unlock()
		if profile == "p2" {
			return nil, errors.New("apply failed")
		}
		return "applied-" + profile, nil
	}

	res := Run(context.Background(), "op", profiles, op, false)

	mu.Lock()
	calls := append([]string(nil), applyCalls...)
	mu.Unlock()
	if len(calls) != 2 || calls[0] != "p1" || calls[1] != "p2" {
		t.Errorf("apply call order wrong: got %v, want [p1 p2] (p3 must be skipped)", calls)
	}

	if res.Results[0].Phase != "apply" || res.Results[0].Status != "ok" {
		t.Errorf("Results[0]: phase=%q status=%q, want apply/ok", res.Results[0].Phase, res.Results[0].Status)
	}
	if res.Results[1].Phase != "apply" || res.Results[1].Status != "error" {
		t.Errorf("Results[1]: phase=%q status=%q, want apply/error", res.Results[1].Phase, res.Results[1].Status)
	}
	if res.Results[1].Error != "apply failed" {
		t.Errorf("Results[1].Error=%q, want 'apply failed'", res.Results[1].Error)
	}
	if res.Results[2].Phase != "skipped" || res.Results[2].Status != "skipped" {
		t.Errorf("Results[2]: phase=%q status=%q, want skipped/skipped", res.Results[2].Phase, res.Results[2].Status)
	}
	if res.Aborted {
		t.Error("Aborted should be false (apply phase started); only true on preflight abort")
	}
	if !res.PreflightOK {
		t.Error("expected PreflightOK=true (preflight passed for all)")
	}
}

func TestFanout_DryRunOnlyMode_SkipsApply(t *testing.T) {
	t.Parallel()
	profiles := []string{"a", "b"}
	var applyCalls int32
	op := func(_ context.Context, profile string, preflight bool) (any, error) {
		if !preflight {
			atomic.AddInt32(&applyCalls, 1)
		}
		return "pf-" + profile, nil
	}

	res := Run(context.Background(), "dry", profiles, op, true)

	if got := atomic.LoadInt32(&applyCalls); got != 0 {
		t.Errorf("dryRunOnly must skip apply phase, got %d apply calls", got)
	}
	if res.Mutating {
		t.Error("expected Mutating=false when dryRunOnly=true")
	}
	if !res.PreflightOK {
		t.Error("expected PreflightOK=true")
	}
	if res.Aborted {
		t.Error("Aborted should be false on successful dryRunOnly")
	}
	for i, r := range res.Results {
		if r.Phase != "preflight" {
			t.Errorf("Results[%d].Phase=%q, want preflight", i, r.Phase)
		}
		if r.Status != "ok" {
			t.Errorf("Results[%d].Status=%q, want ok", i, r.Status)
		}
	}
}

func TestFanout_PreflightRunsInParallel(t *testing.T) {
	t.Parallel()
	profiles := []string{"a", "b", "c"}
	const sleep = 200 * time.Millisecond
	op := func(_ context.Context, _ string, preflight bool) (any, error) {
		if preflight {
			time.Sleep(sleep)
		}
		return nil, nil
	}

	start := time.Now()
	res := Run(context.Background(), "op", profiles, op, true)
	elapsed := time.Since(start)

	// Parallel: ~200ms total, not 600ms. Allow generous slack to avoid CI flakes.
	if elapsed < 100*time.Millisecond {
		t.Errorf("preflight finished too fast (%v) — sleep not honored", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("preflight took %v — looks sequential (3x %v ≈ 600ms). expected parallel (~%v)", elapsed, sleep, sleep)
	}
	if !res.PreflightOK {
		t.Error("expected PreflightOK=true")
	}
}

func TestFanout_ApplyRunsSequentially(t *testing.T) {
	t.Parallel()
	profiles := []string{"a", "b", "c"}
	const sleep = 100 * time.Millisecond

	var inFlight int32
	var maxInFlight int32

	op := func(_ context.Context, _ string, preflight bool) (any, error) {
		if preflight {
			return nil, nil
		}
		cur := atomic.AddInt32(&inFlight, 1)
		// Track peak concurrency during apply phase.
		for {
			m := atomic.LoadInt32(&maxInFlight)
			if cur <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, cur) {
				break
			}
		}
		time.Sleep(sleep)
		atomic.AddInt32(&inFlight, -1)
		return nil, nil
	}

	start := time.Now()
	res := Run(context.Background(), "op", profiles, op, false)
	elapsed := time.Since(start)

	if got := atomic.LoadInt32(&maxInFlight); got != 1 {
		t.Errorf("apply phase concurrency=%d, want 1 (sequential)", got)
	}

	// Sequential apply of 3 ops at 100ms each ≈ 300ms; allow generous slack.
	if elapsed < 250*time.Millisecond {
		t.Errorf("apply finished too fast (%v) — looks parallel", elapsed)
	}
	if elapsed > 800*time.Millisecond {
		t.Errorf("apply took %v — unexpectedly slow", elapsed)
	}

	// StartedAt of each apply should be strictly increasing (each finishes
	// before next starts).
	for i := 1; i < len(res.Results); i++ {
		if !res.Results[i].StartedAt.After(res.Results[i-1].StartedAt) {
			t.Errorf("Results[%d].StartedAt (%v) not after Results[%d].StartedAt (%v)",
				i, res.Results[i].StartedAt, i-1, res.Results[i-1].StartedAt)
		}
	}
}

// TestFanout_Preflight_DoesNotRaceOnSharedBody is a smoke-test for
// the Phase 14 parallel-preflight race fix. The orchestrator runs
// N preflight goroutines in parallel; before the per-svc body-clone
// fix, the closures called delete(body, "_diffHash") on a shared
// caller map, which Go's runtime catches as "concurrent map writes".
//
// The real protection lives in the per-svc regression tests
// (TestX_Create_DoesNotMutateCallerBody) — those assert the body the
// caller passed in is unchanged. This test confirms the orchestrator
// itself isn't a source of races when callers do read-only access on
// a shared body map. Run under `go test -race -count=10` to catch
// regressions.
func TestFanout_Preflight_DoesNotRaceOnSharedBody(t *testing.T) {
	t.Parallel()
	body := map[string]any{
		"Name":      "shared",
		"_diffHash": "abc",
		"x":         1,
		"y":         2,
		"z":         3,
	}
	op := func(_ context.Context, _ string, _ bool) (any, error) {
		// Simulate the kind of body access the real svc layer does:
		// read fields. If the body were being mutated, we'd see a
		// runtime panic or inconsistent reads under -race.
		for k := range body {
			_ = body[k]
		}
		return nil, nil
	}
	profiles := []string{"a", "b", "c", "d", "e"}
	result := Run(context.Background(), "fanout_race_test", profiles, op, true)
	if !result.PreflightOK {
		t.Errorf("expected PreflightOK=true, got %+v", result)
	}
}

func TestFanout_PreservesProfileOrder(t *testing.T) {
	t.Parallel()
	profiles := []string{"c", "a", "b"}
	op := func(_ context.Context, profile string, _ bool) (any, error) {
		return profile, nil
	}

	res := Run(context.Background(), "op", profiles, op, false)

	if len(res.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(res.Results))
	}
	for i, want := range profiles {
		if res.Results[i].Profile != want {
			t.Errorf("Results[%d].Profile=%q, want %q (input order must be preserved)",
				i, res.Results[i].Profile, want)
		}
	}
	// Profiles slice on result also retains input order.
	for i, want := range profiles {
		if res.Profiles[i] != want {
			t.Errorf("Profiles[%d]=%q, want %q", i, res.Profiles[i], want)
		}
	}
}
