# Phase 11 — CI/CD + release polish (design)

**Date:** 2026-05-03
**Status:** Design (pre-implementation)
**Goal:** Mirror the `iainmoffat/tdx` GitHub Actions pattern, add the small polish items tdx doesn't have, and ship the result as `v0.9.1`.

---

## 1. Motivation

Phases 0-10 left sophosfw functionally complete through Phase 10 (MCP-native firewall + NAT rule mutations). Releases work, but the loop is manual:

- Tests run only on the developer's machine.
- Releases require remembering `HOMEBREW_TAP_TOKEN=... goreleaser release --clean` locally.
- The README still says "not yet published".
- There is no LICENSE file despite the repo being public.
- Releases ship binaries only — no shell completions, no LICENSE in the tarball.

Phase 11 closes those gaps. It is intentionally **mechanical and small**: copy a known-working pattern (tdx), add the polish that tdx lacks, ship.

## 2. Architecture

Two GitHub Actions workflows + four small repo-level files + a few `.goreleaser.yaml` extensions. Nothing new in `internal/`. No production code change.

Total new artifacts:
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `.github/dependabot.yml`
- `.golangci.yml`
- `LICENSE`
- (release-time only, not committed) `completions/sophosfw.{bash,zsh,fish}`

Modified:
- `.goreleaser.yaml`
- `README.md`
- `Makefile` (one new target — `make completions`)
- (none under `internal/` or `cmd/`)

## 3. Components

### 3.1 CI workflow

**File:** `.github/workflows/ci.yml`

Mirrors `iainmoffat/tdx/.github/workflows/ci.yml` with the only change being the build target (`./cmd/sophosfw` instead of `./cmd/tdx`).

```yaml
name: CI

on:
  push:
    branches: ['*']
  pull_request:

jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Vet
        run: go vet ./...
      - name: Lint
        uses: golangci/golangci-lint-action@v7
        with:
          version: v2.11.4
      - name: Test
        run: go test ./... -count=1 -race
      - name: Build
        run: go build ./cmd/sophosfw
```

**Behavior:**
- Runs on every push to any branch and every PR.
- No integration tests run (gated by `//go:build integration` — they need the testvm, which CI cannot reach).
- Fails fast on any step failure → red PR.

### 3.2 Release workflow

**File:** `.github/workflows/release.yml`

Mirror of `iainmoffat/tdx/.github/workflows/release.yml`.

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - uses: goreleaser/goreleaser-action@v6
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          HOMEBREW_TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
```

**Behavior:**
- Triggered only by pushing a tag matching `v*`.
- Uses goreleaser-action@v6 with `release --clean`.
- Pulls `HOMEBREW_TAP_TOKEN` from GitHub Actions repo secrets — operator must add it once before first CI release.
- The local `goreleaser release --clean` flow continues to work unchanged.

### 3.3 golangci-lint config

**File:** `.golangci.yml`

Mirror of tdx's config. Conservative linter set — avoids the high-noise linters (gocyclo, dupl, lll, etc.) that don't pull weight.

```yaml
version: "2"

linters:
  default: none
  enable:
    - govet
    - errcheck
    - staticcheck
    - unused
    - ineffassign
  settings:
    errcheck:
      check-type-assertions: true

formatters:
  enable:
    - gofmt
```

### 3.4 Dependabot config

**File:** `.github/dependabot.yml`

Two ecosystems, weekly schedule, grouped minor+patch updates per ecosystem to limit PR noise.

```yaml
version: 2
updates:
  - package-ecosystem: gomod
    directory: "/"
    schedule:
      interval: weekly
    groups:
      go-deps:
        patterns: ["*"]
        update-types: [minor, patch]
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
    groups:
      gha:
        patterns: ["*"]
        update-types: [minor, patch]
```

Major-version bumps land as separate PRs (per Dependabot default).

### 3.5 LICENSE

**File:** `LICENSE`

Standard MIT license. Holder: "Iain Moffat". Year: 2026.

```
MIT License

Copyright (c) 2026 Iain Moffat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 3.6 Completion script generation

Cobra already exposes `sophosfw completion <bash|zsh|fish|powershell>`. The release pipeline must:

1. Build the binary (or use `go run`).
2. Generate `completions/sophosfw.bash`, `completions/sophosfw.zsh`, `completions/sophosfw.fish`.
3. Bundle them in each archive at the path `completions/`.
4. Have the brew formula install them into the right shell paths.

**Implementation in `.goreleaser.yaml`:**

```yaml
before:
  hooks:
    - go mod tidy
    - bash -c 'mkdir -p completions && go run ./cmd/sophosfw completion bash > completions/sophosfw.bash && go run ./cmd/sophosfw completion zsh > completions/sophosfw.zsh && go run ./cmd/sophosfw completion fish > completions/sophosfw.fish'
```

**Archive content extension:**

```yaml
archives:
  - formats: [tar.gz]
    name_template: "sophosfw_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    files:
      - LICENSE
      - completions/*
```

**Brew formula extension:**

```yaml
brews:
  - repository:
      owner: iainmoffat
      name: homebrew-sophosfw
      token: "{{ .Env.HOMEBREW_TAP_TOKEN }}"
    homepage: https://github.com/iainmoffat/sophosfw
    description: CLI and MCP server for the Sophos Firewall API
    license: MIT
    install: |
      bin.install "sophosfw"
      bash_completion.install "completions/sophosfw.bash" => "sophosfw"
      zsh_completion.install "completions/sophosfw.zsh" => "_sophosfw"
      fish_completion.install "completions/sophosfw.fish"
```

**Local convenience target in `Makefile`:**

```makefile
completions: build
	mkdir -p completions
	$(BIN) completion bash > completions/sophosfw.bash
	$(BIN) completion zsh > completions/sophosfw.zsh
	$(BIN) completion fish > completions/sophosfw.fish
```

The `completions/` directory is gitignored (build artifact) — add to `.gitignore`.

### 3.7 README update

**File:** `README.md`

- Replace the "Foundation phase" status paragraph with a refresh that reflects Phases 0-10 complete and Phase 11 in flight.
- Replace the `git clone ... # not yet published` install block with a `brew install iainmoffat/sophosfw/sophosfw` block as the primary path; keep `go install` as the from-source alternative.
- Add three badges at the top of the file (immediately after the `# sophosfw` heading):
  - CI: `https://github.com/iainmoffat/sophosfw/actions/workflows/ci.yml/badge.svg`
  - Latest release: `https://img.shields.io/github/v/release/iainmoffat/sophosfw`
  - License: `https://img.shields.io/github/license/iainmoffat/sophosfw`
- Update the Status section to point at Phases 0-10 with the v0.9.0 release.
- Mention shell completions in Install instructions (Homebrew handles them automatically; for `go install` users, document `sophosfw completion <shell>`).

## 4. Data flow

```
PR / push                 →  ci.yml runs vet/lint/test/build      → red/green
git tag vX.Y.Z; push tag  →  release.yml runs goreleaser          → GitHub release + tap formula push
                                                                    + tarballs containing binary + completions + LICENSE
local: goreleaser release →  same end state, requires HOMEBREW_TAP_TOKEN in env
```

## 5. Errors / failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| Lint regression in PR | CI red | Fix locally; re-push |
| Test regression in PR | CI red | Fix locally; re-push |
| `HOMEBREW_TAP_TOKEN` not in repo secrets | Release fails on tap push step | Add via `gh secret set HOMEBREW_TAP_TOKEN --repo iainmoffat/sophosfw` before first CI release |
| Major-version dep bump in Dependabot PR breaks CI | PR red, doesn't merge | Standard PR review |
| Completion generation fails (e.g., `go run` panics) | release.yml fails before archives | Same diagnostic as local goreleaser run |

## 6. Testing strategy

This phase has no production code, so the testing strategy is verification-by-running:

1. **CI verification**: open a no-op PR (e.g., docs comma fix); confirm CI runs green.
2. **Release verification**: push tag `v0.9.1`. Confirm:
   - `release.yml` runs green
   - 4 archives appear at `https://github.com/iainmoffat/sophosfw/releases/tag/v0.9.1`
   - `iainmoffat/homebrew-sophosfw/sophosfw.rb` updates to version `0.9.1`
   - Each archive contains `sophosfw`, `LICENSE`, and `completions/sophosfw.{bash,zsh,fish}`
   - `brew upgrade sophosfw` pulls 0.9.1 and shell completion works in a fresh terminal (after `compinit` for zsh)
3. **Lint verification**: run `golangci-lint run` locally; pass cleanly. If it flags pre-existing issues, fix them in a separate commit before merging Phase 11.

No automated tests added.

## 7. Acceptance

- [ ] All Phase 11 files committed.
- [ ] `HOMEBREW_TAP_TOKEN` added to `iainmoffat/sophosfw` repo secrets.
- [ ] CI green on the merge commit.
- [ ] Tag `v0.9.1` cut and pushed.
- [ ] Release workflow runs green.
- [ ] Tap formula updates to 0.9.1 with completion install hooks.
- [ ] `brew upgrade sophosfw` succeeds; `sophosfw version` reports `0.9.1`; tab completion works in zsh.
- [ ] `docs/roadmap.md` updated to mark Phase 11 complete; `docs/api-coverage.md` unchanged (no surface change).

## 8. Out of scope (deferred)

- Integration tests in CI (need testvm reachable from runners — major credentials/infra change).
- SBOM, provenance attestations, signed releases (cosign).
- Codecov / coverage reporting.
- Issue / PR templates (low value at current contributor count of 1).
- CODEOWNERS, SECURITY.md (single-author repo).
- Windows builds (the existing `.goreleaser.yaml` is darwin/linux only — not regressing this in Phase 11).
- gosec / additional security linters (separable, can land any time).

These are the obvious "C" items from the brainstorm; deferred to keep Phase 11 small. Any of them can ship as a Phase 11.x patch if needed.

## 9. Risks

- **Lint regressions on existing code.** Adopting golangci-lint may surface real issues. Plan: if lint fails the first run, fix the flagged issues in a pre-Phase 11 cleanup commit before adding the workflow.
- **`HOMEBREW_TAP_TOKEN` scope mismatch.** The token currently used locally needs `Contents: Read/Write` on `iainmoffat/homebrew-sophosfw`. If the existing PAT is repo-scoped to sophosfw only, a fresh token is needed for the tap repo.
- **Completions in archives bloat** — negligible (~100 KB across all three shells).

## 10. Decision log

- **License: MIT, holder "Iain Moffat", year 2026.** Confirmed in brainstorming Q3.
- **Next release tag: `v0.9.1`.** Patch bump — no behavior change, only build/CI/release polish. Confirmed.
- **Branch: work directly on `main` with TDD commits.** No feature branch. Confirmed.
- **Mirror tdx for CI/release/lint config.** Verified by direct read of tdx's `.github/workflows/*.yml` and `.golangci.yml`. The only deltas are the project name and the build target.
- **Cobra `completion` subcommand already exists** — verified via `./bin/sophosfw completion --help` showing bash/fish/powershell/zsh subcommands. No code change needed in `cmd/sophosfw/main.go` or `internal/cli/`.

## 11. References

- tdx CI config (mirror source): `iainmoffat/tdx@main:.github/workflows/ci.yml`
- tdx release config: `iainmoffat/tdx@main:.github/workflows/release.yml`
- tdx golangci config: `iainmoffat/tdx@main:.golangci.yml`
- Existing `.goreleaser.yaml`: `commit 1e65d12`
