# sophosfw Phase 11 Implementation Plan

**Goal:** Mirror the `iainmoffat/tdx` GitHub Actions pattern, add LICENSE + Dependabot + README polish + shell completion bundling, and ship the result as `v0.9.1`.

**Architecture:** Two GitHub Actions workflows + four small repo-level files + four `.goreleaser.yaml` extensions. Zero production code change; nothing under `internal/` or `cmd/` is touched.

**Tech Stack:** GitHub Actions, GoReleaser v2, golangci-lint v2, cobra (existing) for completion script generation. No new Go dependencies.

**Spec:** `docs/superpowers/specs/2026-05-03-sophosfw-phase11-design.md`

---

## Pre-flight

Branch is `main`. Latest tag is `v0.9.0`. Working dir: `/Users/ipm/code/sophosfw`.

```bash
git status
go test ./... -count=1 -race
```
Expected: clean status, all tests pass.

## File structure

**New files:**
- `LICENSE` — MIT, Iain Moffat, 2026.
- `.golangci.yml` — minimal linter set, mirror of tdx.
- `.github/workflows/ci.yml` — vet/lint/test/build on every push and PR.
- `.github/workflows/release.yml` — tag-triggered goreleaser run.
- `.github/dependabot.yml` — weekly grouped updates for gomod + github-actions.

**Modified files:**
- `.goreleaser.yaml` — add `before:` hook for completion generation; add `LICENSE` + `completions/*` to archives; extend brews block with `license: MIT` + completion install hooks.
- `Makefile` — add `completions` convenience target.
- `.gitignore` — add `completions/`.
- `README.md` — replace `git clone ... # not yet published` with `brew install` block; add 3 status badges; refresh Status section to reflect Phases 0-10 complete.
- `docs/roadmap.md` — mark Phase 11 complete (final task).

**External (operator) action required:**
- Add `HOMEBREW_TAP_TOKEN` to `iainmoffat/sophosfw` repo secrets via `gh secret set` before the first CI release.

---

## Task 1: Pre-flight lint sweep

**Why first:** if golangci-lint surfaces real issues in existing code, the rest of the plan is blocked. Surface them now, fix in a separate commit, then proceed.

**Files:**
- (no file changes — diagnostic only; any fixes go to existing files)

- [ ] **Step 1: Run golangci-lint v2.11.4 locally with the exact tdx config**

Create a temporary `.golangci.yml` matching the spec section 3.3 (do NOT commit yet):

```bash
cat > /tmp/sophosfw-lint-probe.yml <<'EOF'
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
EOF
```

Run lint:

```bash
cd /Users/ipm/code/sophosfw
which golangci-lint || brew install golangci-lint
golangci-lint --version  # confirm v2.x; if older, brew upgrade golangci-lint
golangci-lint run --config /tmp/sophosfw-lint-probe.yml ./... 2>&1 | tee /tmp/sophosfw-lint.out
```

- [ ] **Step 2: Triage findings**

If output ends with `0 issues.` (or no issues block): proceed to Task 2.

If issues are reported:
- Open `/tmp/sophosfw-lint.out` and read each issue.
- Fix legitimate issues (most likely: `errcheck` complaining about unchecked `err` returns or untyped type-assertions).
- For false positives, add a `//nolint:<linter>` comment with a one-sentence rationale rather than disabling the linter project-wide.
- Re-run until `0 issues.`

- [ ] **Step 3: Commit lint fixes (only if any were needed)**

```bash
git status --short
git diff
git add -p
git commit -m "fix: address golangci-lint findings ahead of phase 11

Surfaced by running the linter set planned for the phase 11 CI workflow
(govet, errcheck, staticcheck, unused, ineffassign + gofmt). No behavior
change.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

If no fixes were needed, skip the commit.

- [ ] **Step 4: Clean up the temporary lint config**

```bash
rm -f /tmp/sophosfw-lint-probe.yml /tmp/sophosfw-lint.out
```

---

## Task 2: LICENSE + Dependabot + .gitignore

**Files:**
- Create: `LICENSE`
- Create: `.github/dependabot.yml`
- Modify: `.gitignore`

- [ ] **Step 1: Write `LICENSE`**

Create `/Users/ipm/code/sophosfw/LICENSE` with this exact content:

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

- [ ] **Step 2: Write `.github/dependabot.yml`**

Create `.github/` directory (already exists; verify with `ls -la .github`). If the directory does not exist, `mkdir -p .github`.

Create `/Users/ipm/code/sophosfw/.github/dependabot.yml`:

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

- [ ] **Step 3: Append `completions/` to `.gitignore`**

```bash
cd /Users/ipm/code/sophosfw
printf '\ncompletions/\n' >> .gitignore
tail -3 .gitignore
```

Expected last line: `completions/`.

- [ ] **Step 4: Verify nothing broken**

```bash
go build ./...
ls LICENSE .github/dependabot.yml
```

- [ ] **Step 5: Commit**

```bash
git add LICENSE .github/dependabot.yml .gitignore
git commit -m "chore: add LICENSE (MIT), dependabot config, gitignore completions

LICENSE: MIT, attributed to Iain Moffat, 2026.

Dependabot: weekly grouped minor+patch updates for gomod and
github-actions ecosystems. Major-version bumps land as separate PRs
per Dependabot default.

gitignore: completions/ — generated at release time by goreleaser
before-hook; never committed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: golangci-lint config

**Files:**
- Create: `.golangci.yml`

- [ ] **Step 1: Write `.golangci.yml`**

Create `/Users/ipm/code/sophosfw/.golangci.yml`:

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

- [ ] **Step 2: Run lint locally — must pass**

```bash
cd /Users/ipm/code/sophosfw
golangci-lint run ./...
echo "exit: $?"
```

Expected: no output (or `0 issues.`), exit 0.

If this fails, return to Task 1 (something regressed between then and now). Do not commit a `.golangci.yml` that fails locally.

- [ ] **Step 3: Commit**

```bash
git add .golangci.yml
git commit -m "ci: add golangci-lint config (govet, errcheck, staticcheck, unused, ineffassign)

Mirrors the iainmoffat/tdx config. Conservative linter set — avoids
high-noise linters (gocyclo, dupl, lll) that do not pull weight on
this codebase. Adopted by the CI workflow in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the workflow directory**

```bash
mkdir -p /Users/ipm/code/sophosfw/.github/workflows
```

- [ ] **Step 2: Write `.github/workflows/ci.yml`**

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

- [ ] **Step 3: Sanity-check the YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo "YAML parses"
```

Expected: `YAML parses`.

- [ ] **Step 4: Commit and push to trigger first CI run**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow (vet, lint, test, build)

Mirrors iainmoffat/tdx ci.yml. Runs on every push to any branch and
every pull request. Uses go-version-file so go.mod is the source of
truth for the toolchain version. golangci-lint pinned to v2.11.4.
Tests run with -count=1 -race; integration tests are excluded
(build-tag gated).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push origin main
```

- [ ] **Step 5: Watch the first CI run go green**

```bash
gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1
gh run watch --repo iainmoffat/sophosfw $(gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Expected: status `completed`, conclusion `success`. If red, fix locally, push fix, repeat. Do not move on with a red CI.

---

## Task 5: GoReleaser updates (completions, LICENSE, brew hooks) + Makefile target

**Files:**
- Modify: `.goreleaser.yaml`
- Modify: `Makefile`

- [ ] **Step 1: Update `.goreleaser.yaml`**

Read the current file first:

```bash
cat /Users/ipm/code/sophosfw/.goreleaser.yaml
```

Apply these three edits (in order so anchor strings stay unique):

**Edit A** — add the `before:` hook at the top of the file (after `version: 2`, before `builds:`):

Replace:
```yaml
version: 2

builds:
```

With:
```yaml
version: 2

before:
  hooks:
    - go mod tidy
    - bash -c 'mkdir -p completions && go run ./cmd/sophosfw completion bash > completions/sophosfw.bash && go run ./cmd/sophosfw completion zsh > completions/sophosfw.zsh && go run ./cmd/sophosfw completion fish > completions/sophosfw.fish'

builds:
```

**Edit B** — extend `archives:` to include LICENSE + completions:

Replace:
```yaml
archives:
  - formats: [tar.gz]
    name_template: "sophosfw_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
```

With:
```yaml
archives:
  - formats: [tar.gz]
    name_template: "sophosfw_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    files:
      - LICENSE
      - completions/*
```

**Edit C** — extend the brews block with `license: MIT` and completion install hooks:

Replace:
```yaml
brews:
  - repository:
      owner: iainmoffat
      name: homebrew-sophosfw
      token: "{{ .Env.HOMEBREW_TAP_TOKEN }}"
    homepage: https://github.com/iainmoffat/sophosfw
    description: CLI and MCP server for the Sophos Firewall API
    install: |
      bin.install "sophosfw"
```

With:
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

- [ ] **Step 2: Add `Makefile` `completions` target**

Read the current Makefile:

```bash
cat Makefile
```

Edit the `.PHONY` line to include `completions`:

Replace:
```makefile
.PHONY: fmt vet lint test test-int build install skill-doctor clean
```

With:
```makefile
.PHONY: fmt vet lint test test-int build install completions skill-doctor clean
```

Append a new target before the `clean:` rule:

```makefile
completions: build
	mkdir -p completions
	$(BIN) completion bash > completions/sophosfw.bash
	$(BIN) completion zsh > completions/sophosfw.zsh
	$(BIN) completion fish > completions/sophosfw.fish
```

- [ ] **Step 3: Validate goreleaser config**

```bash
goreleaser check
```

Expected: `1 configuration file(s) validated` (the `brews is being phased out` notice is preexisting and acceptable; not a failure).

- [ ] **Step 4: Snapshot build to verify completions get bundled**

```bash
goreleaser release --snapshot --skip=publish --clean
echo "--- archive contents (one platform) ---"
tar -tzf dist/sophosfw_*_darwin_arm64.tar.gz
echo "--- formula install block ---"
sed -n '/install do/,/end$/p' dist/homebrew/sophosfw.rb | head -20
```

Expected:
- Archive contains `sophosfw`, `LICENSE`, `completions/sophosfw.bash`, `completions/sophosfw.zsh`, `completions/sophosfw.fish`.
- Formula install block includes the three `*_completion.install` lines.

- [ ] **Step 5: Verify Makefile target works**

```bash
make clean
make completions
ls completions/
```

Expected: three `sophosfw.*` files.

- [ ] **Step 6: Clean up**

```bash
rm -rf dist/ completions/
```

- [ ] **Step 7: Commit**

```bash
git add .goreleaser.yaml Makefile
git commit -m "build: bundle shell completions and LICENSE in releases

Adds a goreleaser before-hook that runs cobra's completion subcommand
for bash/zsh/fish into completions/. Each archive now contains the
binary, LICENSE, and the three completion scripts.

Brew formula install gets matching hooks so brew install installs the
completions into the right shell paths automatically. Adds license: MIT
to the brews block (now valid because LICENSE exists in the repo).

Adds make completions for local generation, mirroring what goreleaser
does at release time.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push origin main
```

- [ ] **Step 8: Watch CI go green for this commit**

```bash
gh run watch --repo iainmoffat/sophosfw $(gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

---

## Task 6: Release workflow + repo secret

**Files:**
- Create: `.github/workflows/release.yml`

**Operator action:**
- Add `HOMEBREW_TAP_TOKEN` to repo secrets.

- [ ] **Step 1: Write `.github/workflows/release.yml`**

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

- [ ] **Step 2: Sanity-check the YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" && echo "YAML parses"
```

- [ ] **Step 3: Add `HOMEBREW_TAP_TOKEN` to repo secrets**

The same fine-grained PAT used locally (with `Contents: Read/Write` on `iainmoffat/homebrew-sophosfw`) goes here. If the local one is single-use or expired, mint a fresh PAT first.

```bash
# Replace <token> with the actual PAT.
gh secret set HOMEBREW_TAP_TOKEN --repo iainmoffat/sophosfw --body '<token>'
gh secret list --repo iainmoffat/sophosfw
```

Expected: `HOMEBREW_TAP_TOKEN` appears in the secret list.

- [ ] **Step 4: Commit and push (tag NOT yet — that's Task 8)**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add tag-triggered Release workflow

Mirrors iainmoffat/tdx release.yml. Pushes any v* tag to trigger a
goreleaser run on a runner. Pulls HOMEBREW_TAP_TOKEN from repo secrets
so the tap formula push works without operator intervention.

The local HOMEBREW_TAP_TOKEN=... goreleaser release --clean flow
continues to work unchanged for emergencies.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push origin main
```

CI will run on this commit (push to main) — wait for green:

```bash
gh run watch --repo iainmoffat/sophosfw $(gh run list --repo iainmoffat/sophosfw --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

---

## Task 7: README refresh

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read the current README**

```bash
cat /Users/ipm/code/sophosfw/README.md
```

- [ ] **Step 2: Replace the heading + status block with badges and a current status**

Replace the first three sections (heading through end of `## Status`):

Find this block (anchor: starts with `# sophosfw` and ends with the blank line after the foundation phase status bullet list):

```
# sophosfw

Go CLI + MCP server for the Sophos Firewall XML API. Production-safe
read-only inspection by default; mutating workflows arrive in later phases.

## Status

**Foundation phase** (Phases 0-2 of the roadmap):
- Profile-based config with macOS Keychain (file fallback) credential storage
- Sophos XML API client with login injection and credential redaction
- Hybrid object catalog (12 tags; typed parsers for IPHost and Services)
- Generic `object list/get/usage/schema` and `raw get/request --dry-run`
- `mcp serve` scaffold (zero tools registered; Phase 4 lands the tool surface)
- Three-layer read-only safety enforcement
- Stable `sophosfw.v1.*` JSON envelope contract

See `docs/roadmap.md` for what's coming.
```

Replace with:

```
# sophosfw

[![CI](https://github.com/iainmoffat/sophosfw/actions/workflows/ci.yml/badge.svg)](https://github.com/iainmoffat/sophosfw/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/iainmoffat/sophosfw)](https://github.com/iainmoffat/sophosfw/releases/latest)
[![License](https://img.shields.io/github/license/iainmoffat/sophosfw)](LICENSE)

Go CLI + MCP server for the Sophos Firewall XML API. Production-safe
read-only inspection by default, with mutating workflows for IPHosts,
firewall rules, and NAT rules behind explicit confirm gates.

## Status

Phases 0-10 complete (foundation through MCP-native firewall + NAT rule
mutations). The MCP server registers 30 tools; the CLI covers
inspection, drafts, dry-run preview, and apply for the supported
object types. See `docs/roadmap.md` and `docs/api-coverage.md` for the
exact surface.
```

- [ ] **Step 3: Replace the `## Install` block**

Find:

```
## Install

```bash
git clone https://github.com/iainmoffat/sophosfw   # not yet published
cd sophosfw
make build
./bin/sophosfw version
```

Or `make install` to copy to `$GOBIN`.
```

Replace with:

```
## Install

**Homebrew** (macOS / Linux):

```bash
brew install iainmoffat/sophosfw/sophosfw
```

This installs the binary plus shell completions for bash, zsh, and fish.

**From source:**

```bash
git clone https://github.com/iainmoffat/sophosfw
cd sophosfw
make build
./bin/sophosfw version
```

Or `make install` to copy to `$GOBIN`. For shell completion when
installed from source, run `sophosfw completion <shell>` and source
the output (`sophosfw completion --help` shows per-shell instructions).
```

- [ ] **Step 4: Verify README still parses**

```bash
# Quick sanity check — markdown does not have a parser in stdlib; just visually verify with:
head -50 README.md
```

- [ ] **Step 5: Commit and push**

```bash
git add README.md
git commit -m "docs: refresh README with brew install, badges, current status

Drops the stale not yet published note. Adds CI / Release / License
badges. Status section now reflects Phases 0-10 complete instead of
foundation phase. Install section leads with brew, keeps from-source
as the alternative, and points completion users at the cobra
subcommand for shell setup.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push origin main
```

CI will run; wait for green.

---

## Task 8: Cut the v0.9.1 release

**Files:**
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Mark Phase 11 complete in `docs/roadmap.md`**

Read current roadmap:

```bash
cat docs/roadmap.md | head -20
```

Add a new line under the existing Phase 10 entry:

Replace:
```
- Phase 10 — MCP-native firewall and NAT rule mutating tools (complete; v0.9.0-phase10)
```

With:
```
- Phase 10 — MCP-native firewall and NAT rule mutating tools (complete; v0.9.0-phase10)
- Phase 11 — CI/CD + release polish (complete; v0.9.1)
```

- [ ] **Step 2: Commit roadmap and push**

```bash
git add docs/roadmap.md
git commit -m "docs: mark Phase 11 complete in roadmap

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push origin main
```

Wait for CI green (this is the final pre-tag run).

- [ ] **Step 3: Tag v0.9.1 and push**

```bash
git tag -a v0.9.1 -m "v0.9.1 — Phase 11: CI/CD and release polish

CI workflow on every push and PR (vet, lint, test, build).
Tag-triggered release workflow runs goreleaser on a runner.
LICENSE (MIT). Dependabot for gomod and github-actions.
README refreshed with badges and brew install instructions.
Releases now include shell completions for bash, zsh, and fish."
git push origin v0.9.1
```

- [ ] **Step 4: Watch the release workflow**

```bash
gh run list --repo iainmoffat/sophosfw --workflow=release.yml --limit 1
gh run watch --repo iainmoffat/sophosfw $(gh run list --repo iainmoffat/sophosfw --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Expected: status `completed`, conclusion `success`. If red, read the run log:

```bash
gh run view --repo iainmoffat/sophosfw $(gh run list --repo iainmoffat/sophosfw --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId') --log-failed
```

Common fixes:
- Missing `HOMEBREW_TAP_TOKEN` secret → revisit Task 6 step 3.
- Token lacks `Contents: Read/Write` on `homebrew-sophosfw` → mint a new PAT, replace the secret.

- [ ] **Step 5: Verify the GitHub release**

```bash
gh release view v0.9.1 --repo iainmoffat/sophosfw --json name,tagName,assets --jq '{name, tagName, assets: [.assets[].name]}'
```

Expected: `name=v0.9.1`, 5 assets (`checksums.txt` + 4 platform tarballs).

- [ ] **Step 6: Verify the tap formula updated**

```bash
gh api repos/iainmoffat/homebrew-sophosfw/contents/sophosfw.rb --jq '.content' | base64 -d | grep -E '^  version|completion.install' | head -5
```

Expected:
```
  version "0.9.1"
      bash_completion.install "completions/sophosfw.bash" => "sophosfw"
      zsh_completion.install "completions/sophosfw.zsh" => "_sophosfw"
      fish_completion.install "completions/sophosfw.fish"
```

- [ ] **Step 7: Verify brew upgrade**

```bash
brew update
brew upgrade sophosfw
sophosfw version
```

Expected: `sophosfw 0.9.1 (...)`.

- [ ] **Step 8: Verify completion installed**

```bash
ls "$(brew --prefix)/share/zsh/site-functions/_sophosfw" \
   "$(brew --prefix)/etc/bash_completion.d/sophosfw" \
   "$(brew --prefix)/share/fish/vendor_completions.d/sophosfw.fish" 2>&1
```

Expected: all three exist (or at minimum the one for the shell you actually use).

For the zsh completion to take effect in a running shell, run `compinit`. Type `sophosfw <TAB>` and confirm the cobra-generated completion fires.

---

## End of plan

## Self-review checklist

- ✅ **Spec coverage:** Section 3 (CI workflow) → Task 4; (release workflow) → Task 6; (golangci config) → Task 3; (Dependabot) → Task 2; (LICENSE) → Task 2; (completion bundling) → Task 5; (README refresh) → Task 7. Section 7 (acceptance) → Task 8 verification steps. Section 6 (testing) → integrated into each task's verification.
- ✅ **No placeholders.** Every step has actual file contents or commands.
- ✅ **Type/file consistency.** All file paths absolute or rooted at `/Users/ipm/code/sophosfw`. The completion install hooks use the exact filenames the goreleaser before-hook produces.
- ✅ **Dependency order.** Pre-flight lint (Task 1) → LICENSE/dependabot/gitignore (Task 2, no deps) → golangci config (Task 3, depends on Task 1) → CI workflow (Task 4, depends on Task 3) → goreleaser updates (Task 5, depends on LICENSE for archives) → release workflow + secret (Task 6, depends on Task 5) → README (Task 7, depends on badges resolving against published workflows) → tag + verify (Task 8, depends on everything).
- ✅ **No production code touched.** Nothing in `internal/` or `cmd/sophosfw/` is modified by this plan. The lint pre-flight in Task 1 may surface findings that require source fixes — those land in their own commit ahead of Phase 11 proper.
- ✅ **Acceptance verifiable end-to-end.** Task 8 includes `brew upgrade` + version check + completion install verification.

## Notes for the implementer

- **Subagent-driven flow:** Tasks 1-7 are mechanical. Task 8 has external dependencies (GitHub Actions runner, brew CDN propagation) that may need short waits between steps; if `gh run watch` returns immediately with a status other than `completed`, re-poll.
- **Token handling:** the `HOMEBREW_TAP_TOKEN` value is sensitive; do not echo it to logs, do not commit it, do not write it to memory. Use `gh secret set --body '<value>'` (or stdin) directly. After Task 6 step 3, the local `HOMEBREW_TAP_TOKEN` env var no longer needs to be exported for future releases — CI handles them.
- **If lint fails on a Dependabot PR later:** that's CI working as designed. Standard PR review.
