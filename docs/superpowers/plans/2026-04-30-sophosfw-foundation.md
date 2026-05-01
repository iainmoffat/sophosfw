# sophosfw Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the sophosfw Go CLI + MCP-scaffold foundation (Phases 0-2 of the sophosfw roadmap): project skeleton, profile/credential model with macOS Keychain backend, Sophos XML API client, hybrid YAML+typed-Go object catalog, generic `object`/`raw` CLI commands, zero-tool `mcp serve` scaffold, three-layer read-only safety enforcement, stable JSON envelope contract, and the agent-skill outline.

**Architecture:** Layered Go project mirroring tdx — `cmd/sophosfw/main.go` wires Cobra; `internal/cli` is a thin command layer; `internal/svc` holds the only application services that both CLI and (Phase-4) MCP consume; `internal/{sophos,catalog,config,creds}` are the core libraries; `internal/{render,safety}` are sibling helpers; `internal/mcp` is a stub. Read-only enforcement is mechanical at three concentric layers (client / service / integration test).

**Tech Stack:** Go 1.26.2, `github.com/spf13/cobra` (CLI), `github.com/charmbracelet/lipgloss` (table styling, no TUI), `github.com/modelcontextprotocol/go-sdk` (MCP), `github.com/zalando/go-keyring` (Darwin keychain), `gopkg.in/yaml.v3`, `golang.org/x/term` (no-echo password), `github.com/stretchr/testify` (assertions).

**Reference:** Spec at `docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md`. Reference project at `/Users/ipm/code/tdx/`.

**Conventions every task follows:**
- Working directory is `/Users/ipm/code/sophosfw`. All paths in this plan are relative to that root.
- Every code task is TDD: write the failing test, run it (must fail), implement minimally, run it (must pass), commit.
- Commits use a `type: subject` style (`feat:`, `test:`, `docs:`, `chore:`, `refactor:`). Co-author trailer is optional in this plan; the engineer may add one.
- `go test ./...` runs the full test suite. Per-package: `go test ./internal/<pkg> -v -run TestName`.
- Never log unredacted credentials. If a task needs to log XML, run it through `safety.RedactXML` first.
- Never run integration tests in normal flow — they live under build tag `integration` and require `SOPHOSFW_INTEGRATION=1`.

---

## Task 1: Initialize Go module and base project files

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `cmd/sophosfw/main.go`
- Create: `Makefile`

- [ ] **Step 1: Initialize the Go module**

Run:
```bash
go mod init github.com/iainmoffat/sophosfw
```

Expected: creates `go.mod` with `module github.com/iainmoffat/sophosfw` and `go 1.26.2` (or your installed minor version — that's fine; we'll align if needed).

- [ ] **Step 2: Create `.gitignore`**

Write `/Users/ipm/code/sophosfw/.gitignore`:
```
bin/
dist/
*.test
*.out
coverage.txt
.DS_Store
.envrc
.env
.env.*
!.env.example
.idea/
.vscode/
```

- [ ] **Step 3: Create the entrypoint stub**

Write `cmd/sophosfw/main.go`:
```go
package main

import (
	"fmt"
	"os"
)

// version is overridden at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// TEMP: replaced in Task 2 with cobra root.
	fmt.Println("sophosfw", version)
	return nil
}
```

- [ ] **Step 4: Create the Makefile**

Write `Makefile`:
```make
SHELL := bash
GO    := go
PKG   := ./...
BIN   := bin/sophosfw
LDFLAGS := -X main.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: fmt vet lint test test-int build install skill-doctor clean

fmt:
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; skipping"; exit 0; }
	golangci-lint run

test:
	$(GO) test -race $(PKG)

test-int:
	SOPHOSFW_INTEGRATION=1 $(GO) test -tags integration $(PKG)

build:
	mkdir -p bin
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/sophosfw

install: build
	install $(BIN) $$GOBIN/sophosfw

skill-doctor: build
	$(BIN) skill doctor

clean:
	rm -rf bin dist coverage.txt
```

- [ ] **Step 5: Verify the build works**

Run:
```bash
make build && ./bin/sophosfw
```

Expected: prints `sophosfw dev` (or a git-derived version) and exits 0.

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore cmd/sophosfw/main.go Makefile
git commit -m "chore: initialize Go module and project scaffolding"
```

---

## Task 2: Cobra root command + `version` subcommand

**Files:**
- Create: `internal/cli/root.go`
- Create: `internal/cli/version.go`
- Create: `internal/cli/version_test.go`
- Modify: `cmd/sophosfw/main.go`

- [ ] **Step 1: Add the cobra dependency**

Run:
```bash
go get github.com/spf13/cobra@latest
go get github.com/stretchr/testify@latest
go mod tidy
```

- [ ] **Step 2: Write the failing test for `version`**

Create `internal/cli/version_test.go`:
```go
package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionCommand_PrintsVersion(t *testing.T) {
	root := NewRoot(RootDeps{Version: "1.2.3"})
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetArgs([]string{"version"})

	require.NoError(t, root.Execute())
	require.True(t, strings.Contains(out.String(), "1.2.3"),
		"expected output to contain version, got: %q", out.String())
}
```

- [ ] **Step 3: Run the test — it must fail (compile error)**

Run:
```bash
go test ./internal/cli -run TestVersionCommand_PrintsVersion -v
```

Expected: build fails — `NewRoot` and `RootDeps` don't exist.

- [ ] **Step 4: Create `internal/cli/root.go`**

```go
package cli

import (
	"github.com/spf13/cobra"
)

// RootDeps holds dependencies injected into the root command. Keeping this
// explicit lets tests construct a root with controlled state.
type RootDeps struct {
	Version string
}

// NewRoot constructs the cobra root command with all subcommands wired in.
func NewRoot(d RootDeps) *cobra.Command {
	root := &cobra.Command{
		Use:           "sophosfw",
		Short:         "Sophos Firewall CLI + MCP server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags are added in later tasks (auth/object/raw etc.).
	root.PersistentFlags().String("profile", "", "config profile to use (default: currentProfile from config)")
	root.PersistentFlags().Bool("json", false, "emit JSON envelope output instead of tables")
	root.PersistentFlags().Duration("timeout", 0, "override per-request timeout")
	root.PersistentFlags().Bool("debug", false, "verbose logging (credentials always redacted)")

	root.AddCommand(newVersionCmd(d))

	return root
}
```

- [ ] **Step 5: Create `internal/cli/version.go`**

```go
package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print sophosfw version, commit, and Go runtime",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"sophosfw %s (%s/%s, %s)\n",
				d.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return err
		},
	}
}
```

- [ ] **Step 6: Run the test — it must pass**

Run:
```bash
go test ./internal/cli -run TestVersionCommand_PrintsVersion -v
```

Expected: PASS.

- [ ] **Step 7: Wire the root into `main.go`**

Replace `cmd/sophosfw/main.go`:
```go
package main

import (
	"fmt"
	"os"

	"github.com/iainmoffat/sophosfw/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(cli.RootDeps{Version: version})
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 8: Verify the binary works end-to-end**

Run:
```bash
make build && ./bin/sophosfw version
```

Expected: prints `sophosfw <version> (darwin/arm64, go1.26.x)` style line.

- [ ] **Step 9: Commit**

```bash
git add go.mod go.sum cmd/sophosfw/main.go internal/cli/root.go internal/cli/version.go internal/cli/version_test.go
git commit -m "feat(cli): cobra root command and version subcommand"
```

---

## Task 3: `safety` package — XML credential redaction

**Files:**
- Create: `internal/safety/redact.go`
- Create: `internal/safety/redact_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/safety/redact_test.go`:
```go
package safety

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactXML_ReplacesUsernameAndPassword(t *testing.T) {
	in := []byte(`<Request><Login><Username>admin</Username><Password>hunter2</Password></Login><Get><IPHost></IPHost></Get></Request>`)
	out := RedactXML(in)
	require.False(t, strings.Contains(string(out), "admin"))
	require.False(t, strings.Contains(string(out), "hunter2"))
	require.True(t, strings.Contains(string(out), "<Username>***</Username>"))
	require.True(t, strings.Contains(string(out), "<Password>***</Password>"))
	// Other tags must survive unchanged.
	require.True(t, strings.Contains(string(out), "<Get><IPHost></IPHost></Get>"))
}

func TestRedactXML_Idempotent(t *testing.T) {
	in := []byte(`<Login><Username>x</Username><Password>y</Password></Login>`)
	once := RedactXML(in)
	twice := RedactXML(once)
	require.Equal(t, string(once), string(twice))
}

func TestRedactXML_NoCredentials_Unchanged(t *testing.T) {
	in := []byte(`<Get><IPHost></IPHost></Get>`)
	require.Equal(t, string(in), string(RedactXML(in)))
}

func TestRedactString_ReplacesPasswordSubstring(t *testing.T) {
	got := RedactString("connecting as admin with password=hunter2")
	require.False(t, strings.Contains(got, "hunter2"))
}
```

- [ ] **Step 2: Run — must fail (package doesn't exist)**

```bash
go test ./internal/safety -v
```

- [ ] **Step 3: Implement `internal/safety/redact.go`**

```go
// Package safety holds defensive helpers used across the rest of the codebase:
// credential redaction and mutating-XML detection.
package safety

import (
	"regexp"
)

var (
	xmlUsernameRe = regexp.MustCompile(`(?s)<Username>.*?</Username>`)
	xmlPasswordRe = regexp.MustCompile(`(?s)<Password>.*?</Password>`)

	// Loose substring redactor for log lines that mention creds in non-XML form.
	stringPasswordRe = regexp.MustCompile(`(?i)(password\s*[=:]\s*)\S+`)
)

// RedactXML replaces <Username>…</Username> and <Password>…</Password> contents
// with ***. Idempotent. Never modifies any other XML structure.
func RedactXML(b []byte) []byte {
	b = xmlUsernameRe.ReplaceAll(b, []byte("<Username>***</Username>"))
	b = xmlPasswordRe.ReplaceAll(b, []byte("<Password>***</Password>"))
	return b
}

// RedactString scrubs `password=...` style substrings from arbitrary log lines.
func RedactString(s string) string {
	return stringPasswordRe.ReplaceAllString(s, "${1}***")
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/safety -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/safety/redact.go internal/safety/redact_test.go
git commit -m "feat(safety): RedactXML and RedactString helpers"
```

---

## Task 4: `safety` package — mutating-XML detector

**Files:**
- Create: `internal/safety/mutating.go`
- Create: `internal/safety/mutating_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/safety/mutating_test.go`:
```go
package safety

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsMutating_DetectsSetAdd(t *testing.T) {
	x := []byte(`<Request><Set operation="add"><IPHost><Name>x</Name></IPHost></Set></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Contains(t, verbs, "Set:add")
}

func TestIsMutating_DetectsSetUpdate(t *testing.T) {
	x := []byte(`<Request><Set operation="update"><IPHost></IPHost></Set></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Contains(t, verbs, "Set:update")
}

func TestIsMutating_DetectsRemove(t *testing.T) {
	x := []byte(`<Request><Remove><IPHost><Name>x</Name></IPHost></Remove></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Contains(t, verbs, "Remove")
}

func TestIsMutating_GetIsNotMutating(t *testing.T) {
	x := []byte(`<Request><Get><IPHost></IPHost></Get></Request>`)
	mutating, verbs := IsMutating(x)
	require.False(t, mutating)
	require.Empty(t, verbs)
}

func TestIsMutating_StatisticsIsNotMutating(t *testing.T) {
	x := []byte(`<Request><IPHostStatistics><Filter><key name="Name" criteria="like">LAN</key></Filter></IPHostStatistics></Request>`)
	mutating, verbs := IsMutating(x)
	require.False(t, mutating)
	require.Empty(t, verbs)
}

func TestIsMutating_MultipleVerbsAllReported(t *testing.T) {
	x := []byte(`<Request><Set operation="add"></Set><Remove></Remove></Request>`)
	mutating, verbs := IsMutating(x)
	require.True(t, mutating)
	require.Len(t, verbs, 2)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/safety -run TestIsMutating -v
```

- [ ] **Step 3: Implement `internal/safety/mutating.go`**

```go
package safety

import (
	"regexp"
	"sort"
)

// setOpRe matches <Set operation="add|update"> opening tags.
var setOpRe = regexp.MustCompile(`<Set\s+operation\s*=\s*"(add|update)"`)

// removeRe matches a <Remove> opening tag (any whitespace/attrs after).
var removeRe = regexp.MustCompile(`<Remove[\s>]`)

// IsMutating returns true if the XML envelope contains any verb that would
// modify firewall configuration. The second return value lists the detected
// verbs in a stable order (e.g. "Set:add", "Set:update", "Remove"). Statistics
// queries (`<*Statistics>`) are read-only and are not flagged.
func IsMutating(xml []byte) (bool, []string) {
	seen := map[string]struct{}{}

	for _, m := range setOpRe.FindAllSubmatch(xml, -1) {
		seen["Set:"+string(m[1])] = struct{}{}
	}
	if removeRe.Find(xml) != nil {
		seen["Remove"] = struct{}{}
	}

	if len(seen) == 0 {
		return false, nil
	}
	verbs := make([]string, 0, len(seen))
	for v := range seen {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	return true, verbs
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/safety -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/safety/mutating.go internal/safety/mutating_test.go
git commit -m "feat(safety): IsMutating detector for Set/Remove verbs"
```

---

## Task 5: `render` package — JSON envelope writers

**Files:**
- Create: `internal/render/json.go`
- Create: `internal/render/json_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/render/json_test.go`:
```go
package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteJSON_WrapsPayloadWithSchemaField(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteJSON(buf, "sophosfw.v1.authStatus", map[string]any{
		"profile":  "home",
		"loggedIn": true,
	})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "sophosfw.v1.authStatus", got["schema"])
	require.Equal(t, "home", got["profile"])
	require.Equal(t, true, got["loggedIn"])
}

func TestWriteJSON_PrettyPrintedWithTrailingNewline(t *testing.T) {
	buf := &bytes.Buffer{}
	require.NoError(t, WriteJSON(buf, "sophosfw.v1.test", struct{}{}))
	require.True(t, bytes.HasSuffix(buf.Bytes(), []byte("\n")))
	require.Contains(t, buf.String(), "  ") // indented
}

func TestWriteError_EmitsErrorEnvelope(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteError(buf, "auth_failed", "bad credentials", "home", map[string]any{"hint": "check password"})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "sophosfw.v1.error", got["schema"])
	require.Equal(t, "auth_failed", got["kind"])
	require.Equal(t, "bad credentials", got["message"])
	require.Equal(t, "home", got["profile"])
	details := got["details"].(map[string]any)
	require.Equal(t, "check password", details["hint"])
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/render -v
```

- [ ] **Step 3: Implement `internal/render/json.go`**

```go
// Package render owns user-facing output: JSON envelopes and lipgloss tables.
package render

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON wraps payload in a {schema, ...payload} envelope and pretty-prints
// it with a trailing newline. Use this for every successful JSON output.
func WriteJSON(w io.Writer, schema string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("render: marshal payload: %w", err)
	}

	// Merge {schema: ...} into the payload object. We re-encode through a map
	// so callers can pass either a struct (json-tagged) or map[string]any.
	var merged map[string]any
	if err := json.Unmarshal(b, &merged); err != nil {
		// Payload wasn't a JSON object — wrap it under "data".
		merged = map[string]any{"data": json.RawMessage(b)}
	}
	merged["schema"] = schema

	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("render: marshal envelope: %w", err)
	}
	if _, err := w.Write(out); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// WriteError writes a sophosfw.v1.error envelope.
func WriteError(w io.Writer, kind, message, profile string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	return WriteJSON(w, "sophosfw.v1.error", map[string]any{
		"kind":    kind,
		"message": message,
		"profile": profile,
		"details": details,
	})
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/render -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/render/json.go internal/render/json_test.go
git commit -m "feat(render): JSON envelope writers (sophosfw.v1.* + error)"
```

---

## Task 6: `render` package — table writer with `lipgloss`

**Files:**
- Create: `internal/render/color.go`
- Create: `internal/render/table.go`
- Create: `internal/render/table_test.go`

- [ ] **Step 1: Add the `lipgloss` dependency**

```bash
go get github.com/charmbracelet/lipgloss@latest
go mod tidy
```

- [ ] **Step 2: Write the failing tests**

Create `internal/render/table_test.go`:
```go
package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteTable_RendersHeadersAndRows(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	require.NoError(t, WriteTable(buf, []string{"Name", "IPAddress"}, [][]string{
		{"LAN-network", "10.0.0.0"},
		{"DMZ", "192.168.10.0"},
	}))
	out := buf.String()
	require.Contains(t, out, "Name")
	require.Contains(t, out, "IPAddress")
	require.Contains(t, out, "LAN-network")
	require.Contains(t, out, "10.0.0.0")
	require.Contains(t, out, "DMZ")
	require.Contains(t, out, "192.168.10.0")
}

func TestWriteTable_EmptyRowsStillRendersHeader(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	require.NoError(t, WriteTable(buf, []string{"Name"}, nil))
	require.Contains(t, buf.String(), "Name")
}

func TestWriteTable_NoColorModeIsAnsiClean(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	buf := &bytes.Buffer{}
	require.NoError(t, WriteTable(buf, []string{"A"}, [][]string{{"x"}}))
	require.False(t, strings.Contains(buf.String(), "\x1b["),
		"NO_COLOR mode must not emit ANSI escape sequences")
}
```

- [ ] **Step 3: Run — must fail**

```bash
go test ./internal/render -run TestWriteTable -v
```

- [ ] **Step 4: Implement `internal/render/color.go`**

```go
package render

import "os"

// ColorEnabled reports whether colored output should be emitted. Honors
// NO_COLOR (https://no-color.org) which trumps any terminal detection.
func ColorEnabled() bool {
	return os.Getenv("NO_COLOR") == ""
}
```

- [ ] **Step 5: Implement `internal/render/table.go`**

```go
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// WriteTable renders a single-line bordered table. When NO_COLOR=1 is set the
// output is plain ASCII and contains no escape sequences.
func WriteTable(w io.Writer, headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return fmt.Errorf("render: WriteTable: headers required")
	}

	if !ColorEnabled() {
		return writeASCIITable(w, headers, rows)
	}

	headerStyle := lipgloss.NewStyle().Bold(true)
	cellStyle := lipgloss.NewStyle()

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if i >= len(widths) {
				break
			}
			if w := lipgloss.Width(c); w > widths[i] {
				widths[i] = w
			}
		}
	}

	var b strings.Builder
	// Top border
	b.WriteString("┌")
	for i, w := range widths {
		b.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			b.WriteString("┬")
		}
	}
	b.WriteString("┐\n")

	// Header row
	b.WriteString("│")
	for i, h := range headers {
		fmt.Fprintf(&b, " %s ", headerStyle.Render(padRight(h, widths[i])))
		b.WriteString("│")
	}
	b.WriteString("\n")

	// Header separator
	b.WriteString("├")
	for i, w := range widths {
		b.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			b.WriteString("┼")
		}
	}
	b.WriteString("┤\n")

	// Body rows
	for _, row := range rows {
		b.WriteString("│")
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Fprintf(&b, " %s ", cellStyle.Render(padRight(cell, widths[i])))
			b.WriteString("│")
		}
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString("└")
	for i, w := range widths {
		b.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			b.WriteString("┴")
		}
	}
	b.WriteString("┘\n")

	_, err := io.WriteString(w, b.String())
	return err
}

func writeASCIITable(w io.Writer, headers []string, rows [][]string) error {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if i >= len(widths) {
				break
			}
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}

	border := func() string {
		parts := make([]string, len(widths))
		for i, w := range widths {
			parts[i] = strings.Repeat("-", w+2)
		}
		return "+" + strings.Join(parts, "+") + "+\n"
	}

	var b strings.Builder
	b.WriteString(border())
	b.WriteString("|")
	for i, h := range headers {
		fmt.Fprintf(&b, " %s |", padRight(h, widths[i]))
	}
	b.WriteString("\n")
	b.WriteString(border())

	for _, row := range rows {
		b.WriteString("|")
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Fprintf(&b, " %s |", padRight(cell, widths[i]))
		}
		b.WriteString("\n")
	}
	b.WriteString(border())

	_, err := io.WriteString(w, b.String())
	return err
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
```

- [ ] **Step 6: Run — must pass**

```bash
go test ./internal/render -v
```

- [ ] **Step 7: Commit**

```bash
git add internal/render/color.go internal/render/table.go internal/render/table_test.go go.mod go.sum
git commit -m "feat(render): lipgloss + ASCII table writer (NO_COLOR aware)"
```

---

## Task 7: `config` package — `~/.config/sophosfw/config.yaml` model

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Add yaml dependency**

```bash
go get gopkg.in/yaml.v3
go mod tidy
```

- [ ] **Step 2: Write the failing tests**

Create `internal/config/config_test.go`:
```go
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestLoad_EmptyDir_ReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, 1, c.Version)
	require.Equal(t, "table", c.Defaults.Output)
	require.Equal(t, 30*time.Second, c.Defaults.Timeout)
	require.Empty(t, c.Profiles)
	require.Empty(t, c.CurrentProfile)
}

func TestLoad_ParsesProfiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), `
version: 1
currentProfile: home
defaults:
  output: json
  timeout: 45s
profiles:
  home:
    url: https://fw.example.com:4444
    timeout: 30s
    insecureSkipVerify: false
    readOnly: false
    credentialsBackend: keychain
`)
	c, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, "home", c.CurrentProfile)
	require.Equal(t, "json", c.Defaults.Output)
	require.Len(t, c.Profiles, 1)
	p := c.Profiles["home"]
	require.Equal(t, "https://fw.example.com:4444", p.URL)
	require.Equal(t, "keychain", p.CredentialsBackend)
	require.False(t, p.ReadOnly)
}

func TestSave_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	c := &Config{
		Version:        1,
		CurrentProfile: "home",
		Defaults:       Defaults{Output: "table", Timeout: 30 * time.Second},
		Profiles: map[string]Profile{
			"home": {
				URL:                "https://fw.example.com:4444",
				Timeout:            30 * time.Second,
				ReadOnly:           false,
				CredentialsBackend: "keychain",
			},
		},
	}
	require.NoError(t, c.Save(dir))

	got, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, c.CurrentProfile, got.CurrentProfile)
	require.Equal(t, c.Profiles["home"].URL, got.Profiles["home"].URL)
}

func TestProfile_AddRemoveSelect(t *testing.T) {
	c := New()
	c.AddProfile("home", Profile{URL: "https://h:4444"})
	require.Contains(t, c.Profiles, "home")
	require.Equal(t, "home", c.CurrentProfile, "first profile becomes current automatically")

	c.AddProfile("work", Profile{URL: "https://w:4444"})
	require.Equal(t, "home", c.CurrentProfile, "subsequent additions do not change current")

	require.NoError(t, c.UseProfile("work"))
	require.Equal(t, "work", c.CurrentProfile)

	require.Error(t, c.UseProfile("nope"))

	require.NoError(t, c.RemoveProfile("home"))
	require.NotContains(t, c.Profiles, "home")
}

func TestRemoveProfile_CurrentClearedIfRemoved(t *testing.T) {
	c := New()
	c.AddProfile("home", Profile{URL: "https://h:4444"})
	require.NoError(t, c.RemoveProfile("home"))
	require.Empty(t, c.CurrentProfile)
}

func TestActiveProfile(t *testing.T) {
	c := New()
	c.AddProfile("home", Profile{URL: "https://h:4444"})
	p, name, err := c.ActiveProfile("")
	require.NoError(t, err)
	require.Equal(t, "home", name)
	require.Equal(t, "https://h:4444", p.URL)

	_, _, err = c.ActiveProfile("missing")
	require.Error(t, err)
}
```

- [ ] **Step 3: Run — must fail**

```bash
go test ./internal/config -v
```

- [ ] **Step 4: Implement `internal/config/config.go`**

```go
// Package config models ~/.config/sophosfw/config.yaml: the global defaults
// and the registry of named firewall profiles.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	configFileName     = "config.yaml"
	profilesDirName    = "profiles"
	defaultOutput      = "table"
	defaultTimeout     = 30 * time.Second
	defaultBackendName = "keychain" // overridden on non-darwin
)

// Defaults are global settings that apply when a per-profile or per-flag
// override isn't supplied.
type Defaults struct {
	Output             string        `yaml:"output"`
	Timeout            time.Duration `yaml:"timeout"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
}

// Profile is a single named firewall configuration.
type Profile struct {
	URL                string        `yaml:"url"`
	Timeout            time.Duration `yaml:"timeout"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
	ReadOnly           bool          `yaml:"readOnly"`
	APIVersion         string        `yaml:"apiVersion,omitempty"`
	Notes              string        `yaml:"notes,omitempty"`
	CredentialsBackend string        `yaml:"credentialsBackend"`
}

// Config is the top-level config.yaml shape.
type Config struct {
	Version        int                `yaml:"version"`
	CurrentProfile string             `yaml:"currentProfile,omitempty"`
	Defaults       Defaults           `yaml:"defaults"`
	Profiles       map[string]Profile `yaml:"profiles"`
}

// New returns a Config populated with defaults.
func New() *Config {
	return &Config{
		Version: 1,
		Defaults: Defaults{
			Output:  defaultOutput,
			Timeout: defaultTimeout,
		},
		Profiles: map[string]Profile{},
	}
}

// Load reads the config file under baseDir (typically ~/.config/sophosfw).
// If the file is absent, defaults are returned.
func Load(baseDir string) (*Config, error) {
	path := filepath.Join(baseDir, configFileName)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	c := New()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	if c.Defaults.Output == "" {
		c.Defaults.Output = defaultOutput
	}
	if c.Defaults.Timeout == 0 {
		c.Defaults.Timeout = defaultTimeout
	}
	if c.Version == 0 {
		c.Version = 1
	}
	return c, nil
}

// Save writes the config (atomic rename) and ensures the profile dir exists.
func (c *Config) Save(baseDir string) error {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", baseDir, err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, profilesDirName), 0o700); err != nil {
		return fmt.Errorf("config: mkdir profiles: %w", err)
	}

	path := filepath.Join(baseDir, configFileName)
	tmp := path + ".tmp"
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("config: write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

// AddProfile inserts a profile. If no profile is currently selected, the
// newly added one becomes current.
func (c *Config) AddProfile(name string, p Profile) {
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	c.Profiles[name] = p
	if c.CurrentProfile == "" {
		c.CurrentProfile = name
	}
}

// UseProfile switches the current profile.
func (c *Config) UseProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	c.CurrentProfile = name
	return nil
}

// RemoveProfile deletes a profile. Clears CurrentProfile if it was that one.
func (c *Config) RemoveProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	delete(c.Profiles, name)
	if c.CurrentProfile == name {
		c.CurrentProfile = ""
	}
	return nil
}

// ActiveProfile resolves the active profile from an optional override
// (typically the --profile flag). Returns the profile, its name, and an error
// if neither a valid override nor a current profile exists.
func (c *Config) ActiveProfile(override string) (Profile, string, error) {
	name := override
	if name == "" {
		name = c.CurrentProfile
	}
	if name == "" {
		return Profile{}, "", errors.New("no profile selected (use --profile or `sophosfw auth profile use`)")
	}
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, "", fmt.Errorf("profile %q not found", name)
	}
	return p, name, nil
}

// DefaultBaseDir returns the conventional config dir under $XDG_CONFIG_HOME
// or ~/.config.
func DefaultBaseDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "sophosfw"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sophosfw"), nil
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/config -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go go.mod go.sum
git commit -m "feat(config): config.yaml model with profile CRUD"
```

---

## Task 8: `creds` package — `Store` interface

**Files:**
- Create: `internal/creds/store.go`

- [ ] **Step 1: Implement the interface**

Create `internal/creds/store.go`:
```go
// Package creds abstracts credential persistence so the rest of the codebase
// never touches platform-specific keychains directly.
package creds

// Credentials is a username/password pair for a Sophos firewall profile.
type Credentials struct {
	Username string
	Password string
}

// Store persists Credentials per profile name. Implementations must scrub
// values from memory where the platform allows.
type Store interface {
	Load(profile string) (Credentials, error)
	Save(profile string, c Credentials) error
	Delete(profile string) error
	Backend() string // "keychain" | "file"
}

// Backend names returned by Store.Backend().
const (
	BackendKeychain = "keychain"
	BackendFile     = "file"
)
```

- [ ] **Step 2: Commit**

```bash
git add internal/creds/store.go
git commit -m "feat(creds): Store interface and Credentials type"
```

---

## Task 9: `creds` package — file backend

**Files:**
- Create: `internal/creds/file.go`
- Create: `internal/creds/file_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/creds/file_test.go`:
```go
package creds

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileStore_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.Equal(t, BackendFile, s.Backend())

	require.NoError(t, s.Save("home", Credentials{Username: "admin", Password: "hunter2"}))

	got, err := s.Load("home")
	require.NoError(t, err)
	require.Equal(t, "admin", got.Username)
	require.Equal(t, "hunter2", got.Password)
}

func TestFileStore_FileWrittenWith0600(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.NoError(t, s.Save("home", Credentials{Username: "u", Password: "p"}))

	info, err := os.Stat(filepath.Join(dir, "credentials.yaml"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFileStore_LoadRefusesLoosePerms(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.NoError(t, s.Save("home", Credentials{Username: "u", Password: "p"}))

	require.NoError(t, os.Chmod(filepath.Join(dir, "credentials.yaml"), 0o644))
	_, err := s.Load("home")
	require.ErrorIs(t, err, ErrInsecurePermissions)
}

func TestFileStore_LoadMissingProfile(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	_, err := s.Load("missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFileStore_Delete(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	require.NoError(t, s.Save("home", Credentials{Username: "u", Password: "p"}))
	require.NoError(t, s.Delete("home"))
	_, err := s.Load("home")
	require.ErrorIs(t, err, ErrNotFound)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/creds -v
```

- [ ] **Step 3: Implement `internal/creds/file.go`**

```go
package creds

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ErrNotFound is returned when no credentials are stored for a given profile.
var ErrNotFound = errors.New("creds: not found")

// ErrInsecurePermissions is returned when the credentials file has perms
// looser than 0600.
var ErrInsecurePermissions = errors.New("creds: file permissions too permissive (must be 0600)")

const credsFileName = "credentials.yaml"

// FileStore persists credentials in <baseDir>/credentials.yaml at mode 0600.
type FileStore struct {
	baseDir string
}

// NewFileStore returns a Store that persists under baseDir.
func NewFileStore(baseDir string) *FileStore {
	return &FileStore{baseDir: baseDir}
}

func (f *FileStore) Backend() string { return BackendFile }

type fileFormat struct {
	Profiles map[string]Credentials `yaml:"profiles"`
}

func (f *FileStore) path() string { return filepath.Join(f.baseDir, credsFileName) }

func (f *FileStore) load() (*fileFormat, error) {
	path := f.path()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &fileFormat{Profiles: map[string]Credentials{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("creds: stat: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("creds: read: %w", err)
	}
	ff := &fileFormat{Profiles: map[string]Credentials{}}
	if err := yaml.Unmarshal(b, ff); err != nil {
		return nil, fmt.Errorf("creds: parse: %w", err)
	}
	if ff.Profiles == nil {
		ff.Profiles = map[string]Credentials{}
	}
	return ff, nil
}

func (f *FileStore) save(ff *fileFormat) error {
	if err := os.MkdirAll(f.baseDir, 0o700); err != nil {
		return fmt.Errorf("creds: mkdir: %w", err)
	}
	b, err := yaml.Marshal(ff)
	if err != nil {
		return fmt.Errorf("creds: marshal: %w", err)
	}
	tmp := f.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("creds: write tmp: %w", err)
	}
	return os.Rename(tmp, f.path())
}

// Load returns the credentials for the given profile.
func (f *FileStore) Load(profile string) (Credentials, error) {
	ff, err := f.load()
	if err != nil {
		return Credentials{}, err
	}
	c, ok := ff.Profiles[profile]
	if !ok {
		return Credentials{}, ErrNotFound
	}
	return c, nil
}

// Save persists credentials for the given profile.
func (f *FileStore) Save(profile string, c Credentials) error {
	ff, err := f.load()
	if err != nil && !errors.Is(err, ErrInsecurePermissions) {
		return err
	}
	if ff == nil {
		ff = &fileFormat{Profiles: map[string]Credentials{}}
	}
	ff.Profiles[profile] = c
	return f.save(ff)
}

// Delete removes credentials for the given profile.
func (f *FileStore) Delete(profile string) error {
	ff, err := f.load()
	if err != nil {
		return err
	}
	delete(ff.Profiles, profile)
	return f.save(ff)
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/creds -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/creds/file.go internal/creds/file_test.go
git commit -m "feat(creds): file backend with 0600 perm enforcement"
```

---

## Task 10: `creds` package — Darwin keychain backend + factory

**Files:**
- Create: `internal/creds/keychain_darwin.go`
- Create: `internal/creds/keychain_other.go`
- Create: `internal/creds/factory.go`
- Create: `internal/creds/factory_test.go`

- [ ] **Step 1: Add keyring dependency**

```bash
go get github.com/zalando/go-keyring@latest
go mod tidy
```

- [ ] **Step 2: Implement the Darwin backend**

Create `internal/creds/keychain_darwin.go`:
```go
//go:build darwin

package creds

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

const keychainService = "sophosfw"

// KeychainStore persists credentials in the macOS keychain.
type KeychainStore struct{}

// NewKeychainStore returns a Store backed by the macOS keychain.
func NewKeychainStore() *KeychainStore { return &KeychainStore{} }

func (*KeychainStore) Backend() string { return BackendKeychain }

// We pack username and password into a single secret as "username\npassword"
// so each profile is one keychain item.
func (*KeychainStore) Load(profile string) (Credentials, error) {
	v, err := keyring.Get(keychainService, profile)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return Credentials{}, ErrNotFound
		}
		return Credentials{}, fmt.Errorf("creds: keychain get: %w", err)
	}
	parts := strings.SplitN(v, "\n", 2)
	if len(parts) != 2 {
		return Credentials{}, fmt.Errorf("creds: malformed keychain entry for %q", profile)
	}
	return Credentials{Username: parts[0], Password: parts[1]}, nil
}

func (*KeychainStore) Save(profile string, c Credentials) error {
	if strings.Contains(c.Username, "\n") {
		return fmt.Errorf("creds: username must not contain newline")
	}
	return keyring.Set(keychainService, profile, c.Username+"\n"+c.Password)
}

func (*KeychainStore) Delete(profile string) error {
	err := keyring.Delete(keychainService, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
```

- [ ] **Step 3: Implement the non-Darwin shim**

Create `internal/creds/keychain_other.go`:
```go
//go:build !darwin

package creds

// KeychainStore is a stub on non-Darwin platforms. The factory does not
// instantiate it; this exists only so cross-platform code can reference the
// type name without build-tag noise.
type KeychainStore struct{}

func NewKeychainStore() *KeychainStore { return &KeychainStore{} }

func (*KeychainStore) Backend() string                          { return BackendKeychain }
func (*KeychainStore) Load(string) (Credentials, error)         { return Credentials{}, ErrNotFound }
func (*KeychainStore) Save(string, Credentials) error           { return ErrNotFound }
func (*KeychainStore) Delete(string) error                      { return nil }
```

- [ ] **Step 4: Implement the platform factory**

Create `internal/creds/factory.go`:
```go
package creds

import "runtime"

// New returns the platform-default Store: keychain on darwin, file elsewhere.
// The fileBaseDir parameter is used by the file backend (typically
// ~/.config/sophosfw).
func New(fileBaseDir string) Store {
	if runtime.GOOS == "darwin" {
		return NewKeychainStore()
	}
	return NewFileStore(fileBaseDir)
}
```

- [ ] **Step 5: Write the factory test**

Create `internal/creds/factory_test.go`:
```go
package creds

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew_PlatformDefault(t *testing.T) {
	s := New(t.TempDir())
	if runtime.GOOS == "darwin" {
		require.Equal(t, BackendKeychain, s.Backend())
	} else {
		require.Equal(t, BackendFile, s.Backend())
	}
}
```

- [ ] **Step 6: Run — must pass**

```bash
go test ./internal/creds -v
```

- [ ] **Step 7: Commit**

```bash
git add internal/creds/keychain_darwin.go internal/creds/keychain_other.go internal/creds/factory.go internal/creds/factory_test.go go.mod go.sum
git commit -m "feat(creds): macOS keychain backend and platform factory"
```

---

## Task 11: `sophos` package — request envelope builder

**Files:**
- Create: `internal/sophos/request.go`
- Create: `internal/sophos/request_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sophos/request_test.go`:
```go
package sophos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildEnvelope_GetSimpleTag(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}}
	xml, err := BuildEnvelope(env, "admin", "secret")
	require.NoError(t, err)
	s := string(xml)
	require.Contains(t, s, "<Request>")
	require.Contains(t, s, "<Login>")
	require.Contains(t, s, "<Username>admin</Username>")
	require.Contains(t, s, "<Password>secret</Password>")
	require.Contains(t, s, "<Get>")
	require.Contains(t, s, "<IPHost></IPHost>")
}

func TestBuildEnvelope_GetWithName(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost", Name: "LAN"}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	s := string(xml)
	require.Contains(t, s, "<IPHost>")
	require.Contains(t, s, "<Filter>")
	require.Contains(t, s, "<key name=\"Name\" criteria=\"=\">LAN</key>")
}

func TestBuildEnvelope_GetWithFilterLike(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{
		XMLTag: "IPHost",
		Filter: &FilterClause{Field: "Name", Criteria: "like", Value: "LAN"},
	}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	require.Contains(t, string(xml), `<key name="Name" criteria="like">LAN</key>`)
}

func TestBuildEnvelope_StatisticsOp(t *testing.T) {
	env := Envelope{Operations: []Op{StatisticsOp{
		XMLTag: "IPHostStatistics",
		Filter: &FilterClause{Field: "Name", Criteria: "=", Value: "LAN"},
	}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	s := string(xml)
	require.Contains(t, s, "<IPHostStatistics>")
	require.Contains(t, s, `<key name="Name" criteria="=">LAN</key>`)
}

func TestBuildEnvelope_EscapesUserInput(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost", Name: "LAN<bad>&'"}}}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	// Critical: must be escaped, not concatenated.
	require.NotContains(t, string(xml), "<bad>")
	require.Contains(t, string(xml), "&lt;")
	require.Contains(t, string(xml), "&amp;")
}

func TestBuildEnvelope_WithTransactionID(t *testing.T) {
	env := Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}, TxnID: "abc-123"}
	xml, err := BuildEnvelope(env, "u", "p")
	require.NoError(t, err)
	require.Contains(t, string(xml), "<transactionid>abc-123</transactionid>")
}

func TestBuildEnvelope_RawIsReturnedAsIs(t *testing.T) {
	raw := []byte(`<Request><Get><Zone></Zone></Get></Request>`)
	got, err := BuildRawEnvelope(raw, "u", "p")
	require.NoError(t, err)
	// Login must be injected even into a raw envelope.
	require.True(t, strings.Contains(string(got), "<Login>"))
	require.True(t, strings.Contains(string(got), "<Username>u</Username>"))
	require.True(t, strings.Contains(string(got), "<Password>p</Password>"))
	require.True(t, strings.Contains(string(got), "<Get><Zone></Zone></Get>"))
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/sophos -run TestBuildEnvelope -v
```

- [ ] **Step 3: Implement `internal/sophos/request.go`**

```go
// Package sophos implements the Sophos Firewall XML API client: request
// envelope construction, response parsing, status normalization, and HTTP
// transport. Login credentials are owned by this package and injected at
// send time so service-layer code never touches them.
package sophos

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

// Op is implemented by all envelope operations (GetOp, StatisticsOp, …).
type Op interface{ isOp() }

// GetOp models a `<Get><Tag>…</Tag></Get>` envelope. If Name is set it is
// converted to a Name=Value filter. If Filter is set it is used directly.
type GetOp struct {
	XMLTag string
	Name   string
	Filter *FilterClause
}

func (GetOp) isOp() {}

// StatisticsOp models a `<TagStatistics>…</TagStatistics>` envelope with an
// optional rich-criteria filter.
type StatisticsOp struct {
	XMLTag string // e.g. "IPHostStatistics"
	Filter *FilterClause
}

func (StatisticsOp) isOp() {}

// FilterClause is a single field/criteria/value tuple. Validation against the
// allowed criteria set lives in filter.go.
type FilterClause struct {
	Field    string
	Criteria string
	Value    string
}

// Envelope is the user-facing description of an outbound request. The client
// injects credentials and serializes to XML at send time.
type Envelope struct {
	Operations []Op
	TxnID      string
}

// BuildEnvelope serializes an Envelope into a Sophos `<Request>` XML body
// with Login injected.
func BuildEnvelope(env Envelope, username, password string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<Request>")

	if env.TxnID != "" {
		buf.WriteString("<transactionid>")
		if err := xml.EscapeText(&buf, []byte(env.TxnID)); err != nil {
			return nil, err
		}
		buf.WriteString("</transactionid>")
	}

	if err := writeLogin(&buf, username, password); err != nil {
		return nil, err
	}

	for _, op := range env.Operations {
		switch o := op.(type) {
		case GetOp:
			if err := writeGetOp(&buf, o); err != nil {
				return nil, err
			}
		case StatisticsOp:
			if err := writeStatisticsOp(&buf, o); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("sophos: unknown operation type %T", op)
		}
	}

	buf.WriteString("</Request>")
	return buf.Bytes(), nil
}

// BuildRawEnvelope wraps a user-supplied operation body in a `<Request>` with
// Login injected. The raw bytes may be a complete `<Request>…</Request>` (in
// which case we splice Login in after `<Request>`) or just the operation
// body.
func BuildRawEnvelope(raw []byte, username, password string) ([]byte, error) {
	var login bytes.Buffer
	if err := writeLogin(&login, username, password); err != nil {
		return nil, err
	}

	if bytes.Contains(raw, []byte("<Request>")) {
		// Splice Login in immediately after the opening Request tag.
		out := bytes.Replace(raw, []byte("<Request>"), append([]byte("<Request>"), login.Bytes()...), 1)
		return out, nil
	}
	// Wrap.
	var out bytes.Buffer
	out.WriteString("<Request>")
	out.Write(login.Bytes())
	out.Write(raw)
	out.WriteString("</Request>")
	return out.Bytes(), nil
}

func writeLogin(buf *bytes.Buffer, username, password string) error {
	buf.WriteString("<Login>")
	buf.WriteString("<Username>")
	if err := xml.EscapeText(buf, []byte(username)); err != nil {
		return err
	}
	buf.WriteString("</Username>")
	buf.WriteString("<Password>")
	if err := xml.EscapeText(buf, []byte(password)); err != nil {
		return err
	}
	buf.WriteString("</Password>")
	buf.WriteString("</Login>")
	return nil
}

func writeGetOp(buf *bytes.Buffer, o GetOp) error {
	if o.XMLTag == "" {
		return fmt.Errorf("sophos: GetOp requires XMLTag")
	}
	buf.WriteString("<Get>")
	buf.WriteString("<")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")

	switch {
	case o.Filter != nil:
		if err := writeFilter(buf, *o.Filter); err != nil {
			return err
		}
	case o.Name != "":
		if err := writeFilter(buf, FilterClause{Field: "Name", Criteria: "=", Value: o.Name}); err != nil {
			return err
		}
	}

	buf.WriteString("</")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")
	buf.WriteString("</Get>")
	return nil
}

func writeStatisticsOp(buf *bytes.Buffer, o StatisticsOp) error {
	if o.XMLTag == "" {
		return fmt.Errorf("sophos: StatisticsOp requires XMLTag")
	}
	buf.WriteString("<")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")

	if o.Filter != nil {
		if err := writeFilter(buf, *o.Filter); err != nil {
			return err
		}
	}

	buf.WriteString("</")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")
	return nil
}

func writeFilter(buf *bytes.Buffer, f FilterClause) error {
	buf.WriteString("<Filter>")
	buf.WriteString(`<key name="`)
	if err := xml.EscapeText(buf, []byte(f.Field)); err != nil {
		return err
	}
	buf.WriteString(`" criteria="`)
	if err := xml.EscapeText(buf, []byte(f.Criteria)); err != nil {
		return err
	}
	buf.WriteString(`">`)
	if err := xml.EscapeText(buf, []byte(f.Value)); err != nil {
		return err
	}
	buf.WriteString("</key>")
	buf.WriteString("</Filter>")
	return nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/sophos -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/sophos/request.go internal/sophos/request_test.go
git commit -m "feat(sophos): XML envelope builder with login injection and escaping"
```

---

## Task 12: `sophos` package — `Filter` validation

**Files:**
- Create: `internal/sophos/filter.go`
- Create: `internal/sophos/filter_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sophos/filter_test.go`:
```go
package sophos

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterClauseValidate_Object_AllowedCriteria(t *testing.T) {
	for _, c := range []string{"=", "!=", "like"} {
		require.NoError(t, FilterClause{Field: "Name", Criteria: c, Value: "x"}.ValidateForGet(),
			"criteria %q must be allowed for Get", c)
	}
}

func TestFilterClauseValidate_Object_RejectsStatsCriteria(t *testing.T) {
	require.Error(t, FilterClause{Field: "Name", Criteria: "startswith", Value: "x"}.ValidateForGet())
	require.Error(t, FilterClause{Field: "Name", Criteria: ">=", Value: "x"}.ValidateForGet())
}

func TestFilterClauseValidate_Stats_AllowsRichCriteria(t *testing.T) {
	for _, c := range []string{"=", "!=", "like", "not like", "startswith", "in", ">", ">="} {
		require.NoError(t, FilterClause{Field: "Name", Criteria: c, Value: "x"}.ValidateForStatistics(),
			"criteria %q must be allowed for Statistics", c)
	}
}

func TestFilterClauseValidate_RejectsEmptyField(t *testing.T) {
	require.Error(t, FilterClause{Field: "", Criteria: "=", Value: "x"}.ValidateForGet())
}

func TestParseFilterFlag_FieldCriteriaValue(t *testing.T) {
	f, err := ParseFilterFlag("Name:like:LAN")
	require.NoError(t, err)
	require.Equal(t, "Name", f.Field)
	require.Equal(t, "like", f.Criteria)
	require.Equal(t, "LAN", f.Value)
}

func TestParseFilterFlag_AllowsColonsInValue(t *testing.T) {
	f, err := ParseFilterFlag("URL:like:https://x:4444")
	require.NoError(t, err)
	require.Equal(t, "URL", f.Field)
	require.Equal(t, "like", f.Criteria)
	require.Equal(t, "https://x:4444", f.Value)
}

func TestParseFilterFlag_BadFormat(t *testing.T) {
	_, err := ParseFilterFlag("Name=LAN")
	require.Error(t, err)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/sophos -run TestFilter -v
```

- [ ] **Step 3: Implement `internal/sophos/filter.go`**

```go
package sophos

import (
	"fmt"
	"strings"
)

var (
	getCriteria = map[string]struct{}{
		"=":    {},
		"!=":   {},
		"like": {},
	}
	statsCriteria = map[string]struct{}{
		"=":          {},
		"!=":         {},
		"like":       {},
		"not like":   {},
		"startswith": {},
		"in":         {},
		">":          {},
		">=":         {},
	}
)

// ValidateForGet returns an error if the criteria isn't valid for object Get.
func (f FilterClause) ValidateForGet() error {
	if f.Field == "" {
		return fmt.Errorf("filter: Field is required")
	}
	if _, ok := getCriteria[f.Criteria]; !ok {
		return fmt.Errorf("filter: %q is not a valid Get criteria (allowed: =, !=, like)", f.Criteria)
	}
	return nil
}

// ValidateForStatistics returns an error if the criteria isn't valid for *Statistics queries.
func (f FilterClause) ValidateForStatistics() error {
	if f.Field == "" {
		return fmt.Errorf("filter: Field is required")
	}
	if _, ok := statsCriteria[f.Criteria]; !ok {
		return fmt.Errorf("filter: %q is not a valid Statistics criteria", f.Criteria)
	}
	return nil
}

// ParseFilterFlag parses the user-facing `--filter Field:Criteria:Value`
// syntax. Values may contain colons; only the first two colons split the
// fields.
func ParseFilterFlag(s string) (FilterClause, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return FilterClause{}, fmt.Errorf("filter: expected Field:Criteria:Value, got %q", s)
	}
	return FilterClause{Field: parts[0], Criteria: parts[1], Value: parts[2]}, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/sophos -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/sophos/filter.go internal/sophos/filter_test.go
git commit -m "feat(sophos): FilterClause validation and --filter flag parser"
```

---

## Task 13: `sophos` package — `<Status>` normalization to typed errors

**Files:**
- Create: `internal/sophos/status.go`
- Create: `internal/sophos/status_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sophos/status_test.go`:
```go
package sophos

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatusToError_SuccessReturnsNil(t *testing.T) {
	require.NoError(t, statusToError(200, "Operation Successful"))
	require.NoError(t, statusToError(216, "Operation Completed Successfully"))
}

func TestStatusToError_AuthFailed(t *testing.T) {
	err := statusToError(534, "Authentication Failure")
	require.ErrorIs(t, err, ErrAuthFailed)
}

func TestStatusToError_NotFound(t *testing.T) {
	err := statusToError(526, "No matching record found")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestStatusToError_PermissionDenied(t *testing.T) {
	err := statusToError(535, "Permission denied")
	require.ErrorIs(t, err, ErrPermissionDenied)
}

func TestStatusToError_InvalidRequest(t *testing.T) {
	err := statusToError(500, "Bad request")
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestStatusToError_GenericServerError(t *testing.T) {
	err := statusToError(599, "Server error")
	require.ErrorIs(t, err, ErrServerError)
}

func TestStatusToError_PreservesCodeAndMessage(t *testing.T) {
	err := statusToError(534, "Authentication Failure")
	var sErr *StatusError
	require.True(t, errors.As(err, &sErr))
	require.Equal(t, 534, sErr.Code)
	require.Equal(t, "Authentication Failure", sErr.Message)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/sophos -run TestStatus -v
```

- [ ] **Step 3: Implement `internal/sophos/status.go`**

```go
package sophos

import (
	"errors"
	"fmt"
)

// Sentinel errors. Higher layers compare with errors.Is to map to
// sophosfw.v1.error envelope kinds.
var (
	ErrAuthFailed         = errors.New("sophos: authentication failed")
	ErrNotFound           = errors.New("sophos: object not found")
	ErrPermissionDenied   = errors.New("sophos: permission denied")
	ErrInvalidRequest     = errors.New("sophos: invalid request")
	ErrServerError        = errors.New("sophos: server error")
	ErrReadOnlyViolation  = errors.New("sophos: read-only profile rejected mutating XML")
)

// StatusError wraps the original numeric code and message so callers can
// surface them while still matching against a sentinel via errors.Is.
type StatusError struct {
	Code    int
	Message string
	Sentinel error
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("sophos status %d: %s", e.Code, e.Message)
}

func (e *StatusError) Unwrap() error { return e.Sentinel }

// statusToError converts a Sophos status code to a typed error. Returns nil
// for success codes.
func statusToError(code int, message string) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == 534:
		return &StatusError{Code: code, Message: message, Sentinel: ErrAuthFailed}
	case code == 526:
		return &StatusError{Code: code, Message: message, Sentinel: ErrNotFound}
	case code == 535:
		return &StatusError{Code: code, Message: message, Sentinel: ErrPermissionDenied}
	case code >= 500 && code <= 530:
		return &StatusError{Code: code, Message: message, Sentinel: ErrInvalidRequest}
	default:
		return &StatusError{Code: code, Message: message, Sentinel: ErrServerError}
	}
}
```

> **Note for the implementer:** The exact code-to-sentinel mapping above is a *starting point* derived from the Sophos 22.0 API docs (534 = auth failure, 526 = no record, 535 = permission denied). If integration testing reveals the firewall returns a different code for a case we care about, update this mapping (and add a test) — the design intentionally puts the table in one place.

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/sophos -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/sophos/status.go internal/sophos/status_test.go
git commit -m "feat(sophos): status code normalization to typed errors"
```

---

## Task 14: `sophos` package — generic response parser

**Files:**
- Create: `internal/sophos/response.go`
- Create: `internal/sophos/response_test.go`
- Create: `testdata/sophos/responses/iphost_list_2.xml`
- Create: `testdata/sophos/responses/iphost_get_one.xml`
- Create: `testdata/sophos/responses/auth_failure.xml`
- Create: `testdata/sophos/responses/empty_result.xml`

- [ ] **Step 1: Create fixtures**

Create `testdata/sophos/responses/iphost_list_2.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <IPHost transactionid="">
    <Name>LAN-network</Name>
    <IPFamily>IPv4</IPFamily>
    <HostType>Network</HostType>
    <IPAddress>10.0.0.0</IPAddress>
    <Subnet>255.255.255.0</Subnet>
  </IPHost>
  <IPHost transactionid="">
    <Name>DMZ</Name>
    <IPFamily>IPv4</IPFamily>
    <HostType>Network</HostType>
    <IPAddress>192.168.10.0</IPAddress>
    <Subnet>255.255.255.0</Subnet>
  </IPHost>
</Response>
```

Create `testdata/sophos/responses/iphost_get_one.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <IPHost transactionid="">
    <Name>LAN-network</Name>
    <IPFamily>IPv4</IPFamily>
    <HostType>Network</HostType>
    <IPAddress>10.0.0.0</IPAddress>
    <Subnet>255.255.255.0</Subnet>
  </IPHost>
</Response>
```

Create `testdata/sophos/responses/auth_failure.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
  <Login><status>Authentication Failure</status></Login>
</Response>
```

Create `testdata/sophos/responses/empty_result.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <IPHost transactionid="">
    <Status code="526">No matching record found</Status>
  </IPHost>
</Response>
```

- [ ] **Step 2: Write the failing tests**

Create `internal/sophos/response_test.go`:
```go
package sophos

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func TestParseResponse_IPHostList(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/iphost_list_2.xml"))
	require.NoError(t, err)
	require.True(t, r.LoginOK)
	require.Equal(t, "Authentication Successful", r.LoginStatus)
	require.Len(t, r.Body["IPHost"], 2)
}

func TestParseResponse_AuthFailure(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/auth_failure.xml"))
	require.NoError(t, err) // parse OK
	require.False(t, r.LoginOK)
	require.ErrorIs(t, r.AsError(), ErrAuthFailed)
}

func TestParseResponse_EmptyResultIsNotFound(t *testing.T) {
	r, err := ParseResponse(mustRead(t, "../../testdata/sophos/responses/empty_result.xml"))
	require.NoError(t, err)
	require.True(t, r.LoginOK)
	// Per-tag inner Status code 526 should surface via AsError as ErrNotFound.
	require.ErrorIs(t, r.AsError(), ErrNotFound)
}

func TestParseResponse_MalformedXML(t *testing.T) {
	_, err := ParseResponse([]byte("<not xml"))
	require.Error(t, err)
}
```

- [ ] **Step 3: Run — must fail**

```bash
go test ./internal/sophos -run TestParseResponse -v
```

- [ ] **Step 4: Implement `internal/sophos/response.go`**

```go
package sophos

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
)

// Response is the parsed shape of a Sophos `<Response>` envelope.
type Response struct {
	APIVersion  string
	LoginOK     bool
	LoginStatus string

	// Body is keyed by XML tag (e.g. "IPHost"). Each value is a slice of raw
	// per-record JSON fragments (we convert XML records to JSON for downstream
	// consumption). Unknown tags survive intact.
	Body map[string][]json.RawMessage

	// embeddedStatuses captures `<Tag><Status code="…">…</Status></Tag>`
	// blocks per tag so AsError can surface them.
	embeddedStatuses []embeddedStatus
}

type embeddedStatus struct {
	Tag     string
	Code    int
	Message string
}

// ParseResponse parses a Sophos XML response. Returns an error only for
// malformed XML — Sophos status codes inside the response are surfaced via
// Response.AsError() so callers can inspect the body even on failure.
func ParseResponse(b []byte) (*Response, error) {
	r := &Response{Body: map[string][]json.RawMessage{}}

	dec := xml.NewDecoder(bytes.NewReader(b))
	var (
		root    string
		current string
		buf     bytes.Buffer
		depth   int
		inLogin bool
		loginSb bytes.Buffer
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("sophos: parse: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if root == "" && t.Name.Local == "Response" {
				for _, a := range t.Attr {
					if a.Name.Local == "APIVersion" {
						r.APIVersion = a.Value
					}
				}
				root = "Response"
				continue
			}

			if depth == 2 && t.Name.Local == "Login" {
				inLogin = true
				loginSb.Reset()
				continue
			}

			if depth == 2 {
				current = t.Name.Local
				buf.Reset()
				if err := encodeStart(&buf, t); err != nil {
					return nil, err
				}
				continue
			}

			if current != "" {
				if err := encodeStart(&buf, t); err != nil {
					return nil, err
				}
			}

		case xml.EndElement:
			depth--

			if inLogin && t.Name.Local == "Login" {
				r.LoginStatus = loginSb.String()
				r.LoginOK = r.LoginStatus == "Authentication Successful"
				inLogin = false
				continue
			}

			if depth == 1 && current != "" {
				// Closing tag of a top-level child of Response.
				fmt.Fprintf(&buf, "</%s>", t.Name.Local)
				if err := r.absorbRecord(current, buf.Bytes()); err != nil {
					return nil, err
				}
				current = ""
				buf.Reset()
				continue
			}

			if current != "" {
				fmt.Fprintf(&buf, "</%s>", t.Name.Local)
			}

		case xml.CharData:
			if inLogin {
				loginSb.Write(t)
			} else if current != "" {
				if err := xml.EscapeText(&buf, t); err != nil {
					return nil, err
				}
			}
		}
	}

	return r, nil
}

func encodeStart(w *bytes.Buffer, s xml.StartElement) error {
	w.WriteString("<")
	w.WriteString(s.Name.Local)
	for _, a := range s.Attr {
		fmt.Fprintf(w, ` %s="`, a.Name.Local)
		if err := xml.EscapeText(w, []byte(a.Value)); err != nil {
			return err
		}
		w.WriteString(`"`)
	}
	w.WriteString(">")
	return nil
}

// absorbRecord converts the raw XML fragment for one top-level child element
// into a JSON map and appends it to Body[tag]. If the fragment carries an
// embedded `<Status code="…">…</Status>`, it's recorded for AsError.
func (r *Response) absorbRecord(tag string, raw []byte) error {
	// Detect embedded Status (e.g., empty-result tag carrying code 526).
	if code, msg, ok := extractEmbeddedStatus(raw); ok {
		r.embeddedStatuses = append(r.embeddedStatuses, embeddedStatus{Tag: tag, Code: code, Message: msg})
		return nil
	}

	m, err := xmlFragmentToMap(raw)
	if err != nil {
		return fmt.Errorf("sophos: convert %s: %w", tag, err)
	}
	jb, err := json.Marshal(m)
	if err != nil {
		return err
	}
	r.Body[tag] = append(r.Body[tag], json.RawMessage(jb))
	return nil
}

// AsError returns nil if the response is fully successful, or a typed error
// derived from the strongest signal in the response (login first, then
// embedded per-tag status codes).
func (r *Response) AsError() error {
	if !r.LoginOK {
		return &StatusError{Code: 534, Message: r.LoginStatus, Sentinel: ErrAuthFailed}
	}
	for _, s := range r.embeddedStatuses {
		if err := statusToError(s.Code, s.Message); err != nil {
			return err
		}
	}
	return nil
}

func extractEmbeddedStatus(raw []byte) (int, string, bool) {
	// Cheap pattern: look for <Status code="NNN">message</Status>
	const open = `<Status code="`
	idx := bytes.Index(raw, []byte(open))
	if idx < 0 {
		return 0, "", false
	}
	rest := raw[idx+len(open):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return 0, "", false
	}
	codeStr := string(rest[:end])
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return 0, "", false
	}
	rest = rest[end:]
	gt := bytes.IndexByte(rest, '>')
	if gt < 0 {
		return 0, "", false
	}
	rest = rest[gt+1:]
	closeIdx := bytes.Index(rest, []byte("</Status>"))
	if closeIdx < 0 {
		return code, "", true
	}
	return code, string(rest[:closeIdx]), true
}

// xmlFragmentToMap converts an XML element (with its outer tag) to a
// map[string]any with child element names as keys. Lossy for attributes and
// mixed content, which is acceptable for Sophos response shapes.
func xmlFragmentToMap(raw []byte) (map[string]any, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	stack := []map[string]any{}
	var current map[string]any
	var lastKey string
	var charBuf bytes.Buffer

	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			next := map[string]any{}
			if current == nil {
				current = next
				stack = append(stack, current)
				lastKey = ""
				continue
			}
			lastKey = t.Name.Local
			stack = append(stack, next)
			// Will assign on EndElement.
			charBuf.Reset()

		case xml.CharData:
			charBuf.Write(t)

		case xml.EndElement:
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			text := bytesTrim(charBuf.Bytes())
			charBuf.Reset()

			var value any
			if len(top) > 0 {
				value = top
			} else {
				value = string(text)
			}

			if len(stack) == 0 {
				return current, nil
			}
			parent := stack[len(stack)-1]
			parent[t.Name.Local] = value
			lastKey = ""
		}
	}
	return current, nil
}

func bytesTrim(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\t' || b[start] == '\r') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\t' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}
```

> **Implementer note:** The `xmlFragmentToMap` parser above is intentionally simple. It handles Sophos's typical "leaf elements with text or nested elements with children" shape. If integration testing reveals records with attributes that matter (besides `Status code=`) or mixed content, augment the parser and add fixtures. Don't over-engineer it now.

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/sophos -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/sophos/response.go internal/sophos/response_test.go testdata/sophos/responses/
git commit -m "feat(sophos): generic response parser with embedded status detection"
```

---

## Task 15: `sophos` package — HTTP client (`Do` / `DoRaw`)

**Files:**
- Create: `internal/sophos/client.go`
- Create: `internal/sophos/client_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sophos/client_test.go`:
```go
package sophos

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestClient_Do_PostsReqxmlForm(t *testing.T) {
	var receivedBody string
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/webconsole/APIController", r.URL.Path)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		require.NoError(t, r.ParseForm())
		receivedBody = r.Form.Get("reqxml")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login></Response>`)
	})

	c := newClientWithRoots(t, srv.URL, pool)
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(receivedBody, "<Request>"))
	require.Contains(t, receivedBody, "<Username>u</Username>")
	require.Contains(t, receivedBody, "<Get><IPHost></IPHost></Get>")
}

func TestClient_Do_RejectsMutatingWhenReadOnly(t *testing.T) {
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server must not be reached for read-only violation")
	})
	c := newClientWithRoots(t, srv.URL, pool)
	c.ReadOnly = true

	raw := []byte(`<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>`)
	_, err := c.DoRaw(context.Background(), raw)
	require.ErrorIs(t, err, ErrReadOnlyViolation)
}

func TestClient_Do_AuthFailureSurfacesAsError(t *testing.T) {
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<Response APIVersion="2200.1"><Login><status>Authentication Failure</status></Login></Response>`)
	})
	c := newClientWithRoots(t, srv.URL, pool)
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.ErrorIs(t, err, ErrAuthFailed)
}

func TestClient_Do_TimeoutHonored(t *testing.T) {
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	})
	c := newClientWithRoots(t, srv.URL, pool)
	c.Timeout = 10 * time.Millisecond
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.Error(t, err)
}

func TestClient_Do_WarnsOnInsecureSkipVerify(t *testing.T) {
	srv, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<Response><Login><status>Authentication Successful</status></Login></Response>`)
	})
	c := NewClient(ClientConfig{
		BaseURL:            srv.URL,
		Username:           "u",
		Password:           "p",
		InsecureSkipVerify: true,
	})
	stderrBuf := &bytes.Buffer{}
	c.Stderr = stderrBuf
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.NoError(t, err)
	require.Contains(t, stderrBuf.String(), "TLS verification disabled")
}

// newClientWithRoots builds a client trusting a single test cert. Tests do
// NOT use InsecureSkipVerify so that the trust path itself is exercised.
func newClientWithRoots(t *testing.T, base string, pool *x509.CertPool) *Client {
	t.Helper()
	u, err := url.Parse(base)
	require.NoError(t, err)
	c := NewClient(ClientConfig{
		BaseURL:  u.String(),
		Username: "u",
		Password: "p",
		Timeout:  5 * time.Second,
	})
	c.HTTPClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	return c
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/sophos -run TestClient -v
```

- [ ] **Step 3: Implement `internal/sophos/client.go`**

```go
package sophos

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/iainmoffat/sophosfw/internal/safety"
)

// ClientConfig configures a sophos.Client.
type ClientConfig struct {
	BaseURL            string        // e.g. https://fw.example.com:4444
	Username           string
	Password           string
	Timeout            time.Duration
	InsecureSkipVerify bool
	ReadOnly           bool
}

// Client speaks the Sophos XML API over HTTP. Credentials are owned by the
// client and injected into every envelope at send time.
type Client struct {
	BaseURL            string
	Username           string
	Password           string
	Timeout            time.Duration
	InsecureSkipVerify bool
	ReadOnly           bool

	HTTPClient *http.Client
	Stderr     io.Writer // for the per-call --insecure-skip-verify warning
}

// NewClient constructs a Client from the given config.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec
	}
	return &Client{
		BaseURL:            strings.TrimRight(cfg.BaseURL, "/"),
		Username:           cfg.Username,
		Password:           cfg.Password,
		Timeout:            cfg.Timeout,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ReadOnly:           cfg.ReadOnly,
		HTTPClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		// Stderr defaults to os.Stderr; tests can swap it.
		Stderr: stderr(),
	}
}

// stderr is a package-level indirection so tests can capture warnings.
var stderr = func() io.Writer { return os.Stderr }

// Do builds an envelope from `env`, sends it, and returns the parsed response.
func (c *Client) Do(ctx context.Context, env Envelope) (*Response, error) {
	xmlBody, err := BuildEnvelope(env, c.Username, c.Password)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, xmlBody)
}

// DoRaw sends a user-supplied XML envelope. Login is injected if not present.
func (c *Client) DoRaw(ctx context.Context, raw []byte) (*Response, error) {
	body, err := BuildRawEnvelope(raw, c.Username, c.Password)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, body)
}

func (c *Client) send(ctx context.Context, xmlBody []byte) (*Response, error) {
	if c.ReadOnly {
		if mutating, verbs := safety.IsMutating(xmlBody); mutating {
			return nil, fmt.Errorf("%w: %s", ErrReadOnlyViolation, strings.Join(verbs, ","))
		}
	}

	if c.InsecureSkipVerify && c.Stderr != nil {
		fmt.Fprintln(c.Stderr, "warning: TLS verification disabled for this request (--insecure-skip-verify)")
	}

	form := url.Values{}
	form.Set("reqxml", string(xmlBody))

	endpoint := c.BaseURL + "/webconsole/APIController"
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sophos: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sophos: read response: %w", err)
	}

	parsed, err := ParseResponse(respBody)
	if err != nil {
		return nil, err
	}
	if err := parsed.AsError(); err != nil {
		return parsed, err
	}
	return parsed, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/sophos -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/sophos/client.go internal/sophos/client_test.go
git commit -m "feat(sophos): HTTP client (Do/DoRaw) with read-only enforcement"
```

---

## Task 16: `catalog` package — YAML loader and lookup

**Files:**
- Create: `internal/catalog/catalog.go`
- Create: `internal/catalog/catalog_test.go`
- Create: `internal/catalog/testdata/sample.yaml`

- [ ] **Step 1: Create the test fixture**

Create `internal/catalog/testdata/sample.yaml`:
```yaml
objects:
  - tag: IPHost
    aliases: [host-ip, ip-host]
    description: "IP host objects"
    columns: [Name, IPFamily, HostType, IPAddress, Subnet]
    filterable: [Name, IPAddress, IPFamily, HostType]
    usageTag: IPHostStatistics
    typedParser: iphost
  - tag: Services
    aliases: [service]
    description: "Service objects"
    columns: [Name, Type, ServiceDetails]
    filterable: [Name, Type]
    usageTag: ServicesStatistics
    typedParser: service
```

- [ ] **Step 2: Write the failing tests**

Create `internal/catalog/catalog_test.go`:
```go
package catalog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad_ReadsObjects(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)
	tags := c.Tags()
	require.ElementsMatch(t, []string{"IPHost", "Services"}, tags)
}

func TestResolve_ByTag(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)
	e, ok := c.Resolve("IPHost")
	require.True(t, ok)
	require.Equal(t, "IPHost", e.Tag)
	require.Equal(t, "IPHostStatistics", e.UsageTag)
	require.Equal(t, []string{"Name", "IPFamily", "HostType", "IPAddress", "Subnet"}, e.Columns)
}

func TestResolve_ByAlias(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)

	e, ok := c.Resolve("host-ip")
	require.True(t, ok)
	require.Equal(t, "IPHost", e.Tag)

	e, ok = c.Resolve("service")
	require.True(t, ok)
	require.Equal(t, "Services", e.Tag)
}

func TestResolve_Unknown(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	require.NoError(t, err)
	_, ok := c.Resolve("nope")
	require.False(t, ok)
}

func TestLoad_AmbiguousAliasIsAnError(t *testing.T) {
	_, err := loadFromBytes([]byte(`
objects:
  - tag: A
    aliases: [shared]
  - tag: B
    aliases: [shared]
`))
	require.Error(t, err)
}
```

- [ ] **Step 3: Run — must fail**

```bash
go test ./internal/catalog -v
```

- [ ] **Step 4: Implement `internal/catalog/catalog.go`**

```go
// Package catalog is the hybrid metadata + typed-parser registry for Sophos
// XML tags. The bulk of the catalog is YAML; first-class objects also have
// Go-typed unmarshallers registered programmatically.
package catalog

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Entry describes a single Sophos XML tag.
type Entry struct {
	Tag         string   `yaml:"tag"`
	Aliases     []string `yaml:"aliases"`
	Description string   `yaml:"description"`
	Columns     []string `yaml:"columns"`
	Filterable  []string `yaml:"filterable"`
	UsageTag    string   `yaml:"usageTag"`
	TypedParser string   `yaml:"typedParser"`
}

// Catalog holds all known XML tags.
type Catalog struct {
	entries  []Entry
	byTag    map[string]*Entry
	byAlias  map[string]*Entry
	parsers  map[string]TypedParser
}

// TypedParser converts a single record's JSON fragment (produced by the
// generic response parser) into a typed Go struct.
type TypedParser func(json.RawMessage) (any, error)

type yamlDoc struct {
	Objects []Entry `yaml:"objects"`
}

// Load reads the catalog YAML from path.
func Load(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: read %s: %w", path, err)
	}
	return loadFromBytes(b)
}

func loadFromBytes(b []byte) (*Catalog, error) {
	var doc yamlDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("catalog: parse: %w", err)
	}
	c := &Catalog{
		entries: doc.Objects,
		byTag:   map[string]*Entry{},
		byAlias: map[string]*Entry{},
		parsers: map[string]TypedParser{},
	}
	for i := range c.entries {
		e := &c.entries[i]
		if _, dup := c.byTag[e.Tag]; dup {
			return nil, fmt.Errorf("catalog: duplicate tag %q", e.Tag)
		}
		c.byTag[e.Tag] = e
		for _, a := range e.Aliases {
			if _, dup := c.byAlias[a]; dup {
				return nil, fmt.Errorf("catalog: duplicate alias %q", a)
			}
			c.byAlias[a] = e
		}
	}
	return c, nil
}

// Tags returns all canonical tag names.
func (c *Catalog) Tags() []string {
	out := make([]string, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.Tag)
	}
	return out
}

// Resolve returns the entry for either a canonical tag or an alias.
func (c *Catalog) Resolve(nameOrAlias string) (*Entry, bool) {
	if e, ok := c.byTag[nameOrAlias]; ok {
		return e, true
	}
	if e, ok := c.byAlias[nameOrAlias]; ok {
		return e, true
	}
	return nil, false
}

// RegisterParser associates a typed parser with the typedParser identifier in
// the catalog YAML (e.g. "iphost"). Idiomatic call site: in package init().
func (c *Catalog) RegisterParser(name string, p TypedParser) {
	c.parsers[name] = p
}

// Parse dispatches a record to its typed parser if registered, else returns
// the raw fragment unmarshalled as map[string]any.
func (c *Catalog) Parse(tag string, raw json.RawMessage) (any, error) {
	e, ok := c.byTag[tag]
	if !ok {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	if e.TypedParser == "" {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	parser, ok := c.parsers[e.TypedParser]
	if !ok {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	return parser(raw)
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/catalog -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/catalog/catalog.go internal/catalog/catalog_test.go internal/catalog/testdata/
git commit -m "feat(catalog): YAML loader with tag+alias lookup and typed-parser dispatch"
```

---

## Task 17: `catalog` — typed `IPHost` parser

**Files:**
- Create: `internal/catalog/iphost.go`
- Create: `internal/catalog/iphost_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/catalog/iphost_test.go`:
```go
package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPHostParser_ParsesNetworkRecord(t *testing.T) {
	raw := json.RawMessage(`{
		"Name": "LAN-network",
		"IPFamily": "IPv4",
		"HostType": "Network",
		"IPAddress": "10.0.0.0",
		"Subnet": "255.255.255.0"
	}`)
	v, err := IPHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(IPHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "LAN-network", host.Name)
	require.Equal(t, "Network", host.HostType)
	require.Equal(t, "10.0.0.0", host.IPAddress)
}

func TestIPHostParser_ParsesRangeRecord(t *testing.T) {
	raw := json.RawMessage(`{"Name":"R","IPFamily":"IPv4","HostType":"IPRange","StartIPAddress":"10.0.0.1","EndIPAddress":"10.0.0.10"}`)
	v, err := IPHostParser(raw)
	require.NoError(t, err)
	host := v.(IPHost)
	require.Equal(t, "10.0.0.1", host.StartIPAddress)
	require.Equal(t, "10.0.0.10", host.EndIPAddress)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/catalog -run TestIPHostParser -v
```

- [ ] **Step 3: Implement `internal/catalog/iphost.go`**

```go
package catalog

import "encoding/json"

// IPHost is the typed view of a Sophos IPHost record.
type IPHost struct {
	Name           string `json:"Name"`
	IPFamily       string `json:"IPFamily"`
	HostType       string `json:"HostType"`
	IPAddress      string `json:"IPAddress,omitempty"`
	Subnet         string `json:"Subnet,omitempty"`
	StartIPAddress string `json:"StartIPAddress,omitempty"`
	EndIPAddress   string `json:"EndIPAddress,omitempty"`
	IPAddressList  string `json:"IPAddressList,omitempty"`
}

// IPHostParser is the typed-parser callback for the "iphost" identifier in
// objects.yaml.
func IPHostParser(raw json.RawMessage) (any, error) {
	var h IPHost
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return h, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/catalog -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/catalog/iphost.go internal/catalog/iphost_test.go
git commit -m "feat(catalog): typed IPHost parser"
```

---

## Task 18: `catalog` — typed `Services` parser

**Files:**
- Create: `internal/catalog/service.go`
- Create: `internal/catalog/service_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/catalog/service_test.go`:
```go
package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServicesParser_ParsesTCPService(t *testing.T) {
	raw := json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":{"Protocol":"TCP","SourcePort":"1:65535","DestinationPort":"80"}}}`)
	v, err := ServicesParser(raw)
	require.NoError(t, err)
	svc := v.(Service)
	require.Equal(t, "HTTP", svc.Name)
	require.Equal(t, "TCPorUDP", svc.Type)
	require.NotEmpty(t, svc.RawDetails)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/catalog -run TestServicesParser -v
```

- [ ] **Step 3: Implement `internal/catalog/service.go`**

```go
package catalog

import "encoding/json"

// Service is the typed view of a Sophos Services record. The detail shape
// varies by protocol so we keep the raw fragment alongside the common header.
type Service struct {
	Name       string          `json:"Name"`
	Type       string          `json:"Type"`
	RawDetails json.RawMessage `json:"ServiceDetails,omitempty"`
}

// ServicesParser is the typed-parser callback for the "service" identifier
// in objects.yaml.
func ServicesParser(raw json.RawMessage) (any, error) {
	var s Service
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return s, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/catalog -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/catalog/service.go internal/catalog/service_test.go
git commit -m "feat(catalog): typed Services parser"
```

---

## Task 19: `catalog` — production `objects.yaml` and parser registration

**Files:**
- Create: `internal/catalog/objects.yaml`
- Create: `internal/catalog/register.go`
- Create: `internal/catalog/register_test.go`

- [ ] **Step 1: Create the production catalog**

Create `internal/catalog/objects.yaml`:
```yaml
objects:
  - tag: IPHost
    aliases: [host-ip, ip-host]
    description: "IP host objects (single addresses, ranges, networks)"
    columns: [Name, IPFamily, HostType, IPAddress, Subnet]
    filterable: [Name, IPAddress, IPFamily, HostType]
    usageTag: IPHostStatistics
    typedParser: iphost

  - tag: IPHostGroup
    aliases: [host-group, ip-host-group]
    description: "Group of IPHost objects"
    columns: [Name, IPFamily, HostList]
    filterable: [Name, IPFamily]
    usageTag: IPHostGroupStatistics
    typedParser: ""

  - tag: Services
    aliases: [service]
    description: "Service objects (TCP/UDP/IP/ICMP definitions)"
    columns: [Name, Type, ServiceDetails]
    filterable: [Name, Type]
    usageTag: ServicesStatistics
    typedParser: service

  - tag: ServiceGroup
    aliases: [service-group]
    description: "Group of Services objects"
    columns: [Name, ServiceList]
    filterable: [Name]
    usageTag: ServiceGroupStatistics
    typedParser: ""

  - tag: FQDNHost
    aliases: [fqdn]
    description: "FQDN host objects"
    columns: [Name, FQDN, FQDNHostGroup]
    filterable: [Name, FQDN]
    usageTag: FQDNHostStatistics
    typedParser: ""

  - tag: FQDNHostGroup
    aliases: [fqdn-group]
    description: "Group of FQDN host objects"
    columns: [Name, FQDNHostList]
    filterable: [Name]
    usageTag: FQDNHostGroupStatistics
    typedParser: ""

  - tag: MACHost
    aliases: [mac]
    description: "MAC host objects"
    columns: [Name, Type, MACAddress]
    filterable: [Name, MACAddress]
    usageTag: MACHostStatistics
    typedParser: ""

  - tag: Zone
    aliases: [zone]
    description: "Network zones"
    columns: [Name, Type, Description]
    filterable: [Name, Type]
    usageTag: ZoneStatistics
    typedParser: ""

  - tag: Interface
    aliases: [interface]
    description: "Network interfaces"
    columns: [Name, Hardware, IPAddress, NetworkZone]
    filterable: [Name, Hardware]
    usageTag: InterfaceStatistics
    typedParser: ""

  - tag: Gateway
    aliases: [gateway]
    description: "Gateways used in WAN/SD-WAN"
    columns: [Name, IPAddress, GatewayType]
    filterable: [Name, IPAddress]
    usageTag: GatewayStatistics
    typedParser: ""

  - tag: FirewallRule
    aliases: [firewall-rule, fw-rule]
    description: "Firewall rules"
    columns: [Name, Status, Position, IPFamily, Action, SourceZones, DestinationZones]
    filterable: [Name, Status, IPFamily]
    usageTag: ""
    typedParser: ""

  - tag: NATRule
    aliases: [nat-rule, nat]
    description: "NAT rules (linked NAT, source NAT)"
    columns: [Name, Status, Position, OriginalSource, TranslatedSource]
    filterable: [Name, Status]
    usageTag: ""
    typedParser: ""
```

- [ ] **Step 2: Write the test**

Create `internal/catalog/register_test.go`:
```go
package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDefault_LoadsAndRegistersTypedParsers(t *testing.T) {
	c, err := NewDefault()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(c.Tags()), 12)

	// IPHost should dispatch to the typed parser.
	v, err := c.Parse("IPHost", json.RawMessage(`{"Name":"x","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0"}`))
	require.NoError(t, err)
	_, ok := v.(IPHost)
	require.True(t, ok)

	// FQDNHost should fall through to map (no typed parser).
	v, err = c.Parse("FQDNHost", json.RawMessage(`{"Name":"x","FQDN":"a.b"}`))
	require.NoError(t, err)
	_, ok = v.(map[string]any)
	require.True(t, ok)
}
```

- [ ] **Step 3: Implement `internal/catalog/register.go`**

```go
package catalog

import _ "embed"

//go:embed objects.yaml
var defaultYAML []byte

// NewDefault loads the embedded production catalog and registers the
// typed parsers shipped in this package (IPHost, Services).
func NewDefault() (*Catalog, error) {
	c, err := loadFromBytes(defaultYAML)
	if err != nil {
		return nil, err
	}
	c.RegisterParser("iphost", IPHostParser)
	c.RegisterParser("service", ServicesParser)
	return c, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/catalog -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/catalog/objects.yaml internal/catalog/register.go internal/catalog/register_test.go
git commit -m "feat(catalog): production objects.yaml (12 tags) embedded with NewDefault"
```

---

## Task 20: `svc` package — `ProfileSvc` (config + creds CRUD)

**Files:**
- Create: `internal/svc/profile.go`
- Create: `internal/svc/profile_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/profile_test.go`:
```go
package svc

import (
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/stretchr/testify/require"
)

func newProfileSvc(t *testing.T) (*ProfileSvc, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.New()
	store := creds.NewFileStore(dir)
	return &ProfileSvc{
		Config:  cfg,
		Creds:   store,
		BaseDir: dir,
	}, dir
}

func TestProfileSvc_AddSavesConfig(t *testing.T) {
	s, _ := newProfileSvc(t)
	err := s.Add("home", "https://fw.example.com:4444", false)
	require.NoError(t, err)
	require.Contains(t, s.Config.Profiles, "home")
	require.Equal(t, "home", s.Config.CurrentProfile)
}

func TestProfileSvc_AddRejectsEmptyURL(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.Error(t, s.Add("home", "", false))
}

func TestProfileSvc_AddRejectsDuplicateName(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.Error(t, s.Add("home", "https://y:4444", false))
}

func TestProfileSvc_RemoveDeletesCreds(t *testing.T) {
	s, dir := newProfileSvc(t)
	_ = dir
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.NoError(t, s.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))

	require.NoError(t, s.Remove("home"))
	_, err := s.Creds.Load("home")
	require.ErrorIs(t, err, creds.ErrNotFound)
}

func TestProfileSvc_Use(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.NoError(t, s.Add("work", "https://y:4444", false))
	require.NoError(t, s.Use("work"))
	require.Equal(t, "work", s.Config.CurrentProfile)
}

func TestProfileSvc_List(t *testing.T) {
	s, _ := newProfileSvc(t)
	require.NoError(t, s.Add("home", "https://x:4444", false))
	require.NoError(t, s.Add("work", "https://y:4444", true))
	list := s.List()
	require.Len(t, list, 2)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -v
```

- [ ] **Step 3: Implement `internal/svc/profile.go`**

```go
// Package svc holds application services. Both CLI commands and (Phase-4) MCP
// tools call into svc, never directly into sophos/catalog/config. svc owns
// read-only enforcement (per-command layer) and dry-run gating.
package svc

import (
	"errors"
	"fmt"
	"sort"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
)

// ProfileSvc owns profile add/remove/use/list and the corresponding config
// + credential persistence.
type ProfileSvc struct {
	Config  *config.Config
	Creds   creds.Store
	BaseDir string
}

// ProfileInfo is a render-friendly summary returned by List.
type ProfileInfo struct {
	Name     string
	URL      string
	ReadOnly bool
	Current  bool
}

// Add registers a new profile. Fails on duplicate name or empty URL. The
// first profile becomes current automatically.
func (s *ProfileSvc) Add(name, url string, readOnly bool) error {
	if url == "" {
		return errors.New("profile: --url is required")
	}
	if _, dup := s.Config.Profiles[name]; dup {
		return fmt.Errorf("profile %q already exists", name)
	}
	s.Config.AddProfile(name, config.Profile{
		URL:                url,
		Timeout:            s.Config.Defaults.Timeout,
		ReadOnly:           readOnly,
		CredentialsBackend: s.Creds.Backend(),
	})
	return s.Config.Save(s.BaseDir)
}

// Remove deletes a profile and its stored credentials.
func (s *ProfileSvc) Remove(name string) error {
	if err := s.Config.RemoveProfile(name); err != nil {
		return err
	}
	if err := s.Creds.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
		return err
	}
	return s.Config.Save(s.BaseDir)
}

// Use switches the current profile.
func (s *ProfileSvc) Use(name string) error {
	if err := s.Config.UseProfile(name); err != nil {
		return err
	}
	return s.Config.Save(s.BaseDir)
}

// List returns all profiles sorted by name.
func (s *ProfileSvc) List() []ProfileInfo {
	out := make([]ProfileInfo, 0, len(s.Config.Profiles))
	for name, p := range s.Config.Profiles {
		out = append(out, ProfileInfo{
			Name:     name,
			URL:      p.URL,
			ReadOnly: p.ReadOnly,
			Current:  s.Config.CurrentProfile == name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/profile.go internal/svc/profile_test.go
git commit -m "feat(svc): ProfileSvc — add/remove/use/list with config+creds persistence"
```

---

## Task 21: `svc` package — `AuthSvc` (login/status/test/logout)

**Files:**
- Create: `internal/svc/auth.go`
- Create: `internal/svc/auth_test.go`
- Create: `internal/svc/clientfactory.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/auth_test.go`:
```go
package svc

import (
	"context"
	"errors"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeClient struct {
	doErr error
	calls int
}

func (f *fakeClient) Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error) {
	f.calls++
	if f.doErr != nil {
		return nil, f.doErr
	}
	return &sophos.Response{LoginOK: true, LoginStatus: "Authentication Successful"}, nil
}

func (f *fakeClient) DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error) {
	f.calls++
	if f.doErr != nil {
		return nil, f.doErr
	}
	return &sophos.Response{LoginOK: true, LoginStatus: "Authentication Successful"}, nil
}

func newAuthSvc(t *testing.T, fc *fakeClient) (*AuthSvc, *ProfileSvc) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.New()
	store := creds.NewFileStore(dir)
	ps := &ProfileSvc{Config: cfg, Creds: store, BaseDir: dir}
	require.NoError(t, ps.Add("home", "https://x:4444", false))
	auth := &AuthSvc{
		Config:  cfg,
		Creds:   store,
		BaseDir: dir,
		NewClient: func(p config.Profile, c creds.Credentials) Client {
			return fc
		},
	}
	return auth, ps
}

func TestAuthSvc_Login_StoresCredsOnSuccess(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "admin", "secret"))

	got, err := a.Creds.Load("home")
	require.NoError(t, err)
	require.Equal(t, "admin", got.Username)
}

func TestAuthSvc_Login_DoesNotStoreOnAuthFailure(t *testing.T) {
	fc := &fakeClient{doErr: sophos.ErrAuthFailed}
	a, _ := newAuthSvc(t, fc)
	err := a.Login(context.Background(), "home", "admin", "wrong")
	require.ErrorIs(t, err, sophos.ErrAuthFailed)
	_, err = a.Creds.Load("home")
	require.ErrorIs(t, err, creds.ErrNotFound)
}

func TestAuthSvc_Status_NotLoggedInWhenNoCreds(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	st, err := a.Status("home")
	require.NoError(t, err)
	require.False(t, st.LoggedIn)
}

func TestAuthSvc_Status_LoggedInAfterLogin(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "u", "p"))
	st, err := a.Status("home")
	require.NoError(t, err)
	require.True(t, st.LoggedIn)
}

func TestAuthSvc_Test_RoundTrips(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "u", "p"))
	r, err := a.Test(context.Background(), "home")
	require.NoError(t, err)
	require.True(t, r.OK)
}

func TestAuthSvc_Logout_DeletesCreds(t *testing.T) {
	fc := &fakeClient{}
	a, _ := newAuthSvc(t, fc)
	require.NoError(t, a.Login(context.Background(), "home", "u", "p"))
	require.NoError(t, a.Logout("home"))
	_, err := a.Creds.Load("home")
	require.True(t, errors.Is(err, creds.ErrNotFound))
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestAuthSvc -v
```

- [ ] **Step 3: Create the client interface**

Create `internal/svc/clientfactory.go`:
```go
package svc

import (
	"context"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// Client is the subset of sophos.Client used by services. Allows fakes in tests.
type Client interface {
	Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error)
	DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error)
}

// ClientFactory builds a Client for a profile + credentials. Production code
// returns a real *sophos.Client; tests can swap in fakes.
type ClientFactory func(p config.Profile, c creds.Credentials) Client

// DefaultClientFactory builds a real sophos.Client honoring profile settings.
// The insecureSkipVerify override is passed through (e.g. from a CLI flag).
func DefaultClientFactory(insecureSkipVerify bool) ClientFactory {
	return func(p config.Profile, c creds.Credentials) Client {
		return sophos.NewClient(sophos.ClientConfig{
			BaseURL:            p.URL,
			Username:           c.Username,
			Password:           c.Password,
			Timeout:            p.Timeout,
			InsecureSkipVerify: insecureSkipVerify || p.InsecureSkipVerify,
			ReadOnly:           p.ReadOnly,
		})
	}
}
```

- [ ] **Step 4: Implement `internal/svc/auth.go`**

```go
package svc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// AuthSvc owns login/status/test/logout.
type AuthSvc struct {
	Config    *config.Config
	Creds     creds.Store
	BaseDir   string
	NewClient ClientFactory
}

// AuthStatus is the render-friendly view of `auth status`.
type AuthStatus struct {
	Profile            string
	URL                string
	LoggedIn           bool
	CredentialsBackend string
}

// ConnectionResult is the render-friendly view of `auth test`.
type ConnectionResult struct {
	Profile      string
	OK           bool
	LatencyMs    int64
	APIReachable bool
	AuthOK       bool
	Error        string
}

// Login validates credentials by calling the firewall, then persists them
// only on success.
func (a *AuthSvc) Login(ctx context.Context, profileName, username, password string) error {
	p, _, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return err
	}
	c := a.NewClient(p, creds.Credentials{Username: username, Password: password})
	if _, err := c.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}}}); err != nil {
		return err
	}
	return a.Creds.Save(profileName, creds.Credentials{Username: username, Password: password})
}

// Status reports whether credentials are stored for the profile.
func (a *AuthSvc) Status(profileName string) (AuthStatus, error) {
	p, name, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return AuthStatus{}, err
	}
	st := AuthStatus{
		Profile:            name,
		URL:                p.URL,
		CredentialsBackend: a.Creds.Backend(),
	}
	if _, err := a.Creds.Load(name); err == nil {
		st.LoggedIn = true
	} else if !errors.Is(err, creds.ErrNotFound) {
		return st, err
	}
	return st, nil
}

// Test performs a minimal Get to verify the firewall is reachable and the
// stored credentials still authenticate.
func (a *AuthSvc) Test(ctx context.Context, profileName string) (ConnectionResult, error) {
	p, name, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return ConnectionResult{}, err
	}
	c, err := a.Creds.Load(name)
	if err != nil {
		return ConnectionResult{Profile: name, Error: "no stored credentials"}, fmt.Errorf("auth test: %w", err)
	}
	cl := a.NewClient(p, c)
	start := time.Now()
	_, err = cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}}})
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return ConnectionResult{
			Profile:   name,
			OK:        false,
			LatencyMs: latency,
			AuthOK:    !errors.Is(err, sophos.ErrAuthFailed),
			APIReachable: !isNetworkError(err),
			Error:     err.Error(),
		}, err
	}
	return ConnectionResult{
		Profile:      name,
		OK:           true,
		LatencyMs:    latency,
		APIReachable: true,
		AuthOK:       true,
	}, nil
}

// Logout clears stored credentials for the profile.
func (a *AuthSvc) Logout(profileName string) error {
	_, name, err := a.Config.ActiveProfile(profileName)
	if err != nil {
		return err
	}
	if err := a.Creds.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
		return err
	}
	return nil
}

func isNetworkError(err error) bool {
	// Heuristic: anything not auth-failed and not a Sophos status error is
	// likely transport.
	if errors.Is(err, sophos.ErrAuthFailed) {
		return false
	}
	var se *sophos.StatusError
	return !errors.As(err, &se)
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/svc -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/svc/auth.go internal/svc/clientfactory.go internal/svc/auth_test.go
git commit -m "feat(svc): AuthSvc (login/status/test/logout) and Client interface"
```

---

## Task 22: `svc` package — `ObjectSvc` (list/get/usage/schema)

**Files:**
- Create: `internal/svc/object.go`
- Create: `internal/svc/object_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/object_test.go`:
```go
package svc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type cannedClient struct {
	resp *sophos.Response
	err  error
	last sophos.Envelope
}

func (c *cannedClient) Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error) {
	c.last = env
	return c.resp, c.err
}
func (c *cannedClient) DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error) {
	return c.resp, c.err
}

func newObjectSvc(t *testing.T, cl Client) *ObjectSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return &ObjectSvc{
		Config:    cfg,
		Creds:     store,
		Catalog:   cat,
		NewClient: func(p config.Profile, c creds.Credentials) Client { return cl },
	}
}

func TestObjectSvc_List_TypedParser(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {
				json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			},
		},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.List(context.Background(), "home", "IPHost", nil)
	require.NoError(t, err)
	require.Equal(t, "IPHost", out.Tag)
	require.Equal(t, 1, out.Count)
	host, ok := out.Items[0].(catalog.IPHost)
	require.True(t, ok)
	require.Equal(t, "LAN", host.Name)
}

func TestObjectSvc_List_AliasResolves(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body:    map[string][]json.RawMessage{"IPHost": {json.RawMessage(`{"Name":"x"}`)}},
	}
	s := newObjectSvc(t, &cannedClient{resp: resp})
	out, err := s.List(context.Background(), "home", "host-ip", nil)
	require.NoError(t, err)
	require.Equal(t, "IPHost", out.Tag)
}

func TestObjectSvc_List_UnknownTag(t *testing.T) {
	s := newObjectSvc(t, &cannedClient{})
	_, err := s.List(context.Background(), "home", "Nope", nil)
	require.ErrorIs(t, err, ErrCatalogUnknownTag)
}

func TestObjectSvc_List_FilterPassedThrough(t *testing.T) {
	cl := &cannedClient{resp: &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{"IPHost": {}}}}
	s := newObjectSvc(t, cl)
	_, err := s.List(context.Background(), "home", "IPHost", &sophos.FilterClause{Field: "Name", Criteria: "like", Value: "LAN"})
	require.NoError(t, err)
	require.Len(t, cl.last.Operations, 1)
	got := cl.last.Operations[0].(sophos.GetOp)
	require.NotNil(t, got.Filter)
	require.Equal(t, "like", got.Filter.Criteria)
}

func TestObjectSvc_Get_NotFoundSurfacedAsError(t *testing.T) {
	cl := &cannedClient{err: sophos.ErrNotFound}
	s := newObjectSvc(t, cl)
	_, err := s.Get(context.Background(), "home", "IPHost", "nope")
	require.True(t, errors.Is(err, sophos.ErrNotFound))
}

func TestObjectSvc_Usage_UsesUsageTagFromCatalog(t *testing.T) {
	cl := &cannedClient{resp: &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{"IPHostStatistics": {}}}}
	s := newObjectSvc(t, cl)
	_, err := s.Usage(context.Background(), "home", "IPHost", "LAN")
	require.NoError(t, err)
	op := cl.last.Operations[0].(sophos.StatisticsOp)
	require.Equal(t, "IPHostStatistics", op.XMLTag)
}

func TestObjectSvc_Usage_RejectsObjectsWithoutUsageTag(t *testing.T) {
	cl := &cannedClient{}
	s := newObjectSvc(t, cl)
	_, err := s.Usage(context.Background(), "home", "FirewallRule", "X")
	require.Error(t, err)
}

func TestObjectSvc_Schema_ReturnsCatalogEntry(t *testing.T) {
	s := newObjectSvc(t, &cannedClient{})
	e, err := s.Schema("IPHost")
	require.NoError(t, err)
	require.Equal(t, "IPHost", e.Tag)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestObjectSvc -v
```

- [ ] **Step 3: Implement `internal/svc/object.go`**

```go
package svc

import (
	"context"
	"errors"
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// ErrCatalogUnknownTag is returned when a given tag/alias is not in the catalog.
var ErrCatalogUnknownTag = errors.New("catalog: unknown tag")

// ObjectList is the render-friendly result of a list operation.
type ObjectList struct {
	Profile string
	Tag     string
	Filter  *sophos.FilterClause
	Count   int
	Items   []any // typed if catalog has parser, else map[string]any
}

// Object is the render-friendly result of a single-record get.
type Object struct {
	Profile string
	Tag     string
	Name    string
	Typed   bool
	Data    any
}

// ObjectUsage is the render-friendly result of a usage query.
type ObjectUsage struct {
	Profile  string
	Tag      string
	UsageTag string
	Name     string
	Records  []map[string]any
}

// ObjectSvc serves `object list/get/usage/schema`.
type ObjectSvc struct {
	Config    *config.Config
	Creds     creds.Store
	Catalog   *catalog.Catalog
	NewClient ClientFactory
}

func (s *ObjectSvc) clientFor(profileName string) (Client, *catalog.Catalog, string, error) {
	p, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, nil, "", err
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return nil, nil, "", err
	}
	return s.NewClient(p, c), s.Catalog, name, nil
}

// List returns all records of the given XML tag, optionally filtered.
func (s *ObjectSvc) List(ctx context.Context, profileName, tagOrAlias string, filter *sophos.FilterClause) (*ObjectList, error) {
	cl, cat, name, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	entry, ok := cat.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}

	if filter != nil {
		if err := filter.ValidateForGet(); err != nil {
			return nil, err
		}
	}

	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{
		XMLTag: entry.Tag,
		Filter: filter,
	}}})
	if err != nil {
		return nil, err
	}

	out := &ObjectList{Profile: name, Tag: entry.Tag, Filter: filter}
	for _, raw := range resp.Body[entry.Tag] {
		v, err := cat.Parse(entry.Tag, raw)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, v)
	}
	out.Count = len(out.Items)
	return out, nil
}

// Get fetches a single record by name.
func (s *ObjectSvc) Get(ctx context.Context, profileName, tagOrAlias, name string) (*Object, error) {
	cl, cat, profName, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	entry, ok := cat.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}

	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{
		XMLTag: entry.Tag,
		Name:   name,
	}}})
	if err != nil {
		return nil, err
	}
	records := resp.Body[entry.Tag]
	if len(records) == 0 {
		return nil, fmt.Errorf("%s %q: %w", entry.Tag, name, sophos.ErrNotFound)
	}
	v, err := cat.Parse(entry.Tag, records[0])
	if err != nil {
		return nil, err
	}
	return &Object{
		Profile: profName,
		Tag:     entry.Tag,
		Name:    name,
		Typed:   entry.TypedParser != "",
		Data:    v,
	}, nil
}

// Usage runs the *Statistics query for the catalog entry.
func (s *ObjectSvc) Usage(ctx context.Context, profileName, tagOrAlias, name string) (*ObjectUsage, error) {
	cl, cat, profName, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	entry, ok := cat.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}
	if entry.UsageTag == "" {
		return nil, fmt.Errorf("object %q does not support usage queries (no Statistics tag)", entry.Tag)
	}

	var filter *sophos.FilterClause
	if name != "" {
		filter = &sophos.FilterClause{Field: "Name", Criteria: "=", Value: name}
		if err := filter.ValidateForStatistics(); err != nil {
			return nil, err
		}
	}

	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.StatisticsOp{
		XMLTag: entry.UsageTag,
		Filter: filter,
	}}})
	if err != nil {
		return nil, err
	}

	out := &ObjectUsage{Profile: profName, Tag: entry.Tag, UsageTag: entry.UsageTag, Name: name}
	for _, raw := range resp.Body[entry.UsageTag] {
		var m map[string]any
		if err := jsonUnmarshal(raw, &m); err != nil {
			return nil, err
		}
		out.Records = append(out.Records, m)
	}
	return out, nil
}

// Schema returns the catalog entry for tag or alias.
func (s *ObjectSvc) Schema(tagOrAlias string) (*catalog.Entry, error) {
	e, ok := s.Catalog.Resolve(tagOrAlias)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogUnknownTag, tagOrAlias)
	}
	return e, nil
}

// Local helper to keep the encoding/json import alongside the call site.
func jsonUnmarshal(raw []byte, v any) error {
	return jsonUnmarshalImpl(raw, v)
}
```

Add this small companion file to keep `encoding/json` cleanly imported (avoids stale-imports flagged by goimports):

Create `internal/svc/json_helper.go`:
```go
package svc

import "encoding/json"

func jsonUnmarshalImpl(raw []byte, v any) error { return json.Unmarshal(raw, v) }
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/object.go internal/svc/json_helper.go internal/svc/object_test.go
git commit -m "feat(svc): ObjectSvc (list/get/usage/schema) over the hybrid catalog"
```

---

## Task 23: `svc` package — `RawSvc` (raw get + dry-run preview)

**Files:**
- Create: `internal/svc/raw.go`
- Create: `internal/svc/raw_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/raw_test.go`:
```go
package svc

import (
	"context"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func newRawSvc(t *testing.T, cl Client) *RawSvc {
	t.Helper()
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return &RawSvc{
		Config:    cfg,
		Creds:     store,
		NewClient: func(p config.Profile, c creds.Credentials) Client { return cl },
	}
}

func TestRawSvc_Get_RoundTrips(t *testing.T) {
	cl := &cannedClient{resp: &sophos.Response{LoginOK: true}}
	s := newRawSvc(t, cl)
	out, err := s.Get(context.Background(), "home", "IPHost")
	require.NoError(t, err)
	require.Equal(t, "IPHost", out.Tag)
}

func TestRawSvc_Preview_DetectsMutating(t *testing.T) {
	s := newRawSvc(t, &cannedClient{})
	body := []byte(`<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>`)
	pv, err := s.Preview(context.Background(), "home", body)
	require.NoError(t, err)
	require.True(t, pv.Mutating)
	require.Contains(t, pv.Verbs, "Set:add")
}

func TestRawSvc_Preview_RedactsCredentials(t *testing.T) {
	s := newRawSvc(t, &cannedClient{})
	body := []byte(`<Get><IPHost></IPHost></Get>`)
	pv, err := s.Preview(context.Background(), "home", body)
	require.NoError(t, err)
	require.False(t, strings.Contains(pv.RedactedXML, "u"), "username must be redacted")
	require.False(t, strings.Contains(pv.RedactedXML, "p"), "password must be redacted")
	require.Contains(t, pv.RedactedXML, "<Username>***</Username>")
	require.Contains(t, pv.RedactedXML, "<Password>***</Password>")
}

func TestRawSvc_Apply_AlwaysReturnsUnsupported(t *testing.T) {
	s := newRawSvc(t, &cannedClient{})
	err := s.Apply(context.Background(), "home", []byte(`<Set operation="add"></Set>`))
	require.ErrorIs(t, err, ErrUnsupportedInPhase)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestRawSvc -v
```

- [ ] **Step 3: Implement `internal/svc/raw.go`**

```go
package svc

import (
	"context"
	"errors"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// ErrUnsupportedInPhase is returned by foundation-phase code paths that exist
// for forward compatibility but have no implementation yet (e.g. raw apply).
var ErrUnsupportedInPhase = errors.New("operation not supported in foundation phase")

// RawResponse is the render-friendly result of `raw get`.
type RawResponse struct {
	Profile string
	Tag     string
	Status  StatusInfo
	Body    map[string][][]byte // raw XML fragments per tag (re-encoded)
}

// StatusInfo summarizes Sophos status fields.
type StatusInfo struct {
	Code    int
	Message string
}

// Preview is the render-friendly result of `raw request --dry-run`.
type Preview struct {
	Profile        string
	Mutating       bool
	Verbs          []string
	RedactedXML    string
	WouldSendBytes int
	Warning        string
}

// RawSvc serves `raw get` and `raw request --dry-run`.
type RawSvc struct {
	Config    *config.Config
	Creds     creds.Store
	NewClient ClientFactory
}

func (s *RawSvc) clientFor(profileName string) (Client, string, error) {
	p, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, "", err
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return nil, "", err
	}
	return s.NewClient(p, c), name, nil
}

// Get sends a generic <Get><Tag></Tag></Get>.
func (s *RawSvc) Get(ctx context.Context, profileName, xmlTag string) (*RawResponse, error) {
	cl, name, err := s.clientFor(profileName)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(ctx, sophos.Envelope{Operations: []sophos.Op{sophos.GetOp{XMLTag: xmlTag}}})
	if err != nil && resp == nil {
		return nil, err
	}

	out := &RawResponse{Profile: name, Tag: xmlTag, Body: map[string][][]byte{}}
	for tag, recs := range resp.Body {
		out.Body[tag] = make([][]byte, 0, len(recs))
		for _, r := range recs {
			out.Body[tag] = append(out.Body[tag], []byte(r))
		}
	}
	return out, err
}

// Preview wraps a user-supplied body with login (so the returned redacted XML
// reflects what would actually be sent), runs IsMutating, and returns the
// summary. NEVER sends the request.
func (s *RawSvc) Preview(ctx context.Context, profileName string, body []byte) (*Preview, error) {
	p, name, err := s.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}
	c, err := s.Creds.Load(name)
	if err != nil {
		return nil, err
	}
	_ = p

	full, err := sophos.BuildRawEnvelope(body, c.Username, c.Password)
	if err != nil {
		return nil, err
	}

	mutating, verbs := safety.IsMutating(full)
	pv := &Preview{
		Profile:        name,
		Mutating:       mutating,
		Verbs:          verbs,
		RedactedXML:    string(safety.RedactXML(full)),
		WouldSendBytes: len(full),
	}
	if mutating {
		pv.Warning = "Mutating XML detected. Apply path is not implemented in this phase."
	}
	return pv, nil
}

// Apply always returns ErrUnsupportedInPhase in foundation. Phase 6 will
// implement the real apply path.
func (s *RawSvc) Apply(ctx context.Context, profileName string, body []byte) error {
	return ErrUnsupportedInPhase
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/svc/raw.go internal/svc/raw_test.go
git commit -m "feat(svc): RawSvc with Get + dry-run Preview (Apply returns unsupported)"
```

---

## Task 24: `cli` — error→exit-code mapping in `root.go`

**Files:**
- Modify: `internal/cli/root.go`
- Create: `internal/cli/errors.go`
- Create: `internal/cli/errors_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/errors_test.go`:
```go
package cli

import (
	"errors"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestErrorKind_AuthFailed(t *testing.T) {
	k := ErrorKind(sophos.ErrAuthFailed)
	require.Equal(t, "auth_failed", k)
	require.Equal(t, 3, ExitCodeFor(k))
}

func TestErrorKind_NotFound(t *testing.T) {
	require.Equal(t, "not_found", ErrorKind(sophos.ErrNotFound))
}

func TestErrorKind_PermissionDenied(t *testing.T) {
	require.Equal(t, "permission_denied", ErrorKind(sophos.ErrPermissionDenied))
}

func TestErrorKind_ReadOnlyViolation(t *testing.T) {
	k := ErrorKind(sophos.ErrReadOnlyViolation)
	require.Equal(t, "read_only_violation", k)
	require.Equal(t, 4, ExitCodeFor(k))
}

func TestErrorKind_UnsupportedInPhase(t *testing.T) {
	k := ErrorKind(svc.ErrUnsupportedInPhase)
	require.Equal(t, "unsupported_in_phase", k)
	require.Equal(t, 6, ExitCodeFor(k))
}

func TestErrorKind_CatalogUnknown(t *testing.T) {
	require.Equal(t, "catalog_unknown_tag", ErrorKind(svc.ErrCatalogUnknownTag))
}

func TestErrorKind_GenericFallback(t *testing.T) {
	require.Equal(t, "generic", ErrorKind(errors.New("anything else")))
	require.Equal(t, 1, ExitCodeFor("generic"))
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestErrorKind -v
```

- [ ] **Step 3: Implement `internal/cli/errors.go`**

```go
package cli

import (
	"errors"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ErrorKind classifies an error into a sophosfw.v1.error envelope kind.
func ErrorKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, sophos.ErrAuthFailed):
		return "auth_failed"
	case errors.Is(err, sophos.ErrNotFound):
		return "not_found"
	case errors.Is(err, sophos.ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, sophos.ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, sophos.ErrServerError):
		return "server_error"
	case errors.Is(err, sophos.ErrReadOnlyViolation):
		return "read_only_violation"
	case errors.Is(err, svc.ErrUnsupportedInPhase):
		return "unsupported_in_phase"
	case errors.Is(err, svc.ErrCatalogUnknownTag):
		return "catalog_unknown_tag"
	default:
		return "generic"
	}
}

// ExitCodeFor maps an error kind to a process exit code.
func ExitCodeFor(kind string) int {
	switch kind {
	case "":
		return 0
	case "config_error":
		return 2
	case "auth_failed":
		return 3
	case "read_only_violation":
		return 4
	case "tls_error", "network_error":
		return 5
	case "unsupported_in_phase":
		return 6
	default:
		return 1
	}
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/cli -v
```

- [ ] **Step 5: Wire root error handling**

Edit `internal/cli/root.go` — replace the `NewRoot` body to install a `RunE`-aware error mapper. Replace the file with:

```go
package cli

import (
	"fmt"
	"os"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/spf13/cobra"
)

// RootDeps holds dependencies injected into the root command.
type RootDeps struct {
	Version string
	// Wired in later tasks: BaseDir, ConfigLoader, ProfileSvc factory, etc.
}

// NewRoot constructs the cobra root command with all subcommands wired in.
func NewRoot(d RootDeps) *cobra.Command {
	root := &cobra.Command{
		Use:           "sophosfw",
		Short:         "Sophos Firewall CLI + MCP server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().String("profile", "", "config profile to use (default: currentProfile from config)")
	root.PersistentFlags().Bool("json", false, "emit JSON envelope output instead of tables")
	root.PersistentFlags().Duration("timeout", 0, "override per-request timeout")
	root.PersistentFlags().Bool("debug", false, "verbose logging (credentials always redacted)")
	root.PersistentFlags().Bool("insecure-skip-verify", false, "DANGER: skip TLS certificate verification for this invocation")

	root.AddCommand(newVersionCmd(d))

	return root
}

// HandleError maps a returned error to an exit code, printing either an
// error envelope (JSON mode) or a friendly stderr line. Use this from main().
func HandleError(cmd *cobra.Command, err error) int {
	if err == nil {
		return 0
	}
	kind := ErrorKind(err)
	jsonMode, _ := cmd.Flags().GetBool("json")
	profile, _ := cmd.Flags().GetString("profile")

	if jsonMode {
		_ = render.WriteError(os.Stderr, kind, err.Error(), profile, nil)
	} else {
		fmt.Fprintf(os.Stderr, "error (%s): %v\n", kind, err)
	}
	return ExitCodeFor(kind)
}
```

- [ ] **Step 6: Update `cmd/sophosfw/main.go` to use `HandleError`**

Replace `cmd/sophosfw/main.go`:
```go
package main

import (
	"os"

	"github.com/iainmoffat/sophosfw/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(cli.RootDeps{Version: version})
	if err := root.Execute(); err != nil {
		os.Exit(cli.HandleError(root, err))
	}
}
```

- [ ] **Step 7: Run all tests, then build**

```bash
go test ./... && make build
```

- [ ] **Step 8: Commit**

```bash
git add internal/cli/errors.go internal/cli/errors_test.go internal/cli/root.go cmd/sophosfw/main.go
git commit -m "feat(cli): error→kind→exit-code mapper and JSON error envelope on stderr"
```

---

## Task 25: `cli` — `auth` subcommands

**Files:**
- Create: `internal/cli/auth.go`
- Create: `internal/cli/auth_test.go`
- Modify: `internal/cli/root.go` (extend `RootDeps` to carry config/creds/factory)
- Modify: `cmd/sophosfw/main.go` (wire real deps into `RootDeps`)

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/auth_test.go`:
```go
package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeAllOK struct{}

func (fakeAllOK) Do(context.Context, sophos.Envelope) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}
func (fakeAllOK) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForTest(t *testing.T) (*RootDeps, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.New()
	store := creds.NewFileStore(dir)
	d := &RootDeps{
		Version: "test",
		BaseDir: dir,
		Config:  cfg,
		Creds:   store,
		NewClient: func(p config.Profile, c creds.Credentials) svc.Client {
			return fakeAllOK{}
		},
	}
	return d, dir
}

func TestAuth_ProfileAdd_AndList(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	root.SetArgs([]string{"auth", "profile", "add", "home", "--url", "https://x:4444"})
	require.NoError(t, root.Execute())

	out.Reset()
	root.SetArgs([]string{"auth", "profile", "list"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "home")
}

func TestAuth_Status_NotLoggedInInitially(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"auth", "profile", "add", "home", "--url", "https://x:4444"})
	require.NoError(t, root.Execute())

	out.Reset()
	root.SetArgs([]string{"auth", "status", "--json"})
	require.NoError(t, root.Execute())
	require.True(t, strings.Contains(out.String(), `"loggedIn": false`),
		"got: %s", out.String())
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestAuth_ -v
```

- [ ] **Step 3: Extend `RootDeps` in `internal/cli/root.go`**

Replace the `RootDeps` struct definition with:

```go
type RootDeps struct {
	Version   string
	BaseDir   string
	Config    *config.Config
	Creds     creds.Store
	NewClient svc.ClientFactory
}
```

…and update the imports at the top of `root.go`:
```go
import (
	"fmt"
	"os"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)
```

The new fields are referenced by `internal/cli/auth.go` (next step), so the
imports won't be flagged as unused.

- [ ] **Step 4: Implement `internal/cli/auth.go`**

```go
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newAuthCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Authentication and profile management"}
	cmd.AddCommand(
		newAuthLoginCmd(d),
		newAuthStatusCmd(d),
		newAuthTestCmd(d),
		newAuthLogoutCmd(d),
		newAuthProfileCmd(d),
	)
	return cmd
}

func newAuthLoginCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Validate credentials against the firewall and persist them",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			username, password, err := promptCredentials(cmd)
			if err != nil {
				return err
			}
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			if err := a.Login(cmd.Context(), profile, username, password); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
}

func promptCredentials(cmd *cobra.Command) (string, string, error) {
	if u := os.Getenv("SOPHOSFW_USERNAME"); u != "" {
		return u, os.Getenv("SOPHOSFW_PASSWORD"), nil
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Username: ")
	r := bufio.NewReader(os.Stdin)
	username, err := r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	username = strings.TrimSpace(username)

	fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", "", err
	}
	fmt.Fprintln(cmd.ErrOrStderr())
	return username, string(pw), nil
}

func newAuthStatusCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current profile and whether credentials are stored",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			st, err := a.Status(profile)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.authStatus", map[string]any{
					"profile":            st.Profile,
					"url":                st.URL,
					"loggedIn":           st.LoggedIn,
					"credentialsBackend": st.CredentialsBackend,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "profile: %s\nurl: %s\nloggedIn: %t\nbackend: %s\n",
				st.Profile, st.URL, st.LoggedIn, st.CredentialsBackend)
			return nil
		},
	}
}

func newAuthTestCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Test connectivity and stored credentials against the firewall",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			r, err := a.Test(cmd.Context(), profile)
			if err != nil {
				_ = render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.connectionTest", map[string]any{
					"profile":      r.Profile,
					"ok":           false,
					"latencyMs":    r.LatencyMs,
					"apiReachable": r.APIReachable,
					"authOk":       r.AuthOK,
					"error":        r.Error,
				})
				return err
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.connectionTest", map[string]any{
				"profile":      r.Profile,
				"ok":           r.OK,
				"latencyMs":    r.LatencyMs,
				"apiReachable": r.APIReachable,
				"authOk":       r.AuthOK,
			})
		},
	}
}

func newAuthLogoutCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete stored credentials for the current/selected profile",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			a := &svc.AuthSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir, NewClient: d.NewClient}
			return a.Logout(profile)
		},
	}
}

func newAuthProfileCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "profile", Short: "Manage firewall profiles"}
	cmd.AddCommand(
		newProfileAddCmd(d),
		newProfileListCmd(d),
		newProfileUseCmd(d),
		newProfileRemoveCmd(d),
	)
	return cmd
}

func newProfileAddCmd(d RootDeps) *cobra.Command {
	var url string
	var readOnly bool
	c := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new firewall profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			return ps.Add(args[0], url, readOnly)
		},
	}
	c.Flags().StringVar(&url, "url", "", "firewall base URL (e.g. https://fw.example.com:4444)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "create profile in read-only mode")
	_ = c.MarkFlagRequired("url")
	return c
}

func newProfileListCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all profiles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			list := ps.List()
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				profiles := make([]map[string]any, 0, len(list))
				for _, p := range list {
					profiles = append(profiles, map[string]any{
						"name":     p.Name,
						"url":      p.URL,
						"readOnly": p.ReadOnly,
						"current":  p.Current,
					})
				}
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.profileList", map[string]any{
					"current":  d.Config.CurrentProfile,
					"profiles": profiles,
				})
			}
			for _, p := range list {
				marker := "  "
				if p.Current {
					marker = "* "
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s%s\t%s\n", marker, p.Name, p.URL)
			}
			return nil
		},
	}
}

func newProfileUseCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Switch the current profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			return ps.Use(args[0])
		},
	}
}

func newProfileRemoveCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a profile and its stored credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ps := &svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}
			return ps.Remove(args[0])
		},
	}
}
```

- [ ] **Step 5: Wire `auth` into root**

In `internal/cli/root.go` `NewRoot`, add `root.AddCommand(newAuthCmd(d))` after the version command. Also remove the now-unused `_ = config` placeholder if any.

- [ ] **Step 6: Update `cmd/sophosfw/main.go` to wire real deps**

Replace `cmd/sophosfw/main.go`:
```go
package main

import (
	"fmt"
	"os"

	"github.com/iainmoffat/sophosfw/internal/cli"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

var version = "dev"

func main() {
	baseDir, err := config.DefaultBaseDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config dir:", err)
		os.Exit(2)
	}
	cfg, err := config.Load(baseDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config load:", err)
		os.Exit(2)
	}
	store := creds.New(baseDir)

	root := cli.NewRoot(cli.RootDeps{
		Version: version,
		BaseDir: baseDir,
		Config:  cfg,
		Creds:   store,
		NewClient: func(p config.Profile, c creds.Credentials) svc.Client {
			// Wire CLI flags here once we have access to them; for now, use defaults.
			return svc.DefaultClientFactory(false)(p, c)
		},
	})
	if err := root.Execute(); err != nil {
		os.Exit(cli.HandleError(root, err))
	}
}
```

- [ ] **Step 7: Run tests and build**

```bash
go get golang.org/x/term
go mod tidy
go test ./... && make build
```

- [ ] **Step 8: Smoke test the binary**

Run:
```bash
TMPHOME=$(mktemp -d) XDG_CONFIG_HOME=$TMPHOME ./bin/sophosfw auth profile add home --url https://example.invalid:4444
TMPHOME_DIR=$TMPHOME XDG_CONFIG_HOME=$TMPHOME ./bin/sophosfw auth profile list
```

Expected: `* home    https://example.invalid:4444`.

- [ ] **Step 9: Commit**

```bash
git add internal/cli/auth.go internal/cli/auth_test.go internal/cli/root.go cmd/sophosfw/main.go go.mod go.sum
git commit -m "feat(cli): auth login/status/test/logout/profile commands"
```

---

## Task 26: `cli` — `object` subcommands (list / get / usage / schema)

**Files:**
- Create: `internal/cli/object.go`
- Create: `internal/cli/object_test.go`

> The remaining test functions (`TestObject_List_TablePrintsRows`, `TestObject_List_JSONIncludesEnvelope`, `TestObject_Schema_PrintsCatalogEntry`) shown below go in the same `object_test.go` file alongside the `newRootForObjectTest` helper.

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/object_test.go`:
```go
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeObjectClient struct{ resp *sophos.Response }

func (f fakeObjectClient) Do(context.Context, sophos.Envelope) (*sophos.Response, error) {
	return f.resp, nil
}
func (f fakeObjectClient) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return f.resp, nil
}

func newRootForObjectTest(t *testing.T, resp *sophos.Response) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeObjectClient{resp: resp}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestObject_List_TablePrintsRows(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
		},
	}
	d := newRootForObjectTest(t, resp)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"object", "list", "IPHost"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN")
	require.Contains(t, out.String(), "10.0.0.0")
}

func TestObject_List_JSONIncludesEnvelope(t *testing.T) {
	resp := &sophos.Response{
		LoginOK: true,
		Body: map[string][]json.RawMessage{
			"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network"}`)},
		},
	}
	d := newRootForObjectTest(t, resp)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"object", "list", "IPHost", "--json"})
	require.NoError(t, root.Execute())
	require.True(t, strings.Contains(out.String(), `"schema": "sophosfw.v1.objectList"`))
	require.True(t, strings.Contains(out.String(), `"xmlTag": "IPHost"`))
}

func TestObject_Schema_PrintsCatalogEntry(t *testing.T) {
	d := newRootForObjectTest(t, &sophos.Response{LoginOK: true})
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"object", "schema", "IPHost", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"tag": "IPHost"`)
	require.Contains(t, out.String(), `"usageTag": "IPHostStatistics"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestObject -v
```

- [ ] **Step 3: Implement `internal/cli/object.go`**

```go
package cli

import (
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newObjectCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "object", Short: "Generic Sophos object commands"}
	cmd.AddCommand(
		newObjectListCmd(d, cat),
		newObjectGetCmd(d, cat),
		newObjectUsageCmd(d, cat),
		newObjectSchemaCmd(d, cat),
	)
	return cmd
}

func newObjectListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list <xml-tag-or-alias>",
		Short: "List all objects of the given XML tag",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")

			var filter *sophos.FilterClause
			if filterStr != "" {
				f, err := sophos.ParseFilterFlag(filterStr)
				if err != nil {
					return err
				}
				filter = &f
			}

			out, err := s.List(cmd.Context(), profile, args[0], filter)
			if err != nil {
				return err
			}
			return renderObjectList(cmd, out, cat)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value (e.g. Name:like:LAN)")
	return c
}

func renderObjectList(cmd *cobra.Command, out *svc.ObjectList, cat *catalog.Catalog) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		payload := map[string]any{
			"profile": out.Profile,
			"xmlTag":  out.Tag,
			"count":   out.Count,
			"items":   out.Items,
		}
		if out.Filter != nil {
			payload["filter"] = map[string]any{
				"field":    out.Filter.Field,
				"criteria": out.Filter.Criteria,
				"value":    out.Filter.Value,
			}
		}
		return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.objectList", payload)
	}
	entry, _ := cat.Resolve(out.Tag)
	headers := entry.Columns
	rows := make([][]string, 0, len(out.Items))
	for _, item := range out.Items {
		rows = append(rows, columnsFor(item, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

// columnsFor extracts named fields from a typed struct (via JSON round-trip)
// or a map[string]any.
func columnsFor(item any, columns []string) []string {
	m, ok := item.(map[string]any)
	if !ok {
		// Round-trip through JSON to reach struct fields by name.
		b, _ := jsonMarshalImpl(item)
		_ = jsonUnmarshalImpl(b, &m)
	}
	row := make([]string, len(columns))
	for i, col := range columns {
		if v, ok := m[col]; ok {
			row[i] = stringify(v)
		}
	}
	return row
}

func stringify(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func newObjectGetCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var name string
	c := &cobra.Command{
		Use:   "get <xml-tag-or-alias>",
		Short: "Get a single object by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")
			obj, err := s.Get(cmd.Context(), profile, args[0], name)
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.object", map[string]any{
					"profile": obj.Profile,
					"xmlTag":  obj.Tag,
					"name":    obj.Name,
					"typed":   obj.Typed,
					"data":    obj.Data,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s:\n%v\n", obj.Tag, obj.Name, obj.Data)
			return nil
		},
	}
	c.Flags().StringVar(&name, "name", "", "object name")
	_ = c.MarkFlagRequired("name")
	return c
}

func newObjectUsageCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var name string
	c := &cobra.Command{
		Use:   "usage <xml-tag-or-alias>",
		Short: "Show object usage / statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")
			u, err := s.Usage(cmd.Context(), profile, args[0], name)
			if err != nil {
				return err
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.objectUsage", map[string]any{
				"profile":   u.Profile,
				"xmlTag":    u.Tag,
				"usageTag":  u.UsageTag,
				"name":      u.Name,
				"records":   u.Records,
			})
		},
	}
	c.Flags().StringVar(&name, "name", "", "object name to look up usage for")
	return c
}

func newObjectSchemaCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "schema <xml-tag-or-alias>",
		Short: "Print the catalog entry for an XML tag",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.ObjectSvc{Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient}
			e, err := s.Schema(args[0])
			if err != nil {
				return err
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.objectSchema", map[string]any{
				"tag":         e.Tag,
				"aliases":     e.Aliases,
				"description": e.Description,
				"columns":     e.Columns,
				"filterable":  e.Filterable,
				"usageTag":    e.UsageTag,
				"typedParser": e.TypedParser,
			})
		},
	}
}
```

Add a marshal helper to `internal/svc/json_helper.go` for the columnsFor round-trip. Edit it to:

```go
package svc

import "encoding/json"

func jsonUnmarshalImpl(raw []byte, v any) error { return json.Unmarshal(raw, v) }
func jsonMarshalImpl(v any) ([]byte, error)     { return json.Marshal(v) }
```

…and in `internal/cli/object.go`, change the references to use the new shims. (You can also inline `encoding/json` in `cli/object.go` directly — it's fine to import it there as well; the `svc` shims exist only to keep test files clean.)

Replace the `jsonMarshalImpl`/`jsonUnmarshalImpl` calls in `columnsFor` with direct `encoding/json` calls, and add `import "encoding/json"` to `object.go`.

- [ ] **Step 4: Wire `object` into root**

In `internal/cli/root.go`, modify `NewRoot` to load the catalog once and pass it down:

```go
func NewRoot(d RootDeps) *cobra.Command {
	root := &cobra.Command{
		Use:           "sophosfw",
		Short:         "Sophos Firewall CLI + MCP server",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// (… persistent flags as before …)

	cat, _ := catalog.NewDefault() // failure here is treated as bug; tests catch it
	root.AddCommand(newVersionCmd(d))
	root.AddCommand(newAuthCmd(d))
	root.AddCommand(newObjectCmd(d, cat))

	return root
}
```

…and add the catalog import to `root.go`.

- [ ] **Step 5: Run tests and build**

```bash
go test ./... && make build
```

- [ ] **Step 6: Commit**

```bash
git add internal/cli/object.go internal/cli/object_test.go internal/cli/root.go internal/svc/json_helper.go
git commit -m "feat(cli): object list/get/usage/schema with JSON+table output"
```

---

## Task 27: `cli` — `raw` subcommands (get / request --dry-run)

**Files:**
- Create: `internal/cli/raw.go`
- Create: `internal/cli/raw_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/raw_test.go`:
```go
package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type rawFakeClient struct{}

func (rawFakeClient) Do(context.Context, sophos.Envelope) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}
func (rawFakeClient) DoRaw(context.Context, []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForRawTest(t *testing.T) *RootDeps {
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client { return rawFakeClient{} }
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestRaw_Get_PrintsEnvelope(t *testing.T) {
	d := newRootForRawTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "get", "IPHost", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.rawResponse"`)
}

func TestRaw_Request_DryRunDetectsMutating(t *testing.T) {
	d := newRootForRawTest(t)
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "mut.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--dry-run", "--json"})
	require.NoError(t, root.Execute())

	require.Contains(t, out.String(), `"mutating": true`)
	require.Contains(t, out.String(), `"Set:add"`)
	require.False(t, strings.Contains(out.String(), "<Username>u</Username>"), "credentials must not appear unredacted")
}

func TestRaw_Request_YesReturnsUnsupported(t *testing.T) {
	d := newRootForRawTest(t)
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "x.xml")
	require.NoError(t, os.WriteFile(xmlPath, []byte(`<Set operation="add"></Set>`), 0o600))

	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"raw", "request", xmlPath, "--yes"})
	err := root.Execute()
	require.Error(t, err)
	require.ErrorIs(t, err, svc.ErrUnsupportedInPhase)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestRaw_ -v
```

- [ ] **Step 3: Implement `internal/cli/raw.go`**

```go
package cli

import (
	"io"
	"os"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newRawCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "raw",
		Short: "Raw Sophos XML API access (escape hatch)",
	}
	cmd.AddCommand(newRawGetCmd(d), newRawRequestCmd(d))
	return cmd
}

func newRawGetCmd(d RootDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "get <xml-tag>",
		Short: "Issue <Get><Tag></Tag></Get> for an arbitrary XML tag",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s := &svc.RawSvc{Config: d.Config, Creds: d.Creds, NewClient: d.NewClient}
			profile, _ := cmd.Flags().GetString("profile")
			r, err := s.Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			body := map[string]any{}
			for tag, recs := range r.Body {
				items := make([]string, 0, len(recs))
				for _, rec := range recs {
					items = append(items, string(rec))
				}
				body[tag] = items
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.rawResponse", map[string]any{
				"profile": r.Profile,
				"xmlTag":  r.Tag,
				"body":    body,
			})
		},
	}
}

func newRawRequestCmd(d RootDeps) *cobra.Command {
	var dryRun, yes bool
	c := &cobra.Command{
		Use:   "request <file|->",
		Short: "Send (preview) a hand-authored Sophos XML envelope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")

			var (
				body []byte
				err  error
			)
			if args[0] == "-" {
				body, err = io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
			} else {
				body, err = os.ReadFile(args[0])
				if err != nil {
					return err
				}
			}

			s := &svc.RawSvc{Config: d.Config, Creds: d.Creds, NewClient: d.NewClient}

			if !dryRun && !yes {
				dryRun = true // default to safety
			}

			if yes {
				return s.Apply(cmd.Context(), profile, body)
			}

			pv, err := s.Preview(cmd.Context(), profile, body)
			if err != nil {
				return err
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.preview", map[string]any{
				"profile":        pv.Profile,
				"mutating":       pv.Mutating,
				"verbs":          pv.Verbs,
				"redactedXml":    pv.RedactedXML,
				"wouldSendBytes": pv.WouldSendBytes,
				"warning":        pv.Warning,
			})
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview only (default in foundation phase)")
	c.Flags().BoolVar(&yes, "yes", false, "(reserved) apply path is not implemented in foundation")
	return c
}
```

- [ ] **Step 4: Wire `raw` into root**

In `internal/cli/root.go`, add `root.AddCommand(newRawCmd(d))`.

- [ ] **Step 5: Run tests and build**

```bash
go test ./... && make build
```

- [ ] **Step 6: Commit**

```bash
git add internal/cli/raw.go internal/cli/raw_test.go internal/cli/root.go
git commit -m "feat(cli): raw get and raw request --dry-run with mutating-XML detection"
```

---

## Task 28: `mcp` package — zero-tool stub server

**Files:**
- Create: `internal/mcp/server.go`
- Create: `internal/mcp/server_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/server_test.go`:
```go
package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/stretchr/testify/require"
)

func TestServer_StartupExercisesSeam(t *testing.T) {
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	store := creds.NewFileStore(t.TempDir())

	s := NewServer(Deps{
		Config:    cfg,
		Creds:     store,
		Catalog:   cat,
	})
	msg, err := s.StartupReport(context.Background())
	require.NoError(t, err)
	require.True(t, strings.Contains(msg, "0 tools registered"),
		"got: %s", msg)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/mcp -v
```

- [ ] **Step 3: Implement `internal/mcp/server.go`**

```go
// Package mcp is the foundation-phase MCP server scaffold. It registers zero
// tools but exists to prove the seam: the catalog and svc packages must be
// usable from a non-Cobra consumer. Phase 4 will add the real tool surface.
package mcp

import (
	"context"
	"fmt"
	"io"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
)

// Deps are the dependencies the MCP server needs from main.
type Deps struct {
	Config  *config.Config
	Creds   creds.Store
	Catalog *catalog.Catalog
}

// Server is the MCP server stub.
type Server struct {
	deps Deps
}

// NewServer constructs a stub server.
func NewServer(d Deps) *Server { return &Server{deps: d} }

// StartupReport returns the line printed by `mcp serve` at startup. It also
// exercises the seam by calling into the catalog so a future Phase-4 plug-in
// can rely on Catalog being non-nil and loadable.
func (s *Server) StartupReport(ctx context.Context) (string, error) {
	tags := s.deps.Catalog.Tags()
	return fmt.Sprintf(
		"sophosfw MCP server: 0 tools registered (foundation phase scaffold; Phase 4 will add tools). Catalog has %d tags loaded.",
		len(tags),
	), nil
}

// Serve is the entrypoint for `mcp serve`. In foundation phase it simply
// prints the startup report and blocks on ctx.Done(). Phase 4 will replace
// this with the real MCP transport (stdio JSON-RPC) and tool registration.
func (s *Server) Serve(ctx context.Context, w io.Writer) error {
	msg, err := s.StartupReport(ctx)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, msg); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/mcp -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/mcp/server.go internal/mcp/server_test.go
git commit -m "feat(mcp): zero-tool server stub exercising the catalog seam"
```

---

## Task 29: `cli` — `mcp serve` command

**Files:**
- Create: `internal/cli/mcp.go`
- Create: `internal/cli/mcp_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/cli/mcp_test.go`:
```go
package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMCPServe_PrintsStartupAndExitsOnContextCancel(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	root.SetContext(ctx)
	root.SetArgs([]string{"mcp", "serve"})

	err := root.Execute()
	// We expect either nil (clean shutdown) or context-canceled — both are OK.
	if err != nil {
		require.True(t, strings.Contains(err.Error(), "context"), "unexpected error: %v", err)
	}
	require.Contains(t, out.String(), "0 tools registered")
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestMCPServe -v
```

- [ ] **Step 3: Implement `internal/cli/mcp.go`**

```go
package cli

import (
	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/mcp"
	"github.com/spf13/cobra"
)

func newMCPCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "mcp", Short: "MCP server commands"}
	cmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server (foundation phase: zero tools registered)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s := mcp.NewServer(mcp.Deps{
				Config:  d.Config,
				Creds:   d.Creds,
				Catalog: cat,
			})
			return s.Serve(cmd.Context(), cmd.OutOrStdout())
		},
	})
	return cmd
}
```

- [ ] **Step 4: Wire `mcp` into root**

In `internal/cli/root.go`, add `root.AddCommand(newMCPCmd(d, cat))` after the other commands.

- [ ] **Step 5: Run tests and build**

```bash
go test ./... && make build
```

- [ ] **Step 6: Smoke test**

```bash
./bin/sophosfw mcp serve &
PID=$!
sleep 0.2
kill $PID
wait $PID 2>/dev/null
```

Expected: prints the "0 tools registered" line then exits when killed.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/mcp.go internal/cli/mcp_test.go internal/cli/root.go
git commit -m "feat(cli): mcp serve command (zero-tool stub)"
```

---

## Task 30: Agent skill — canonical files in skillshare + symlink

**Files:**
- Create: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/SKILL.md`
- Create: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/examples.md`
- Create: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/safety-checklist.md`
- Create: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/api-patterns.md`
- Create: `/Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall/audit-template.md`
- Create: `.claude/skills/sophos-firewall` (symlink in repo)

- [ ] **Step 1: Create the skill directory in skillshare**

```bash
mkdir -p /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall
```

- [ ] **Step 2: Write `SKILL.md`** (canonical path above)

```markdown
---
name: sophos-firewall
description: |
  Use when the user wants to inspect, search, or (later) modify Sophos Firewall
  configuration. Covers the sophosfw CLI and its MCP server. Read-only by
  default; any mutating operation requires explicit human confirmation.
  Production firewall is treated as live infrastructure.
---

# Sophos Firewall CLI + MCP Agent Skill

## Purpose

This skill lets an AI agent operate the `sophosfw` Go CLI and its MCP server
to inspect Sophos Firewall configuration safely. The CLI talks to the Sophos
XML API (`/webconsole/APIController`); credentials live in the macOS Keychain
on Darwin and a 0600 file on other platforms.

## When to Use This Skill
- The user asks to look at firewall objects, rules, or NAT.
- The user asks to search for a host, service, or rule by name or filter.
- The user asks to test connectivity to the firewall.
- The user wants a summary or audit of part of their firewall config.

## When NOT to Use This Skill
- If the user wants to *change* firewall configuration: only `--dry-run`
  preview is supported in foundation phase. Apply paths arrive in Phase 6.
- If you do not have an `auth profile` configured locally — ask the user to
  run `sophosfw auth profile add … && sophosfw auth login` first.

## Safety Model

Three concentric layers of read-only enforcement:
1. **Client layer.** When a profile is `readOnly: true`, the HTTP client
   refuses any envelope containing `<Set …>` or `<Remove …>`.
2. **Service layer.** `svc` is the only place that accepts user-supplied XML
   (`raw request --dry-run`) and runs `safety.IsMutating` before any send.
3. **Integration tests.** All integration tests construct envelopes through
   a wrapper that mechanically blocks mutations.

Production firewall = live infrastructure. Default to read-only operations.

## Read-Only First Rule

If the user asks for information, prefer:
- `sophosfw object list <tag>` — generic, works for any catalog tag.
- `sophosfw object get <tag> --name <name>` — single record.
- `sophosfw object usage <tag> --name <name>` — where is this object used.
- `sophosfw raw get <tag>` — when the catalog doesn't have what you need.

Do not invoke `sophosfw raw request` unless the user explicitly asks to see
a preview of a hand-authored envelope. Never pass `--yes` — the apply path
is unimplemented and will return `unsupported_in_phase`.

## CLI Usage Pattern

- Always include `--json` for machine-parseable output.
- Always include `--profile <name>` when working across multiple firewalls.
- Exit codes: 0 success, 1 generic, 2 config, 3 auth, 4 read-only violation,
  5 network/TLS, 6 unsupported-in-phase.

## MCP Usage Pattern

Foundation phase ships `sophosfw mcp serve` as a *stub* — zero tools are
registered. Phase 4 will add the real tool surface (`get_auth_status`,
`list_objects`, `get_object`, `get_object_usage`, `list_ip_hosts`, etc.).

For now, prefer the CLI directly. If the user asks you to use MCP tools,
tell them the MCP scaffold is in place but tools land in Phase 4.

## Profile and Credential Handling

- Profiles live in `~/.config/sophosfw/config.yaml`.
- Credentials live in macOS Keychain (Darwin) or `~/.config/sophosfw/credentials.yaml` (0600).
- Never echo credentials to the user. Never include them in commit messages.
- If the user asks "what is my password?", refuse politely.

## Common Read-Only Workflows

See `examples.md` for command-by-command patterns. Quick reference:
- Inventory all IP host objects: `sophosfw object list IPHost --json`.
- Search for a host: `sophosfw object get IPHost --filter Name:like:LAN --json`.
- Check object usage: `sophosfw object usage IPHost --name "LAN-network" --json`.
- Test the connection: `sophosfw auth test --json`.

## Common Change Workflows

**Not implemented in foundation phase.** Phase 6 will land the
`--dry-run`/preview/`--yes`/apply pattern. Until then, if the user wants to
change something, summarize what would need to change and tell them apply
isn't supported yet.

## Raw API Escape Hatch

- `sophosfw raw get <tag>` — for any tag the catalog doesn't have. Safe.
- `sophosfw raw request <file> --dry-run` — preview a hand-authored XML
  envelope. Output includes `mutating`, `verbs`, `redactedXml`, and
  `wouldSendBytes`. Credentials are redacted before display.
- **Never** pass `--yes` in foundation. It always returns `unsupported_in_phase`.

## XML API Basics

Sophos uses XML envelopes. Read paths look like:
```xml
<Request>
  <Login><Username>...</Username><Password>...</Password></Login>
  <Get><IPHost></IPHost></Get>
</Request>
```
Filters live inside the inner tag:
```xml
<IPHost><Filter><key name="Name" criteria="like">LAN</key></Filter></IPHost>
```
Statistics queries (e.g., `IPHostStatistics`) support a richer criteria set
including `like`, `not like`, `startswith`, `in`, `>`, `>=`.

## Output and JSON Parsing

Every JSON success envelope wraps payload under `schema: "sophosfw.v1.<name>"`.
Schema names you'll see: `authStatus`, `connectionTest`, `profileList`,
`objectList`, `object`, `objectUsage`, `objectSchema`, `rawResponse`,
`preview`. Errors use `sophosfw.v1.error` with a `kind` field.

## Error Handling

- `auth_failed` → ask the user to re-run `sophosfw auth login`.
- `not_found` → the object name probably doesn't exist; suggest a search.
- `permission_denied` → the configured Sophos user lacks the right; do not retry.
- `read_only_violation` → the profile is in read-only mode by design. Do not
  attempt to bypass; explain to the user.
- `unsupported_in_phase` → the operation is reserved for a future phase.
  Stop and tell the user.
- `network_error`/`tls_error` → connectivity issue. Check `sophosfw auth test`.

## Audit Summary Pattern

After every operation that touches the firewall, produce a compact summary
using `audit-template.md`. Include the profile, mode, mutating yes/no, the
operation, and any names affected.

## Dangerous Operations Checklist

See `safety-checklist.md`. The short version:
- Don't run `raw request` with `--yes` — apply path is unimplemented.
- Don't disable TLS verification (`--insecure-skip-verify`) without consent.
- Don't change profile mode (`--read-only=false`) on a prod profile without
  explicit confirmation.
- Don't iterate over many tags rapidly — Sophos throttles.

## Examples

See `examples.md`.

## Things Agents MUST NEVER Do

1. Make firewall changes unless the user clearly requested a change.
2. Delete firewall objects.
3. Alter firewall rules, NAT rules, VPN settings, zones, interfaces,
   routing, authentication, certificates, or admin access casually.
4. Use raw mutating XML if a safer first-class command exists.
5. Pass `--insecure-skip-verify` without explicit user approval.
6. Reveal passwords, API credentials, or full credential-containing XML.
7. Assume object names are unique without API confirmation.
8. Treat `--dry-run` as equivalent to apply.
9. Use MCP mutating tools without `confirm: true` (when they exist in Phase 6).

## Current Limitations (Foundation Phase)

- No mutating operations — anything that would change the firewall.
- MCP server is a zero-tool stub.
- Only `IPHost` and `Services` have typed parsers; other tags fall through
  to generic map output.
- No draft/snapshot workflows yet.
- No first-class wrappers for `host ip`, `firewall rule`, `nat rule`, etc.
  Use generic `object` commands instead.
```

- [ ] **Step 3: Write `examples.md`**

```markdown
# sophosfw — examples

## Authentication

Set up a profile and log in:
```bash
sophosfw auth profile add home --url https://fw.example.com:4444
sophosfw auth login --profile home
sophosfw auth status --json
sophosfw auth test --json
```

## Inspect IP host objects

```bash
sophosfw object list IPHost --json
sophosfw object get IPHost --filter Name:like:LAN --json
sophosfw object get IPHost --name "LAN-network" --json
sophosfw object usage IPHost --name "LAN-network" --json
sophosfw object schema IPHost --json
```

## Inspect services

```bash
sophosfw object list Services --json
sophosfw object get Services --name "HTTP" --json
sophosfw object usage Services --name "HTTP" --json
```

## Inspect firewall and NAT rules (generic, no typed parser yet)

```bash
sophosfw object list FirewallRule --json
sophosfw object list NATRule --json
sophosfw object get FirewallRule --name "LAN-To-WAN" --json
```

## Raw API escape hatch

```bash
# Read any tag, even one without a catalog entry
sophosfw raw get Zone --json

# Preview a hand-authored envelope (NEVER ships in this phase)
echo '<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>' > /tmp/req.xml
sophosfw raw request /tmp/req.xml --dry-run --json
```

## MCP scaffold

```bash
sophosfw mcp serve
# Prints: "0 tools registered (foundation phase scaffold; Phase 4 will add tools). Catalog has 12 tags loaded."
```
```

- [ ] **Step 4: Write `safety-checklist.md`**

```markdown
# Sophos Firewall — Dangerous Operations Checklist

Before doing anything that touches the firewall:

1. ☐ Confirm you have explicit user instruction for this action.
2. ☐ Confirm the profile points at the right firewall (`sophosfw auth status --json`).
3. ☐ For any data-changing intent: stop. Foundation phase has no apply path.
4. ☐ For any `--insecure-skip-verify` use: stop, ask the user.
5. ☐ For any `--read-only=false` profile change: stop, ask the user.
6. ☐ Do not iterate more than ~20 tags without a pause; Sophos throttles.
7. ☐ Never echo credentials to user-visible output.
8. ☐ Always include the audit summary after the operation.
9. ☐ If `read_only_violation` returns: do not retry, explain to user.
10. ☐ If `auth_failed` returns: do not retry, ask the user to re-login.
```

- [ ] **Step 5: Write `api-patterns.md`**

```markdown
# Sophos XML API — patterns the agent should know

## Endpoint
```
POST https://<host>:<port>/webconsole/APIController
Content-Type: application/x-www-form-urlencoded
Body:        reqxml=<URL-encoded XML>
```

## Read envelope (single object)
```xml
<Request>
  <Login><Username>...</Username><Password>...</Password></Login>
  <Get>
    <IPHost>
      <Filter><key name="Name" criteria="=">LAN-network</key></Filter>
    </IPHost>
  </Get>
</Request>
```

## Read envelope (filter many)
```xml
<Request>
  <Login>...</Login>
  <Get>
    <IPHost>
      <Filter><key name="Name" criteria="like">LAN</key></Filter>
    </IPHost>
  </Get>
</Request>
```

## Statistics envelope
```xml
<Request>
  <Login>...</Login>
  <IPHostStatistics>
    <Filter><key name="Name" criteria="=">LAN-network</key></Filter>
  </IPHostStatistics>
</Request>
```

## Status codes (foundation handles these)
- 200-216: success
- 526: not found
- 534: authentication failure
- 535: permission denied
- 500-530: invalid request
- other: server error

## Filter criteria
- Object Get: `=`, `!=`, `like`
- *Statistics*: `=`, `!=`, `like`, `not like`, `startswith`, `in`, `>`, `>=`
```

- [ ] **Step 6: Write `audit-template.md`**

```markdown
# Sophos Firewall — Audit Summary Template

Produce one of these after every operation that touches the firewall:

```
Operation: <CLI command or MCP tool name>
Profile:   <name>
Mode:      <read-only | read-write>
Mutating:  <yes | no>
Result:    <ok | error:<kind>>
Affected:  <count> <tag> object(s)
Names:     <name1, name2, ...>
Notes:     <slow response, partial data, etc.>
```

Example:
```
Operation: sophosfw object list IPHost --filter Name:like:LAN
Profile:   home
Mode:      read-write
Mutating:  no
Result:    ok
Affected:  3 IPHost object(s)
Names:     LAN-network, LAN-DHCP-pool, LAN-printers
Notes:     none
```
```

- [ ] **Step 7: Create the project symlink**

```bash
mkdir -p /Users/ipm/code/sophosfw/.claude/skills
ln -s /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall \
      /Users/ipm/code/sophosfw/.claude/skills/sophos-firewall
ls -la /Users/ipm/code/sophosfw/.claude/skills/
```

Expected: shows `sophos-firewall -> /Users/ipm/code/ai-tooling/skillshare/skills/sophos-firewall`.

- [ ] **Step 8: Commit the symlink**

```bash
git add .claude/skills/sophos-firewall
git commit -m "feat(skill): symlink sophos-firewall skill from ai-tooling/skillshare"
```

(Note: the canonical files in `/Users/ipm/code/ai-tooling/skillshare/...` are committed in *that* repo, separately. This commit only adds the project-side symlink.)

---

## Task 31: `cli` — `skill doctor` subcommand + `make skill-doctor`

**Files:**
- Create: `internal/cli/skill.go`
- Create: `internal/cli/skill_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/skill_test.go`:
```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSkillDoctor_PassesWhenSkillExists(t *testing.T) {
	// Set up a fake project root with a fake skill.
	dir := t.TempDir()
	skillDir := filepath.Join(dir, ".claude", "skills", "sophos-firewall")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"),
		[]byte(`# Skill\n\nReferences sophosfw auth status, sophosfw object list, sophosfw raw get, sophosfw mcp serve.`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status\nsophosfw object list IPHost\nsophosfw raw get IPHost\nsophosfw mcp serve`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.NoError(t, root.Execute())
}

func TestSkillDoctor_FailsWhenSkillMissing(t *testing.T) {
	d, _ := newRootForTest(t)
	d.SkillDir = filepath.Join(t.TempDir(), "absent")
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}

func TestSkillDoctor_FailsIfRequiredCommandMissingFromExamples(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	require.NoError(t, os.MkdirAll(skillDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`x`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(skillDir, "examples.md"),
		[]byte(`sophosfw auth status`), 0o600))

	d, _ := newRootForTest(t)
	d.SkillDir = skillDir
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"skill", "doctor"})
	require.Error(t, root.Execute())
}
```

- [ ] **Step 2: Add `SkillDir` to `RootDeps`**

In `internal/cli/root.go`, extend `RootDeps`:
```go
type RootDeps struct {
	Version   string
	BaseDir   string
	SkillDir  string
	Config    *config.Config
	Creds     creds.Store
	NewClient svc.ClientFactory
}
```

- [ ] **Step 3: Run — must fail**

```bash
go test ./internal/cli -run TestSkillDoctor -v
```

- [ ] **Step 4: Implement `internal/cli/skill.go`**

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var requiredCommandsInExamples = []string{
	"sophosfw auth status",
	"sophosfw object list",
	"sophosfw raw get",
	"sophosfw mcp serve",
}

func newSkillCmd(d RootDeps) *cobra.Command {
	cmd := &cobra.Command{Use: "skill", Short: "Agent-skill maintenance helpers"}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "path",
			Short: "Print the absolute path to the installed agent skill",
			RunE: func(cmd *cobra.Command, _ []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), d.SkillDir)
				return nil
			},
		},
		&cobra.Command{
			Use:   "doctor",
			Short: "Validate that the agent skill is in sync with the implementation",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runSkillDoctor(cmd.OutOrStdout(), d.SkillDir)
			},
		},
	)
	return cmd
}

func runSkillDoctor(out interface{ Write([]byte) (int, error) }, skillDir string) error {
	if _, err := os.Stat(skillDir); err != nil {
		return fmt.Errorf("skill directory missing: %s", skillDir)
	}

	skillFile := filepath.Join(skillDir, "SKILL.md")
	if _, err := os.Stat(skillFile); err != nil {
		return fmt.Errorf("SKILL.md missing in %s", skillDir)
	}

	examplesFile := filepath.Join(skillDir, "examples.md")
	body, err := os.ReadFile(examplesFile)
	if err != nil {
		return fmt.Errorf("examples.md missing in %s: %w", skillDir, err)
	}
	text := string(body)
	missing := []string{}
	for _, req := range requiredCommandsInExamples {
		if !strings.Contains(text, req) {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("examples.md is missing required commands: %s", strings.Join(missing, ", "))
	}
	fmt.Fprintln(out, "skill ok")
	return nil
}
```

- [ ] **Step 5: Wire `skill` into root and pass `SkillDir` from main**

Add `root.AddCommand(newSkillCmd(d))` in `NewRoot`.

In `cmd/sophosfw/main.go`, set `SkillDir` to the symlinked path:
```go
SkillDir: filepath.Join(".claude", "skills", "sophos-firewall"),
```
(Use `filepath` from the `path/filepath` package.)

- [ ] **Step 6: Run tests and verify the doctor against the real skill**

```bash
go test ./... && make skill-doctor
```

Expected: `skill ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/skill.go internal/cli/skill_test.go internal/cli/root.go cmd/sophosfw/main.go
git commit -m "feat(cli): skill path/doctor commands + make skill-doctor"
```

---

## Task 32: Integration test scaffolding

**Files:**
- Create: `internal/testutil/integration.go`
- Create: `internal/testutil/integration_test.go`

- [ ] **Step 1: Implement the integration client wrapper**

Create `internal/testutil/integration.go`:
```go
//go:build integration

// Package testutil provides test helpers including the IntegrationClient
// wrapper that mechanically prevents mutating envelopes during integration
// tests. The build tag ensures this code is only compiled when the
// integration tests are explicitly requested.
package testutil

import (
	"context"
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/safety"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// IntegrationClient wraps a sophos.Client and panics at construction time on
// any envelope containing mutating verbs. This is stronger than the runtime
// read-only check because it fails *during the test*, not on a server response.
type IntegrationClient struct {
	inner *sophos.Client
}

// NewIntegrationClient builds the wrapper. Caller must construct the inner
// sophos.Client themselves so test setup remains explicit.
func NewIntegrationClient(inner *sophos.Client) *IntegrationClient {
	return &IntegrationClient{inner: inner}
}

func (c *IntegrationClient) Do(ctx context.Context, env sophos.Envelope) (*sophos.Response, error) {
	xml, err := sophos.BuildEnvelope(env, c.inner.Username, c.inner.Password)
	if err != nil {
		return nil, err
	}
	if mutating, verbs := safety.IsMutating(xml); mutating {
		panic(fmt.Sprintf("integration test attempted mutating envelope: %v", verbs))
	}
	return c.inner.Do(ctx, env)
}

func (c *IntegrationClient) DoRaw(ctx context.Context, raw []byte) (*sophos.Response, error) {
	if mutating, verbs := safety.IsMutating(raw); mutating {
		panic(fmt.Sprintf("integration test attempted mutating raw envelope: %v", verbs))
	}
	return c.inner.DoRaw(ctx, raw)
}
```

- [ ] **Step 2: Implement an actual integration test**

Create `internal/testutil/integration_test.go`:
```go
//go:build integration

package testutil

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func loadProfile(t *testing.T) (config.Profile, creds.Credentials) {
	t.Helper()
	profileName := os.Getenv("SOPHOSFW_PROFILE")
	require.NotEmpty(t, profileName, "set SOPHOSFW_PROFILE for integration tests")

	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	p, _, err := cfg.ActiveProfile(profileName)
	require.NoError(t, err)

	store := creds.New(baseDir)
	c, err := store.Load(profileName)
	require.NoError(t, err)
	return p, c
}

func newClient(t *testing.T) *IntegrationClient {
	t.Helper()
	p, c := loadProfile(t)
	inner := sophos.NewClient(sophos.ClientConfig{
		BaseURL:  p.URL,
		Username: c.Username,
		Password: c.Password,
		Timeout:  15 * time.Second,
	})
	return NewIntegrationClient(inner)
}

func TestIntegration_AuthTest_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}},
	})
	require.NoError(t, err)
}

func TestIntegration_CatalogTagsAllRoundTrip(t *testing.T) {
	c := newClient(t)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)

	for _, tag := range cat.Tags() {
		t.Run(tag, func(t *testing.T) {
			_, err := c.Do(context.Background(), sophos.Envelope{
				Operations: []sophos.Op{sophos.GetOp{XMLTag: tag}},
			})
			// Some tags may legitimately 404 in an empty environment;
			// accept ErrNotFound but reject auth/permission/server failures.
			if err != nil && !errorsIsAny(err, sophos.ErrNotFound) {
				t.Fatalf("tag %q: unexpected error: %v", tag, err)
			}
		})
	}
}

func errorsIsAny(err error, targets ...error) bool {
	for _, t := range targets {
		if err == t {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Verify the build tag isolates the code**

```bash
go test ./... && go build ./...
```

Expected: passes; no integration code is compiled into the normal test binary.

- [ ] **Step 4: Optionally smoke-run integration**

(Only if you have credentials set up.)
```bash
SOPHOSFW_INTEGRATION=1 SOPHOSFW_PROFILE=home make test-int
```

Expected: `TestIntegration_AuthTest_RoundTrips` passes; per-tag subtests either pass or report `ErrNotFound`. No mutating panic.

- [ ] **Step 5: Commit**

```bash
git add internal/testutil/integration.go internal/testutil/integration_test.go
git commit -m "test(integration): IntegrationClient wrapper and read-only round-trip suite"
```

---

## Task 33: Project documentation — README, AGENTS.md, CLAUDE.md, docs/

**Files:**
- Create: `README.md`
- Create: `AGENTS.md`
- Create: `CLAUDE.md`
- Create: `docs/configuration.md`
- Create: `docs/safety-model.md`
- Create: `docs/api-coverage.md`
- Create: `docs/command-map.md`
- Create: `docs/agent-skill.md`
- Create: `docs/examples.md`
- Create: `docs/roadmap.md`

- [ ] **Step 1: Write `README.md`**

```markdown
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

## Install

```bash
git clone https://github.com/iainmoffat/sophosfw   # not yet published
cd sophosfw
make build
./bin/sophosfw version
```

Or `make install` to copy to `$GOBIN`.

## Quick start

```bash
sophosfw auth profile add home --url https://fw.example.com:4444
sophosfw auth login --profile home
sophosfw auth test --json
sophosfw object list IPHost --json
sophosfw object get IPHost --filter Name:like:LAN --json
```

## Safety warning

This tool talks to live firewall infrastructure. The foundation phase ships
no apply path — all mutating raw XML is preview-only. Read `docs/safety-model.md`
before doing anything beyond inspection.

## Sophos API prerequisites

The Sophos API is **disabled by default**. To use this tool:
1. Enable API access in the firewall web admin UI.
2. Add the host running `sophosfw` to the API allowed-clients list.
3. Confirm the API endpoint is reachable: `https://<host>:<admin-port>/webconsole/APIController`.

## MCP setup (foundation: stub only)

```json
{
  "mcpServers": {
    "sophosfw": {
      "command": "sophosfw",
      "args": ["mcp", "serve"]
    }
  }
}
```
The Phase-4 release will add the real tool surface; for now this serves
zero tools.

## Agent skill

Detailed agent guidance lives at
[`.claude/skills/sophos-firewall/SKILL.md`](.claude/skills/sophos-firewall/SKILL.md)
(symlink to `ai-tooling/skillshare/skills/sophos-firewall/`).
```

- [ ] **Step 2: Write `AGENTS.md` and `CLAUDE.md`**

`AGENTS.md`:
```markdown
# AGENTS.md — sophosfw

## Operating rules
- Treat the Sophos API as production. Default to read-only.
- Never log unredacted credentials. Use `safety.RedactXML` first.
- Mutating commands are not implemented in foundation phase. Do not add them
  outside a Phase-6 spec.
- Integration tests must round-trip through `internal/testutil.IntegrationClient`
  which mechanically blocks mutations. Do not add integration tests that bypass it.

## Where to look
- Spec: `docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md`
- Plan: `docs/superpowers/plans/2026-04-30-sophosfw-foundation.md`
- Roadmap (Phases 3-7): `docs/roadmap.md`
- Agent skill: `.claude/skills/sophos-firewall/SKILL.md`

## Conventions
- Cobra commands in `internal/cli/`; thin — they call into `internal/svc`.
- Service layer is the only home for read-only enforcement and dry-run gating.
- Catalog is the seam for adding new XML tags. YAML metadata + optional Go-typed parser.
- JSON envelope schema names follow `sophosfw.v1.<name>`.
```

`CLAUDE.md`:
```markdown
# CLAUDE.md

This file mirrors `AGENTS.md` for Claude-specific tools that look here.
See [`AGENTS.md`](AGENTS.md) for the canonical project rules.
```

- [ ] **Step 3: Write `docs/configuration.md`** — short reference for the `config.yaml` and credential layouts (mirror what's in `internal/config/config.go` and the spec section 4).

- [ ] **Step 4: Write `docs/safety-model.md`** — explain the three-layer enforcement and credential redaction, link the spec section.

- [ ] **Step 5: Write `docs/api-coverage.md`** with this table:

```markdown
# API coverage

| Area | XML Tag | CLI Command | MCP Tool | Get | Add | Update | Remove | Usage | Status |
|---|---|---|---|---|---|---|---|---|---|
| Host | IPHost | object list/get IPHost | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | IPHostGroup | object list/get IPHostGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Service | Services | object list/get Services | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Service | ServiceGroup | object list/get ServiceGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | FQDNHost | object list/get FQDNHost | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | FQDNHostGroup | object list/get FQDNHostGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | MACHost | object list/get MACHost | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Zone | object list/get Zone | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Interface | object list/get Interface | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Gateway | object list/get Gateway | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Firewall | FirewallRule | object list/get FirewallRule | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | n/a | partial |
| Firewall | NATRule | object list/get NATRule | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | n/a | partial |

Source references: Sophos 22.0 API docs, Sophos Postman collection, Sophos Python SDK behavior.
```

- [ ] **Step 6: Write `docs/command-map.md`** — list implemented vs planned vs long-term commands.

- [ ] **Step 7: Write `docs/agent-skill.md`** — explain skill location, sync mechanism, validation.

- [ ] **Step 8: Write `docs/examples.md`** — link or copy from the skill `examples.md`.

- [ ] **Step 9: Write `docs/roadmap.md`** — Phases 3-7 with one paragraph each, copying from the spec section 6.

- [ ] **Step 10: Commit**

```bash
git add README.md AGENTS.md CLAUDE.md docs/
git commit -m "docs: README, agent guidance, config/safety/api-coverage/roadmap"
```

---

## Task 34: Implementation plan + design doc cross-references

**Files:**
- Modify: `docs/implementation-plan.md` (create as a thin pointer)

- [ ] **Step 1: Create the implementation-plan pointer**

Create `docs/implementation-plan.md`:
```markdown
# sophosfw implementation plan

The active plan lives at:
[`docs/superpowers/plans/2026-04-30-sophosfw-foundation.md`](superpowers/plans/2026-04-30-sophosfw-foundation.md).

The design that drove this plan:
[`docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md`](superpowers/specs/2026-04-30-sophosfw-foundation-design.md).

Phases 3-7 are tracked in [`docs/roadmap.md`](roadmap.md). Each future phase
gets its own brainstorm → spec → plan → implementation cycle.
```

- [ ] **Step 2: Commit**

```bash
git add docs/implementation-plan.md
git commit -m "docs: implementation-plan pointer to the active spec and plan"
```

---

## Task 35: Acceptance verification

**Files:** none new — runs the foundation acceptance checklist from the spec.

- [ ] **Step 1: Run the full test suite**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```

Expected: PASS, no warnings.

- [ ] **Step 2: Build and inspect the binary**

```bash
make build
./bin/sophosfw version
./bin/sophosfw --help
```

- [ ] **Step 3: Walk through the acceptance items manually**

In a scratch directory (e.g., `mktemp -d` and set `XDG_CONFIG_HOME` to it):
```bash
./bin/sophosfw auth profile add home --url https://example.invalid:4444
./bin/sophosfw auth profile list
./bin/sophosfw auth profile list --json
./bin/sophosfw auth status --json   # loggedIn:false expected
./bin/sophosfw object schema IPHost --json
./bin/sophosfw mcp serve &           # prints scaffold line
sleep 0.2 && kill %1
```

- [ ] **Step 4: Run skill-doctor**

```bash
make skill-doctor
```
Expected: `skill ok`.

- [ ] **Step 5: Optional integration smoke (only if creds are set up)**

```bash
./bin/sophosfw auth login --profile home
./bin/sophosfw auth test --json
./bin/sophosfw raw get IPHost --json | head -20
./bin/sophosfw object list IPHost --json | head -20
./bin/sophosfw object get IPHost --filter Name:like:LAN --json | head -20
SOPHOSFW_INTEGRATION=1 SOPHOSFW_PROFILE=home make test-int
```

Expected: each command returns a `sophosfw.v1.*` envelope; integration tests pass.

- [ ] **Step 6: Tag the foundation milestone**

```bash
git tag -a v0.1.0-foundation -m "Foundation phase complete (Phases 0-2)"
```

- [ ] **Step 7: Final commit (if anything was tweaked during verification)**

```bash
git status
# If clean, you're done. If not, commit the fixes:
git add -A
git commit -m "fix: foundation acceptance pass adjustments"
```

---

## End of plan

This concludes the foundation implementation plan. Next steps live in
`docs/roadmap.md` (Phases 3-7), each of which should go through its own
brainstorm → spec → plan → implementation cycle.
