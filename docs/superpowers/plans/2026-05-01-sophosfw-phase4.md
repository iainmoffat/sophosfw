# sophosfw Phase 4 Implementation Plan — MCP read-only server

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the foundation MCP stub with a real stdio MCP server exposing 21 read-only tools that mirror the cli surface, returning the existing `sophosfw.v1.*` JSON envelopes as MCP tool content.

**Architecture:** Each MCP tool handler is a thin adapter over an existing `svc.*Svc` method. Tools are registered per-group in `internal/mcp/<group>.go` files. Two prep refactors land first: (a) extract envelope construction into `internal/render/envelope.go` so cli and MCP share one source of truth for each `sophosfw.v1.*` schema; (b) extract `cli.ErrorKind` into `internal/svc/errors.go` so cli and MCP share the same error→kind mapping.

**Tech Stack:** Go 1.26.2, `github.com/iainmoffat/sophosfw` module, cobra, lipgloss, testify, and new dep `github.com/modelcontextprotocol/go-sdk` v1.5.0 (matches the user's `tdx` project).

**Spec:** [`docs/superpowers/specs/2026-05-01-sophosfw-phase4-design.md`](../specs/2026-05-01-sophosfw-phase4-design.md)

**Predecessor:** Phase 3, tagged `v0.2.0-phase3` on `main` (commit `92bfc63`).

---

## Conventions

- **Module:** `github.com/iainmoffat/sophosfw`. Working directory: `/Users/ipm/code/sophosfw`.
- **No Co-Authored-By trailer** on implementation commits.
- **Commit messages:** use the exact text given in each task's commit step.
- **SDK package alias:** import as `sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"` (matching tdx convention; avoids collision with our own `internal/mcp` package).
- **Push to origin:** after the phase tag is set in T14.

## SDK API quick reference (verified against tdx + v1.5.0)

```go
import sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

// Server construction
srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "sophosfw", Version: "..."}, nil)

// Tool registration (handler signature is fixed)
sdkmcp.AddTool(srv, &sdkmcp.Tool{
    Name:        "host_ip_list",
    Description: "...",
}, handlerFn)

// Handler
func handlerFn(ctx context.Context, req *sdkmcp.CallToolRequest, args ArgType) (*sdkmcp.CallToolResult, any, error) {
    return &sdkmcp.CallToolResult{
        Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "..."}},
    }, nil, nil
}

// Stdio transport
srv.Run(ctx, &sdkmcp.StdioTransport{})

// In-memory transport pair (for tests)
ct, st := sdkmcp.NewInMemoryTransports()
ss, _ := srv.Connect(ctx, st, nil)            // server side
client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "0"}, nil)
cs, _ := client.Connect(ctx, ct, nil)         // client side
result, _ := cs.ListTools(ctx, nil)
result, _ := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "host_ip_list", Arguments: argsMap})
```

`*sdkmcp.CallToolResult{IsError: true}` is reserved for SDK-detected failures (schema validation, panics). Phase 4 business errors come back as IsError=false with a `sophosfw.v1.error` envelope text body (per spec §6).

---

## Task 1: SDK dep + render envelope helpers refactor

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/render/envelope.go`
- Create: `internal/render/envelope_test.go`
- Modify: `internal/cli/auth.go`, `internal/cli/object.go`, `internal/cli/raw.go`, `internal/cli/hostip.go`, `internal/cli/service.go`, `internal/cli/firewallrule.go`, `internal/cli/natrule.go`

This is the biggest task in the plan. It adds the SDK dependency AND extracts envelope construction into shared helpers. The refactor is invisible to cli consumers — JSON output is byte-identical — so the existing cli tests stay green.

- [ ] **Step 1: Add the SDK dependency**

```bash
go get github.com/modelcontextprotocol/go-sdk@v1.5.0
go mod tidy
```

Verify it landed:
```bash
grep "modelcontextprotocol/go-sdk" go.mod
```
Expected: `github.com/modelcontextprotocol/go-sdk v1.5.0` line present.

- [ ] **Step 2: Confirm the existing build still works**

```bash
go build ./...
go test ./... -count=1
```
Expected: PASS for both. (Adding a dep without using it shouldn't break anything.)

- [ ] **Step 3: Create `internal/render/envelope.go` (first half)**

`catalog` is a leaf package (it has no `svc` imports), so `render` can import both `svc` and `catalog` cleanly. Create the file with all the simple envelope helpers:

```go
// Package render envelope.go: construct sophosfw.v1.* JSON envelopes as
// byte slices. The cli layer writes these directly; the mcp layer wraps
// them as TextContent. Keeping construction in one place ensures that
// changing an envelope shape changes both surfaces in lockstep.
package render

import (
	"bytes"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// AuthStatusEnvelope renders sophosfw.v1.authStatus.
func AuthStatusEnvelope(st svc.AuthStatus) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.authStatus", map[string]any{
		"profile":            st.Profile,
		"url":                st.URL,
		"loggedIn":           st.LoggedIn,
		"credentialsBackend": st.CredentialsBackend,
	})
}

// ConnectionTestEnvelope renders sophosfw.v1.connectionTest.
func ConnectionTestEnvelope(r svc.ConnectionResult) ([]byte, error) {
	payload := map[string]any{
		"profile":      r.Profile,
		"ok":           r.OK,
		"latencyMs":    r.LatencyMs,
		"apiReachable": r.APIReachable,
		"authOk":       r.AuthOK,
	}
	if r.Error != "" {
		payload["error"] = r.Error
	}
	return marshalEnvelope("sophosfw.v1.connectionTest", payload)
}

// ProfileListEnvelope renders sophosfw.v1.profileList.
func ProfileListEnvelope(currentProfile string, list []svc.ProfileInfo) ([]byte, error) {
	profiles := make([]map[string]any, 0, len(list))
	for _, p := range list {
		profiles = append(profiles, map[string]any{
			"name":     p.Name,
			"url":      p.URL,
			"readOnly": p.ReadOnly,
			"current":  p.Current,
		})
	}
	return marshalEnvelope("sophosfw.v1.profileList", map[string]any{
		"current":  currentProfile,
		"profiles": profiles,
	})
}

// ObjectListEnvelope renders sophosfw.v1.objectList.
func ObjectListEnvelope(out *svc.ObjectList) ([]byte, error) {
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
	return marshalEnvelope("sophosfw.v1.objectList", payload)
}

// ObjectEnvelope renders sophosfw.v1.object.
func ObjectEnvelope(obj *svc.Object) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.object", map[string]any{
		"profile": obj.Profile,
		"xmlTag":  obj.Tag,
		"name":    obj.Name,
		"typed":   obj.Typed,
		"data":    obj.Data,
	})
}

// ObjectUsageEnvelope renders sophosfw.v1.objectUsage.
func ObjectUsageEnvelope(u *svc.ObjectUsage) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.objectUsage", map[string]any{
		"profile":  u.Profile,
		"xmlTag":   u.Tag,
		"usageTag": u.UsageTag,
		"name":     u.Name,
		"records":  u.Records,
	})
}

// ObjectSchemaEnvelope renders sophosfw.v1.objectSchema.
func ObjectSchemaEnvelope(e *catalog.Entry) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.objectSchema", map[string]any{
		"tag":         e.Tag,
		"aliases":     e.Aliases,
		"description": e.Description,
		"columns":     e.Columns,
		"filterable":  e.Filterable,
		"usageTag":    e.UsageTag,
		"typedParser": e.TypedParser,
	})
}
```

- [ ] **Step 4: Add the remaining envelope helpers (second half)**

Append to `internal/render/envelope.go`:

```go
// RawResponseEnvelope renders sophosfw.v1.rawResponse. Body is the
// re-encoded XML fragment map keyed by tag.
func RawResponseEnvelope(r *svc.RawResponse) ([]byte, error) {
	body := map[string]any{}
	for tag, recs := range r.Body {
		items := make([]string, 0, len(recs))
		for _, rec := range recs {
			items = append(items, string(rec))
		}
		body[tag] = items
	}
	return marshalEnvelope("sophosfw.v1.rawResponse", map[string]any{
		"profile": r.Profile,
		"xmlTag":  r.Tag,
		"body":    body,
	})
}

// PreviewEnvelope renders sophosfw.v1.preview (raw_request --dry-run).
func PreviewEnvelope(p *svc.Preview) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.preview", map[string]any{
		"profile":        p.Profile,
		"mutating":       p.Mutating,
		"verbs":          p.Verbs,
		"redactedXml":    p.RedactedXML,
		"wouldSendBytes": p.WouldSendBytes,
		"warning":        p.Warning,
	})
}

// HostIPListEnvelope renders sophosfw.v1.hostIpList. The schema name is
// passed in by the caller because list and search reuse the same payload
// shape under different schemas (sophosfw.v1.hostIpList vs hostIpSearch).
func HostIPListEnvelope(schema string, list *svc.HostIPList) ([]byte, error) {
	return marshalEnvelope(schema, map[string]any{
		"profile": list.Profile,
		"xmlTag":  "IPHost",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// HostIPEnvelope renders sophosfw.v1.hostIp.
func HostIPEnvelope(h *svc.HostIP) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.hostIp", h)
}

// HostIPUsageEnvelope renders sophosfw.v1.hostIpUsage.
func HostIPUsageEnvelope(u *svc.HostIPUsage) ([]byte, error) {
	payload := map[string]any{
		"profile": u.Profile,
		"name":    u.Name,
		"records": u.Records,
	}
	if u.References != nil {
		payload["references"] = u.References.Refs
		if len(u.References.Errors) > 0 {
			payload["referenceErrors"] = u.References.Errors
		}
	}
	return marshalEnvelope("sophosfw.v1.hostIpUsage", payload)
}

// ServiceListEnvelope renders sophosfw.v1.serviceList or sophosfw.v1.serviceSearch.
func ServiceListEnvelope(schema string, list *svc.ServiceList) ([]byte, error) {
	return marshalEnvelope(schema, map[string]any{
		"profile": list.Profile,
		"xmlTag":  "Services",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// ServiceEnvelope renders sophosfw.v1.service.
func ServiceEnvelope(v *svc.Service) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.service", v)
}

// ServiceUsageEnvelope renders sophosfw.v1.serviceUsage.
func ServiceUsageEnvelope(u *svc.ServiceUsage) ([]byte, error) {
	payload := map[string]any{
		"profile": u.Profile,
		"name":    u.Name,
		"records": u.Records,
	}
	if u.References != nil {
		payload["references"] = u.References.Refs
		if len(u.References.Errors) > 0 {
			payload["referenceErrors"] = u.References.Errors
		}
	}
	return marshalEnvelope("sophosfw.v1.serviceUsage", payload)
}

// FirewallRuleListEnvelope renders sophosfw.v1.firewallRuleList.
func FirewallRuleListEnvelope(list *svc.FirewallRuleList) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.firewallRuleList", map[string]any{
		"profile": list.Profile,
		"xmlTag":  "FirewallRule",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// FirewallRuleEnvelope renders sophosfw.v1.firewallRule.
func FirewallRuleEnvelope(rule map[string]any) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.firewallRule", rule)
}

// NATRuleListEnvelope renders sophosfw.v1.natRuleList.
func NATRuleListEnvelope(list *svc.NATRuleList) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.natRuleList", map[string]any{
		"profile": list.Profile,
		"xmlTag":  "NATRule",
		"count":   list.Count,
		"items":   list.Items,
	})
}

// NATRuleEnvelope renders sophosfw.v1.natRule.
func NATRuleEnvelope(rule map[string]any) ([]byte, error) {
	return marshalEnvelope("sophosfw.v1.natRule", rule)
}

// ErrorEnvelope renders sophosfw.v1.error.
func ErrorEnvelope(kind, message, profile string) ([]byte, error) {
	payload := map[string]any{
		"kind":    kind,
		"message": message,
	}
	if profile != "" {
		payload["profile"] = profile
	}
	return marshalEnvelope("sophosfw.v1.error", payload)
}

// marshalEnvelope is the shared writer used by all envelope helpers. It
// produces the same indent-2 JSON that WriteJSON does, with the schema
// embedded as the first field.
func marshalEnvelope(schema string, payload any) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, schema, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

- [ ] **Step 5: Write envelope tests**

Create `internal/render/envelope_test.go`:

```go
package render

import (
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func TestAuthStatusEnvelope(t *testing.T) {
	got, err := AuthStatusEnvelope(svc.AuthStatus{
		Profile: "home", URL: "https://x", LoggedIn: false, CredentialsBackend: "keychain",
	})
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.authStatus"`)
	require.Contains(t, s, `"profile": "home"`)
	require.Contains(t, s, `"loggedIn": false`)
	require.Contains(t, s, `"credentialsBackend": "keychain"`)
}

func TestProfileListEnvelope(t *testing.T) {
	got, err := ProfileListEnvelope("home", []svc.ProfileInfo{
		{Name: "home", URL: "https://x:4444", ReadOnly: false, Current: true},
	})
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.profileList"`)
	require.Contains(t, s, `"current": "home"`)
	require.Contains(t, s, `"profiles"`)
	require.Contains(t, s, `"name": "home"`)
}

func TestObjectListEnvelope_NoFilter(t *testing.T) {
	out := &svc.ObjectList{
		Profile: "home", Tag: "IPHost", Count: 0, Items: []any{},
	}
	got, err := ObjectListEnvelope(out)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, s, `"xmlTag": "IPHost"`)
	require.Contains(t, s, `"count": 0`)
	require.False(t, strings.Contains(s, `"filter"`), "no filter clause should mean no filter key")
}

func TestHostIPListEnvelope_HasXmlTag(t *testing.T) {
	list := &svc.HostIPList{Profile: "home", Count: 0, Items: []svc.HostIP{}}
	got, err := HostIPListEnvelope("sophosfw.v1.hostIpList", list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.hostIpList"`)
	require.Contains(t, s, `"xmlTag": "IPHost"`)
}

func TestServiceListEnvelope_SearchSchema(t *testing.T) {
	list := &svc.ServiceList{Profile: "home", Count: 0, Items: []svc.Service{}}
	got, err := ServiceListEnvelope("sophosfw.v1.serviceSearch", list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.serviceSearch"`)
	require.Contains(t, s, `"xmlTag": "Services"`)
}

func TestFirewallRuleListEnvelope(t *testing.T) {
	list := &svc.FirewallRuleList{Profile: "home", Count: 0, Items: []map[string]any{}}
	got, err := FirewallRuleListEnvelope(list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.firewallRuleList"`)
	require.Contains(t, s, `"xmlTag": "FirewallRule"`)
}

func TestNATRuleListEnvelope(t *testing.T) {
	list := &svc.NATRuleList{Profile: "home", Count: 0, Items: []map[string]any{}}
	got, err := NATRuleListEnvelope(list)
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.natRuleList"`)
	require.Contains(t, s, `"xmlTag": "NATRule"`)
}

func TestErrorEnvelope(t *testing.T) {
	got, err := ErrorEnvelope("not_found", "host LAN: not found", "home")
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.error"`)
	require.Contains(t, s, `"kind": "not_found"`)
	require.Contains(t, s, `"profile": "home"`)
}

func TestErrorEnvelope_NoProfile(t *testing.T) {
	got, err := ErrorEnvelope("config_error", "no current profile", "")
	require.NoError(t, err)
	s := string(got)
	require.Contains(t, s, `"schema": "sophosfw.v1.error"`)
	require.False(t, strings.Contains(s, `"profile"`), "empty profile should be omitted")
}
```

- [ ] **Step 6: Run envelope tests — must pass**

```bash
go test ./internal/render -count=1 -v
```
Expected: PASS for all envelope tests plus existing render tests.

- [ ] **Step 7: Refactor cli renderers to use envelope helpers**

This step touches each cli file that emits a `sophosfw.v1.*` envelope. The pattern: replace inline `render.WriteJSON(...)` calls with `render.<Schema>Envelope(...)` followed by `cmd.OutOrStdout().Write(bytes)` plus a trailing newline. Behavior is byte-identical.

Concrete edits:

In `internal/cli/auth.go`:

Find in `newAuthStatusCmd`:
```go
return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.authStatus", map[string]any{
    "profile":            st.Profile,
    "url":                st.URL,
    "loggedIn":           st.LoggedIn,
    "credentialsBackend": st.CredentialsBackend,
})
```
Replace with:
```go
b, err := render.AuthStatusEnvelope(st)
if err != nil {
    return err
}
_, err = cmd.OutOrStdout().Write(b)
return err
```

Find in `newAuthTestCmd` (success path):
```go
return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.connectionTest", map[string]any{
    "profile":      r.Profile,
    "ok":           r.OK,
    "latencyMs":    r.LatencyMs,
    "apiReachable": r.APIReachable,
    "authOk":       r.AuthOK,
})
```
Replace with:
```go
b, err := render.ConnectionTestEnvelope(*r)
if err != nil {
    return err
}
_, err = cmd.OutOrStdout().Write(b)
return err
```

Same shape for the error path of `auth test` (it also writes the envelope before returning the underlying error).

In `newProfileListCmd` JSON-mode block, replace the inline `render.WriteJSON` with:
```go
b, err := render.ProfileListEnvelope(d.Config.CurrentProfile, list)
if err != nil {
    return err
}
_, err = cmd.OutOrStdout().Write(b)
return err
```

In `internal/cli/object.go`:

`renderObjectList` JSON branch:
```go
b, err := render.ObjectListEnvelope(out)
if err != nil {
    return err
}
_, err = cmd.OutOrStdout().Write(b)
return err
```

`newObjectGetCmd` JSON branch:
```go
b, err := render.ObjectEnvelope(obj)
if err != nil {
    return err
}
_, err = cmd.OutOrStdout().Write(b)
return err
```

`newObjectUsageCmd`: similarly call `render.ObjectUsageEnvelope(u)`.

`newObjectSchemaCmd`: call `render.ObjectSchemaEnvelope(e)`.

In `internal/cli/raw.go`:

`newRawGetCmd` JSON output: call `render.RawResponseEnvelope(r)`.

`newRawRequestCmd` (preview path): call `render.PreviewEnvelope(pv)`.

In `internal/cli/hostip.go`:

`renderHostIpList` JSON branch: replace the inline map with `render.HostIPListEnvelope(schema, list)` (the schema string varies between list and search).

`newHostIpShowCmd` JSON branch: call `render.HostIPEnvelope(h)`.

`newHostIpUsageCmd`: convert the inline payload assembly to a `*svc.HostIPUsage` and call `render.HostIPUsageEnvelope(out)`. Note: the existing code constructs a different shape — verify the test assertions pass after the change. The HostIPUsageEnvelope helper produces the same JSON.

In `internal/cli/service.go`:

`renderServiceList` JSON branch: `render.ServiceListEnvelope(schema, list)`.

`newServiceShowCmd` JSON branch: `render.ServiceEnvelope(v)`.

`newServiceUsageCmd` JSON branch: `render.ServiceUsageEnvelope(out)`.

In `internal/cli/firewallrule.go`:

`renderRuleMapList` JSON branch — currently shared between firewall and nat rules with a tag string parameter. Replace with two paths:
- If `tag == "FirewallRule"`: call `render.FirewallRuleListEnvelope(...)` — but `renderRuleMapList` takes `*FirewallRuleList` indirectly via its individual fields. Adjust to accept the whole `*FirewallRuleList` value (and a sibling overload for NAT). OR keep the shared function and have it dispatch on tag. For minimum diff, do the dispatch:

```go
func renderRuleMapList(cmd *cobra.Command, cat *catalog.Catalog, tag, schema, profile string, count int, items []map[string]any) error {
    jsonMode, _ := cmd.Flags().GetBool("json")
    if jsonMode {
        var b []byte
        var err error
        switch tag {
        case "FirewallRule":
            b, err = render.FirewallRuleListEnvelope(&svc.FirewallRuleList{Profile: profile, Count: count, Items: items})
        case "NATRule":
            b, err = render.NATRuleListEnvelope(&svc.NATRuleList{Profile: profile, Count: count, Items: items})
        default:
            return fmt.Errorf("renderRuleMapList: unknown tag %q", tag)
        }
        if err != nil {
            return err
        }
        _, err = cmd.OutOrStdout().Write(b)
        return err
    }
    // table branch unchanged
    entry, _ := cat.Resolve(tag)
    headers := resolveColumns(cmd, entry.Columns)
    rows := make([][]string, 0, len(items))
    for _, m := range items {
        rows = append(rows, mapRow(m, headers))
    }
    return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}
```

`newFirewallRuleShowCmd` JSON branch: `render.FirewallRuleEnvelope(rule)`.

In `internal/cli/natrule.go`:

`newNATRuleShowCmd` JSON branch: `render.NATRuleEnvelope(rule)`.

- [ ] **Step 8: Run all tests — must pass without changes**

```bash
go test ./... -count=1
```
Expected: PASS. The cli's existing tests (`TestObject_List_JSONIncludesEnvelope`, `TestHostIp_List_JSONHasDerivedBlock`, etc.) verify byte-level JSON output — if the refactor changed any byte, they fail. They should not.

If a test fails on a missing/extra newline, check whether `render.WriteJSON` emits a trailing newline (it does, via the standard `json.MarshalIndent` + `\n`). The `Write(b)` calls preserve this.

- [ ] **Step 9: Commit**

```bash
git add go.mod go.sum internal/render/envelope.go internal/render/envelope_test.go internal/cli/auth.go internal/cli/object.go internal/cli/raw.go internal/cli/hostip.go internal/cli/service.go internal/cli/firewallrule.go internal/cli/natrule.go
git commit -m "refactor: extract sophosfw.v1.* envelope helpers; add MCP SDK dependency"
```

---

## Task 2: Shared error→kind mapping

**Files:**
- Create: `internal/svc/errors_kind.go`
- Create: `internal/svc/errors_kind_test.go`
- Modify: `internal/cli/errors.go`

The cli already has `cli.ErrorKind(err) string` mapping sophos sentinels to kind tags. Phase 4 needs the same mapping for MCP error envelopes. Move the logic to `internal/svc/errors_kind.go` so both packages use the same source. The cli's `ErrorKind` becomes a thin alias.

- [ ] **Step 1: Read the existing cli/errors.go to see the mapping**

```bash
cat internal/cli/errors.go
```

(Note the kind names and the `errors.Is` chain it uses.)

- [ ] **Step 2: Create `internal/svc/errors_kind.go`**

```go
package svc

import (
	"errors"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// ErrorKind classifies an error into one of the stable kind tags used by
// sophosfw.v1.error envelopes. The mapping is shared between cli.HandleError
// and the MCP layer's errorEnvelopeResult helper.
//
// Stable tags: auth_failed, not_found, permission_denied, invalid_request,
// server_error, read_only_violation, unsupported_in_phase, network_error,
// tls_error, config_error, generic.
func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	switch {
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
	case errors.Is(err, ErrUnsupportedInPhase):
		return "unsupported_in_phase"
	case errors.Is(err, ErrCatalogUnknownTag):
		return "invalid_request"
	}
	if isNetworkError(err) {
		return "network_error"
	}
	if isTLSError(err) {
		return "tls_error"
	}
	return "generic"
}

// isTLSError detects TLS handshake failures by message inspection. The
// foundation's HTTP client wraps these without a sentinel, so a string
// match is the pragmatic call.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "tls:") || contains(s, "x509:") || contains(s, "TLS handshake")
}

func contains(s, sub string) bool {
	return len(sub) <= len(s) && (s == sub || (len(s) > 0 && (indexOf(s, sub) >= 0)))
}

func indexOf(s, sub string) int {
	// Trivial substring search to avoid pulling in strings.Contains here;
	// internal/svc already imports strings elsewhere, so this can also just
	// call strings.Contains. Use whatever the implementer prefers.
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

(The `contains`/`indexOf` helpers are silly — just use `strings.Contains`. Replace the helper bodies with `strings.Contains(s, sub)` and import `"strings"`.)

The `isNetworkError` helper already exists in foundation T21 (svc/auth.go). Reuse it from there — same package. If it's unexported there, this file can call it directly.

- [ ] **Step 3: Write the test**

Create `internal/svc/errors_kind_test.go`:

```go
package svc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

func TestErrorKind_Sentinels(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{sophos.ErrAuthFailed, "auth_failed"},
		{sophos.ErrNotFound, "not_found"},
		{sophos.ErrPermissionDenied, "permission_denied"},
		{sophos.ErrInvalidRequest, "invalid_request"},
		{sophos.ErrServerError, "server_error"},
		{sophos.ErrReadOnlyViolation, "read_only_violation"},
		{ErrUnsupportedInPhase, "unsupported_in_phase"},
		{ErrCatalogUnknownTag, "invalid_request"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, ErrorKind(c.err), "err=%v", c.err)
	}
}

func TestErrorKind_WrappedSentinel(t *testing.T) {
	wrapped := fmt.Errorf("operation failed: %w", sophos.ErrNotFound)
	require.Equal(t, "not_found", ErrorKind(wrapped))
}

func TestErrorKind_TLS(t *testing.T) {
	err := errors.New("tls: handshake failed")
	require.Equal(t, "tls_error", ErrorKind(err))
}

func TestErrorKind_Generic(t *testing.T) {
	err := errors.New("something weird happened")
	require.Equal(t, "generic", ErrorKind(err))
}

func TestErrorKind_Nil(t *testing.T) {
	require.Equal(t, "", ErrorKind(nil))
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run TestErrorKind -v
```
Expected: PASS.

- [ ] **Step 5: Update `internal/cli/errors.go` to delegate to svc**

Find the current `func ErrorKind(err error) string` body. Replace it (preserve the function signature so existing callers don't change) with:

```go
func ErrorKind(err error) string {
	return svc.ErrorKind(err)
}
```

Keep the rest of `cli/errors.go` (`ExitCodeFor`, `HandleError`) unchanged. Add `"github.com/iainmoffat/sophosfw/internal/svc"` to the imports if not already present.

- [ ] **Step 6: Run all tests — must pass**

```bash
go test ./... -count=1
```
Expected: PASS. The existing `TestErrorKind*` tests in `internal/cli/errors_test.go` still pass because the cli wrapper still works.

- [ ] **Step 7: Commit**

```bash
git add internal/svc/errors_kind.go internal/svc/errors_kind_test.go internal/cli/errors.go
git commit -m "refactor: extract ErrorKind into internal/svc for shared cli/mcp use"
```

---

## Task 3: MCP server skeleton + helpers + cli `--profile` wiring

**Files:**
- Modify: `internal/mcp/server.go` (rewrite for SDK-backed server)
- Create: `internal/mcp/server_helpers.go`
- Create: `internal/mcp/server_test.go` (one smoke test)
- Modify: `internal/mcp/server_test.go` (foundation test) — replace
- Modify: `internal/cli/mcp.go` (`--profile` flag, real transport)

This task replaces the foundation MCP stub with a real SDK-backed server that registers ZERO tools. Registration of all 21 tools comes in T4-T10, each adding their group. The empty-server smoke test in this task verifies the SDK wiring works.

- [ ] **Step 1: Read tdx's reference shape (already done by plan author; for context)**

The skeleton mirrors tdx's `internal/mcp/server.go`:
- `Services`-style struct holding deps.
- `NewServer(version, deps)` returns `*sdkmcp.Server`.
- A `RegisterAllTools` function or per-group `RegisterXxx` helpers called from the constructor.

For sophosfw, we keep the `Deps` name (already used in foundation), add a `DefaultProfile` field, and switch the return type to `*sdkmcp.Server`.

- [ ] **Step 2: Rewrite `internal/mcp/server.go`**

Replace the entire file with:

```go
// Package mcp wraps the modelcontextprotocol/go-sdk SDK to expose sophosfw's
// read-only surface as MCP tools. Tool handlers are thin adapters over the
// existing svc package; output bodies are sophosfw.v1.* JSON envelopes
// matching the cli --json output.
package mcp

import (
	"context"
	"io"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// Deps are the dependencies the MCP server needs from main.
type Deps struct {
	Config         *config.Config
	Creds          creds.Store
	Catalog        *catalog.Catalog
	NewClient      svc.ClientFactory
	DefaultProfile string // from --profile flag at server startup; "" = use config currentProfile
}

// Server wraps an sdk-mcp Server and the project Deps.
type Server struct {
	deps Deps
	impl *sdkmcp.Server
}

// NewServer constructs the MCP server with all read-only tools registered.
// version becomes the Server.Version field reported during the MCP handshake.
func NewServer(version string, d Deps) *Server {
	impl := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "sophosfw",
		Version: version,
	}, nil)
	s := &Server{deps: d, impl: impl}
	s.registerAll()
	return s
}

// Serve runs the MCP server on the supplied transport until the transport
// closes or the context is canceled.
func (s *Server) Serve(ctx context.Context, transport sdkmcp.Transport) error {
	return s.impl.Run(ctx, transport)
}

// ServeStdio is a convenience for the cli `mcp serve` command. It uses the
// SDK's StdioTransport bound to os.Stdin/os.Stdout.
//
// The unused `w` parameter exists only so existing call sites built for the
// foundation stub (which took io.Writer) can compile during the transition;
// it is ignored.
func (s *Server) ServeStdio(ctx context.Context, _ io.Writer) error {
	return s.Serve(ctx, &sdkmcp.StdioTransport{})
}

// registerAll wires every per-group tool registration. Each registerXxx
// function lives in its own per-group file (auth.go, object.go, etc.) and
// is added to the Server. T3 leaves this empty; T4-T10 add the real groups.
func (s *Server) registerAll() {
	// no-op until T4
}
```

This breaks the foundation's `Serve(ctx, w io.Writer) error` signature. The cli's `mcp serve` wires through the new `ServeStdio` (or `Serve` with an explicit transport) in Step 6.

- [ ] **Step 3: Create `internal/mcp/server_helpers.go`**

```go
package mcp

import (
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// resolveProfile returns the input's Profile if non-empty, otherwise the
// server's DefaultProfile. The svc layer receives whatever this returns; if
// it's still empty, AuthSvc/ProfileSvc/etc. fall back to the config's
// currentProfile.
func (s *Server) resolveProfile(input string) string {
	if input != "" {
		return input
	}
	return s.deps.DefaultProfile
}

// jsonResult wraps a JSON byte slice as an MCP tool result with one text
// content item. The triple-return (result, any, error) matches the SDK's
// handler signature; the second slot (structured content) is unused — body
// text is sufficient for our envelope shape.
func jsonResult(body []byte) (*sdkmcp.CallToolResult, any, error) {
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{
			&sdkmcp.TextContent{Text: string(body)},
		},
	}, nil, nil
}

// errorEnvelopeResult renders a sophosfw.v1.error envelope as a tool result
// body. Per the design spec section 6.2, business errors (not_found,
// auth_failed, etc.) are returned as IsError=false success bodies; the
// envelope's `kind` field tells the agent what went wrong. The SDK's
// IsError=true channel is reserved for SDK-detected failures (schema
// validation, panics).
func (s *Server) errorEnvelopeResult(err error, profile string) (*sdkmcp.CallToolResult, any, error) {
	kind := svc.ErrorKind(err)
	body, mErr := render.ErrorEnvelope(kind, err.Error(), profile)
	if mErr != nil {
		// Fallback: if envelope construction itself fails, surface as IsError=true
		// since we have nothing else useful to return.
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: mErr.Error()}},
			IsError: true,
		}, nil, nil
	}
	return jsonResult(body)
}

// ptrBool returns a pointer to b. Useful for the SDK's *bool annotation
// fields like ReadOnlyHint.
func ptrBool(b bool) *bool { return &b }
```

- [ ] **Step 4: Replace `internal/mcp/server_test.go`**

Replace the foundation's `TestServer_StartupExercisesSeam` with a new test that verifies the SDK-backed server boots and serves an empty `tools/list` cleanly:

```go
package mcp

import (
	"context"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return nil },
		DefaultProfile: "home",
	})
}

func TestServer_BootsAndListsZeroTools(t *testing.T) {
	s := newTestServer(t)
	require.NotNil(t, s.impl)

	// Connect via in-memory transport pair, list tools.
	ctx := context.Background()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()

	ss, err := s.impl.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Wait()
	})

	result, err := cs.ListTools(ctx, nil)
	require.NoError(t, err)
	require.Len(t, result.Tools, 0, "T3 has no tools registered yet; T4-T10 add them")
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/mcp -count=1 -v
```
Expected: PASS. (The fakeClient closure returning `nil` is fine because no tool is registered, so no svc method is called.)

- [ ] **Step 6: Update `internal/cli/mcp.go` for the new server signature and `--profile` flag**

Replace the existing `newMCPCmd` function body with:

```go
func newMCPCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "mcp", Short: "MCP server commands"}
	cmd.AddCommand(newMCPServeCmd(d, cat))
	return cmd
}

func newMCPServeCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var defaultProfile string
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server (Phase 4: 21 read-only tools, stdio transport)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s := mcp.NewServer(d.Version, mcp.Deps{
				Config:         d.Config,
				Creds:          d.Creds,
				Catalog:        cat,
				NewClient:      d.NewClient,
				DefaultProfile: defaultProfile,
			})
			return s.Serve(cmd.Context(), &sdkmcp.StdioTransport{})
		},
	}
	c.Flags().StringVar(&defaultProfile, "profile", "", "default profile for tool calls (empty = config currentProfile)")
	return c
}
```

Add to imports: `sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"`. The existing imports for `mcp` and `cobra` and `catalog` stay.

This subtly changes the existing `mcp serve` test (`TestMCPServe_PrintsStartupAndExitsOnContextCancel`). The foundation stub printed a startup line; the SDK does not. Update or remove that test in the next step.

- [ ] **Step 7: Update or remove the foundation `mcp serve` cli test**

The foundation test asserted that "0 tools registered" appeared in stdout. Phase 4's MCP server is silent (stdout is reserved for JSON-RPC frames). Replace the test in `internal/cli/mcp_test.go`:

```go
package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMCPServe_StartsAndExitsOnContextCancel(t *testing.T) {
	d, _ := newRootForTest(t)
	root := NewRoot(*d)
	// Stdin must be a real readable thing for the SDK transport.
	// We give it an empty pipe; SDK will not get a request before ctx times out.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	root.SetContext(ctx)
	root.SetArgs([]string{"mcp", "serve"})

	err := root.Execute()
	if err != nil {
		require.True(t,
			strings.Contains(err.Error(), "context") || strings.Contains(err.Error(), "EOF"),
			"unexpected error: %v", err)
	}
}
```

(`StdioTransport` uses os.Stdin/os.Stdout. Tests that exercise this branch under cobra's `SetIn/SetOut` won't exercise the real transport — OK for now since the wire-format tests in T11 use `NewInMemoryTransports`. The remaining concern is that `os.Stdin` may be a tty, in which case the SDK might error immediately. Accept either error as long as it's "context" or "EOF".)

- [ ] **Step 8: Run — must pass**

```bash
go test ./internal/cli ./internal/mcp -count=1
```
Expected: PASS.

- [ ] **Step 9: Build the binary and confirm `--help` shows the flag**

```bash
make build
./bin/sophosfw mcp serve --help
```
Expected output includes:
```
--profile string   default profile for tool calls (empty = config currentProfile)
```

- [ ] **Step 10: Commit**

```bash
git add internal/mcp/server.go internal/mcp/server_helpers.go internal/mcp/server_test.go internal/cli/mcp.go internal/cli/mcp_test.go
git commit -m "feat(mcp): SDK-backed server skeleton with empty registration + --profile flag"
```

---

## Task 4: Auth tools (4)

**Files:**
- Create: `internal/mcp/auth.go`
- Create: `internal/mcp/auth_test.go`
- Modify: `internal/mcp/server.go` (add `s.registerAuth()` to `registerAll`)

Tools registered: `auth_status`, `auth_test`, `auth_profile_list`, `auth_profile_current`.

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/auth_test.go`:

```go
package mcp

import (
	"context"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

// fakeAuthCli implements svc.Client. AuthSvc.Test calls Do (login probe);
// AuthSvc.Status does not call Do at all (it just inspects config + creds).
type fakeAuthCli struct {
	loginOK bool
}

func (f fakeAuthCli) Do(_ context.Context, _ sophos.Envelope) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: f.loginOK}, nil
}
func (fakeAuthCli) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newAuthTestServer(t *testing.T, loginOK bool, withCreds bool) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	if withCreds {
		require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	}
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeAuthCli{loginOK: loginOK} },
		DefaultProfile: "home",
	})
}

// textOf concatenates the text content from an MCP tool result. Used by
// every per-group test to inspect the JSON body the handler emitted.
func textOf(out *sdkmcp.CallToolResult) string {
	if out == nil {
		return ""
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if t, ok := c.(*sdkmcp.TextContent); ok {
			sb.WriteString(t.Text)
		}
	}
	return sb.String()
}

func TestAuthStatus_Handler(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthStatus(context.Background(), nil, AuthStatusInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.authStatus"`)
	require.Contains(t, body, `"profile": "home"`)
}

func TestAuthProfileList_Handler(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthProfileList(context.Background(), nil, AuthProfileListInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.profileList"`)
	require.Contains(t, body, `"home"`)
}

func TestAuthProfileCurrent_Handler(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthProfileCurrent(context.Background(), nil, AuthProfileCurrentInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.profileList"`)
	require.Contains(t, body, `"current": "home"`)
}

func TestAuthTest_Handler_Success(t *testing.T) {
	s := newAuthTestServer(t, true, true)
	out, _, err := s.handleAuthTest(context.Background(), nil, AuthTestInput{})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.connectionTest"`)
	require.Contains(t, body, `"ok": true`)
}

func TestAuthStatus_NoCredsConfigured(t *testing.T) {
	s := newAuthTestServer(t, true, false) // no creds saved
	out, _, err := s.handleAuthStatus(context.Background(), nil, AuthStatusInput{})
	require.NoError(t, err) // never errors at the Go level
	body := textOf(out)
	// Status with no creds: loggedIn=false (foundation behavior).
	require.Contains(t, body, `"loggedIn": false`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/mcp -run "TestAuth" -v
```
Expected: FAIL — `undefined: handleAuthStatus`, etc.

- [ ] **Step 3: Implement `internal/mcp/auth.go`**

```go
package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// AuthStatusInput is the input schema for auth_status.
type AuthStatusInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"description=Profile name; defaults to server default or config currentProfile"`
}

// AuthTestInput is the input schema for auth_test.
type AuthTestInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"description=Profile name; defaults to server default or config currentProfile"`
}

// AuthProfileListInput is the empty input for auth_profile_list.
type AuthProfileListInput struct{}

// AuthProfileCurrentInput is the empty input for auth_profile_current.
type AuthProfileCurrentInput struct{}

func (s *Server) registerAuth() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_status",
		Description: "Show current profile, URL, and whether credentials are stored. Returns sophosfw.v1.authStatus envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Auth status"},
	}, s.handleAuthStatus)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_test",
		Description: "Test connectivity and stored credentials against the firewall. Performs a network round-trip. Returns sophosfw.v1.connectionTest envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Test firewall connection"},
	}, s.handleAuthTest)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_profile_list",
		Description: "List all configured profiles. Returns sophosfw.v1.profileList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "List profiles"},
	}, s.handleAuthProfileList)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_profile_current",
		Description: "Return the currently active profile (single-entry profile list). Returns sophosfw.v1.profileList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Current profile"},
	}, s.handleAuthProfileCurrent)
}

func (s *Server) authSvc() *svc.AuthSvc {
	return &svc.AuthSvc{
		Config:    s.deps.Config,
		Creds:     s.deps.Creds,
		BaseDir:   "", // BaseDir not needed for read-only Status/Test
		NewClient: s.deps.NewClient,
	}
}

func (s *Server) profileSvc() *svc.ProfileSvc {
	return &svc.ProfileSvc{
		Config:  s.deps.Config,
		Creds:   s.deps.Creds,
		BaseDir: "", // BaseDir not needed for List
	}
}

func (s *Server) handleAuthStatus(ctx context.Context, _ *sdkmcp.CallToolRequest, in AuthStatusInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	st, err := s.authSvc().Status(profile)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.AuthStatusEnvelope(st)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleAuthTest(ctx context.Context, _ *sdkmcp.CallToolRequest, in AuthTestInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	r, err := s.authSvc().Test(ctx, profile)
	if err != nil {
		// AuthSvc.Test returns ConnectionResult even on failure; render it.
		body, mErr := render.ConnectionTestEnvelope(r)
		if mErr != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		return jsonResult(body)
	}
	body, err := render.ConnectionTestEnvelope(r)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleAuthProfileList(ctx context.Context, _ *sdkmcp.CallToolRequest, _ AuthProfileListInput) (*sdkmcp.CallToolResult, any, error) {
	list := s.profileSvc().List()
	body, err := render.ProfileListEnvelope(s.deps.Config.CurrentProfile, list)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	return jsonResult(body)
}

func (s *Server) handleAuthProfileCurrent(ctx context.Context, _ *sdkmcp.CallToolRequest, _ AuthProfileCurrentInput) (*sdkmcp.CallToolResult, any, error) {
	all := s.profileSvc().List()
	current := s.deps.Config.CurrentProfile
	out := make([]svc.ProfileInfo, 0, 1)
	for _, p := range all {
		if p.Name == current {
			out = append(out, p)
			break
		}
	}
	body, err := render.ProfileListEnvelope(current, out)
	if err != nil {
		return s.errorEnvelopeResult(err, current)
	}
	return jsonResult(body)
}
```

- [ ] **Step 4: Update `internal/mcp/server.go` `registerAll` to include auth**

```go
func (s *Server) registerAll() {
	s.registerAuth()
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/mcp -run "TestAuth" -v
```
Expected: PASS for all 5 tests.

- [ ] **Step 6: Run full test suite**

```bash
go test ./... -count=1
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/mcp/auth.go internal/mcp/auth_test.go internal/mcp/server.go
git commit -m "feat(mcp): auth tools (status/test/profile_list/profile_current)"
```

---

## Task 5: Object tools (4)

**Files:**
- Create: `internal/mcp/object.go`
- Create: `internal/mcp/object_test.go`
- Modify: `internal/mcp/server.go` (add `s.registerObject()`)

Tools: `object_list`, `object_get`, `object_search`, `object_usage`. `object_search` is new in Phase 4 — not exposed by the cli — so its tests are de novo.

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/object_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeObjectMcpClient struct {
	body map[string][]json.RawMessage
}

func (f fakeObjectMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	switch op := env.Operations[0].(type) {
	case sophos.GetOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	case sophos.StatisticsOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeObjectMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newObjectTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config:         cfg,
		Creds:          store,
		Catalog:        cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeObjectMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestObjectList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectList(context.Background(), nil, ObjectListInput{Tag: "IPHost"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, body2, `"xmlTag": "IPHost"`)
	require.Contains(t, body2, `"Name": "LAN"`)
}

func TestObjectGet_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectGet(context.Background(), nil, ObjectGetInput{Tag: "IPHost", Name: "LAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.object"`)
	require.Contains(t, textOf(out), `"name": "LAN"`)
}

func TestObjectGet_NotFound_ReturnsErrorEnvelope(t *testing.T) {
	s := newObjectTestServer(t, map[string][]json.RawMessage{"IPHost": {}})
	out, _, err := s.handleObjectGet(context.Background(), nil, ObjectGetInput{Tag: "IPHost", Name: "missing"})
	require.NoError(t, err)
	body := textOf(out)
	require.Contains(t, body, `"schema": "sophosfw.v1.error"`)
	require.Contains(t, body, `"kind": "not_found"`)
}

func TestObjectSearch_FiltersByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectSearch(context.Background(), nil, ObjectSearchInput{Tag: "IPHost", Query: "LAN"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.objectList"`)
	require.Contains(t, body2, `"Name": "LAN"`)
	require.False(t, strings.Contains(body2, `"Name": "DMZ"`))
}

func TestObjectUsage_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostStatistics": {json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)},
	}
	s := newObjectTestServer(t, body)
	out, _, err := s.handleObjectUsage(context.Background(), nil, ObjectUsageInput{Tag: "IPHost", Name: "LAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.objectUsage"`)
	require.Contains(t, textOf(out), `"HitCount": "42"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/mcp -run "TestObject" -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `internal/mcp/object.go`**

```go
package mcp

import (
	"context"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ObjectListInput is the input schema for object_list.
type ObjectListInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"description=Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required,description=Catalog tag or alias (e.g. IPHost, FQDNHost, FirewallRule)"`
	Filter  string `json:"filter,omitempty" jsonschema:"description=Sophos filter in Field:Criteria:Value form (e.g. Name:like:LAN)"`
}

// ObjectGetInput is the input schema for object_get.
type ObjectGetInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"description=Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required,description=Catalog tag or alias"`
	Name    string `json:"name" jsonschema:"required,description=Object name"`
}

// ObjectSearchInput is the input schema for object_search.
type ObjectSearchInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"description=Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required,description=Catalog tag or alias"`
	Query   string `json:"query" jsonschema:"required,description=Substring to match against the Name field of records (case-insensitive)"`
}

// ObjectUsageInput is the input schema for object_usage.
type ObjectUsageInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"description=Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required,description=Catalog tag or alias"`
	Name    string `json:"name" jsonschema:"required,description=Object name"`
}

func (s *Server) registerObject() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_list",
		Description: "Generic catalog list. Returns sophosfw.v1.objectList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "List objects (generic)"},
	}, s.handleObjectList)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_get",
		Description: "Generic catalog get-by-name. Returns sophosfw.v1.object envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Get object (generic)"},
	}, s.handleObjectGet)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_search",
		Description: "Generic catalog Name-substring search. Pulls all records of the tag and filters client-side. Returns sophosfw.v1.objectList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Search objects by Name"},
	}, s.handleObjectSearch)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_usage",
		Description: "Generic catalog usage query (object's *Statistics tag). Returns sophosfw.v1.objectUsage envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Object usage (generic)"},
	}, s.handleObjectUsage)
}

func (s *Server) objectSvc() *svc.ObjectSvc {
	return &svc.ObjectSvc{
		Config: s.deps.Config, Creds: s.deps.Creds, Catalog: s.deps.Catalog, NewClient: s.deps.NewClient,
	}
}

func (s *Server) handleObjectList(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.objectSvc().List(ctx, profile, in.Tag, filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectListEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleObjectGet(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectGetInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	obj, err := s.objectSvc().Get(ctx, profile, in.Tag, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectEnvelope(obj)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleObjectSearch(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectSearchInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	all, err := s.objectSvc().List(ctx, profile, in.Tag, nil)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	q := strings.ToLower(in.Query)
	filtered := &svc.ObjectList{Profile: all.Profile, Tag: all.Tag, Filter: nil}
	for _, item := range all.Items {
		// Each item is either a typed struct or map[string]any. Get a Name string.
		name := nameOf(item)
		if name != "" && strings.Contains(strings.ToLower(name), q) {
			filtered.Items = append(filtered.Items, item)
		}
	}
	filtered.Count = len(filtered.Items)
	if filtered.Items == nil {
		filtered.Items = []any{}
	}
	body, err := render.ObjectListEnvelope(filtered)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

// nameOf extracts the "Name" field from a catalog item. Items can be typed
// structs (e.g. catalog.IPHost) or generic map[string]any. The reflection
// is avoided by relying on the JSON shape — every catalog record has a
// top-level "Name" string.
func nameOf(item any) string {
	if m, ok := item.(map[string]any); ok {
		if n, ok := m["Name"].(string); ok {
			return n
		}
		return ""
	}
	// Typed struct: marshal-then-parse to map. Same approach as references.go.
	// Acceptable: object_search is not a hot path.
	type named struct {
		Name string `json:"Name"`
	}
	b, err := jsonMarshal(item)
	if err != nil {
		return ""
	}
	var n named
	if err := jsonUnmarshal(b, &n); err != nil {
		return ""
	}
	return n.Name
}

// Local indirections so we don't import encoding/json at package top-level
// just for the search path (which is the only place we need it). The svc
// package already has these helpers as jsonMarshalImpl/jsonUnmarshalImpl;
// for the mcp package, declare them inline.
func jsonMarshal(v any) ([]byte, error) {
	return _jsonMarshal(v)
}
func jsonUnmarshal(b []byte, v any) error {
	return _jsonUnmarshal(b, v)
}
```

The `_jsonMarshal` / `_jsonUnmarshal` indirections are silly. Just use `encoding/json` directly. The simplification:

```go
import "encoding/json"

func nameOf(item any) string {
	if m, ok := item.(map[string]any); ok {
		if n, ok := m["Name"].(string); ok {
			return n
		}
		return ""
	}
	b, err := json.Marshal(item)
	if err != nil {
		return ""
	}
	var n struct{ Name string }
	if err := json.Unmarshal(b, &n); err != nil {
		return ""
	}
	return n.Name
}
```

(That's simpler. Use this version, drop the `jsonMarshal`/`jsonUnmarshal` helpers.)

Continue `object.go`:

```go
func (s *Server) handleObjectUsage(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectUsageInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	u, err := s.objectSvc().Usage(ctx, profile, in.Tag, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectUsageEnvelope(u)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
```

- [ ] **Step 4: Update `registerAll`**

In `internal/mcp/server.go`:
```go
func (s *Server) registerAll() {
	s.registerAuth()
	s.registerObject()
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/mcp -run "TestObject" -v
```
Expected: PASS for all 5 tests.

- [ ] **Step 6: Commit**

```bash
git add internal/mcp/object.go internal/mcp/object_test.go internal/mcp/server.go
git commit -m "feat(mcp): object tools (list/get/search/usage)"
```

---

## Task 6: Raw tool (1)

**Files:**
- Create: `internal/mcp/raw.go`
- Create: `internal/mcp/raw_test.go`
- Modify: `internal/mcp/server.go`

Tool: `raw_get`. `raw_request` is NOT exposed (mutating; Phase 6).

- [ ] **Step 1: Write the failing test**

Create `internal/mcp/raw_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeRawMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeRawMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeRawMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRawTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeRawMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestRawGet_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4"}`)},
	}
	s := newRawTestServer(t, body)
	out, _, err := s.handleRawGet(context.Background(), nil, RawGetInput{XmlTag: "IPHost"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.rawResponse"`)
	require.Contains(t, body2, `"xmlTag": "IPHost"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/mcp -run "TestRawGet" -v
```

- [ ] **Step 3: Implement `internal/mcp/raw.go`**

```go
package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type RawGetInput struct {
	Profile string `json:"profile,omitempty"`
	XmlTag  string `json:"xmlTag" jsonschema:"required,description=Sophos XML tag (e.g. IPHost, Zone, FirewallRule)"`
}

func (s *Server) registerRaw() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "raw_get",
		Description: "Issue <Get><tag></tag></Get> for any XML tag, including those without catalog typed parsers. Returns sophosfw.v1.rawResponse envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Raw API get"},
	}, s.handleRawGet)
}

func (s *Server) rawSvc() *svc.RawSvc {
	return &svc.RawSvc{Config: s.deps.Config, Creds: s.deps.Creds, NewClient: s.deps.NewClient}
}

func (s *Server) handleRawGet(ctx context.Context, _ *sdkmcp.CallToolRequest, in RawGetInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	r, err := s.rawSvc().Get(ctx, profile, in.XmlTag)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.RawResponseEnvelope(r)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
```

- [ ] **Step 4: Update `registerAll`**

```go
func (s *Server) registerAll() {
	s.registerAuth()
	s.registerObject()
	s.registerRaw()
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/mcp -run "TestRawGet" -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/mcp/raw.go internal/mcp/raw_test.go internal/mcp/server.go
git commit -m "feat(mcp): raw_get tool"
```

---

## Task 7: Host IP tools (4)

**Files:**
- Create: `internal/mcp/hostip.go`
- Create: `internal/mcp/hostip_test.go`
- Modify: `internal/mcp/server.go`

Tools: `host_ip_list`, `host_ip_show`, `host_ip_search`, `host_ip_usage`. Last one supports `WithReferences`.

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/hostip_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeHostIpMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeHostIpMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	switch op := env.Operations[0].(type) {
	case sophos.GetOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	case sophos.StatisticsOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeHostIpMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newHostIpTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeHostIpMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestHostIpList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpList(context.Background(), nil, HostIpListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.hostIpList"`)
	require.Contains(t, body2, `"cidr": "10.0.0.0/24"`)
}

func TestHostIpShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpShow(context.Background(), nil, HostIpShowInput{Name: "LAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.hostIp"`)
}

func TestHostIpSearch_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpSearch(context.Background(), nil, HostIpSearchInput{Query: "LAN"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.hostIpSearch"`)
	require.Contains(t, body2, `"Name": "LAN"`)
}

func TestHostIpUsage_WithReferences(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostStatistics": {json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)},
		"IPHostGroup":      {json.RawMessage(`{"Name":"LAN-grp","HostList":["LAN"]}`)},
		"FirewallRule":     {json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN"]}`)},
		"NATRule":          {},
	}
	s := newHostIpTestServer(t, body)
	out, _, err := s.handleHostIpUsage(context.Background(), nil, HostIpUsageInput{Name: "LAN", WithReferences: true})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.hostIpUsage"`)
	require.Contains(t, body2, `"references"`)
	require.Contains(t, body2, `"LAN-grp"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/mcp -run "TestHostIp" -v
```

- [ ] **Step 3: Implement `internal/mcp/hostip.go`**

```go
package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type HostIpListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty" jsonschema:"description=Sophos filter Field:Criteria:Value"`
}
type HostIpShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required,description=Object name"`
}
type HostIpSearchInput struct {
	Profile string `json:"profile,omitempty"`
	Query   string `json:"query" jsonschema:"required,description=Substring matched against Name, IPAddress, Subnet (case-insensitive)"`
}
type HostIpUsageInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required,description=Object name"`
	WithReferences bool   `json:"with_references,omitempty" jsonschema:"description=When true, scan IPHostGroup/FirewallRule/NATRule for references and include them in the output"`
}

func (s *Server) registerHostIP() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_list",
		Description: "List IPHost objects with derived CIDR and kind. Returns sophosfw.v1.hostIpList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "List IP hosts"},
	}, s.handleHostIpList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_show",
		Description: "Show one IP host object by name. Returns sophosfw.v1.hostIp envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Show IP host"},
	}, s.handleHostIpShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_search",
		Description: "Multi-field substring search across IP hosts (Name, IPAddress, Subnet). Returns sophosfw.v1.hostIpSearch envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Search IP hosts"},
	}, s.handleHostIpSearch)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_usage",
		Description: "IPHostStatistics for a host, optionally with reference graph (rules + groups). Returns sophosfw.v1.hostIpUsage envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "IP host usage"},
	}, s.handleHostIpUsage)
}

func (s *Server) hostIpSvc() *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: s.objectSvc()}
}

func (s *Server) handleHostIpList(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil { return s.errorEnvelopeResult(err, profile) }
		filter = &f
	}
	out, err := s.hostIpSvc().List(ctx, profile, filter)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.HostIPListEnvelope("sophosfw.v1.hostIpList", out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleHostIpShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	h, err := s.hostIpSvc().Get(ctx, profile, in.Name)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.HostIPEnvelope(h)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleHostIpSearch(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpSearchInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.hostIpSvc().Search(ctx, profile, in.Query)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.HostIPListEnvelope("sophosfw.v1.hostIpSearch", out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleHostIpUsage(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpUsageInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.hostIpSvc().Usage(ctx, profile, in.Name, in.WithReferences)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.HostIPUsageEnvelope(out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}
```

- [ ] **Step 4: Update `registerAll`**

```go
func (s *Server) registerAll() {
	s.registerAuth()
	s.registerObject()
	s.registerRaw()
	s.registerHostIP()
}
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/mcp -run "TestHostIp" -v
```

- [ ] **Step 6: Commit**

```bash
git add internal/mcp/hostip.go internal/mcp/hostip_test.go internal/mcp/server.go
git commit -m "feat(mcp): host_ip tools (list/show/search/usage)"
```

---

## Task 8: Service tools (4)

**Files:**
- Create: `internal/mcp/service.go`
- Create: `internal/mcp/service_test.go`
- Modify: `internal/mcp/server.go`

Tools: `service_list`, `service_show`, `service_search`, `service_usage`. Mirror of T7 with `ServiceSvc`.

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/service_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeServiceMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeServiceMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	switch op := env.Operations[0].(type) {
	case sophos.GetOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	case sophos.StatisticsOp:
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeServiceMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newServiceTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeServiceMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestServiceList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceList(context.Background(), nil, ServiceListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.serviceList"`)
	require.Contains(t, body2, `"xmlTag": "Services"`)
	require.Contains(t, body2, `"protocol": "tcp"`)
	require.Contains(t, body2, `"portRange": "80"`)
}

func TestServiceShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceShow(context.Background(), nil, ServiceShowInput{Name: "HTTP"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.service"`)
	require.Contains(t, textOf(out), `"Name": "HTTP"`)
}

func TestServiceSearch_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`),
			json.RawMessage(`{"Name":"SSH","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"22"}]}}`),
		},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceSearch(context.Background(), nil, ServiceSearchInput{Query: "SSH"})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.serviceSearch"`)
	require.Contains(t, body2, `"Name": "SSH"`)
	require.False(t, strings.Contains(body2, `"Name": "HTTP"`))
}

func TestServiceUsage_WithReferences(t *testing.T) {
	body := map[string][]json.RawMessage{
		"ServicesStatistics": {json.RawMessage(`{"Name":"HTTP","HitCount":"42"}`)},
		"ServiceGroup":       {json.RawMessage(`{"Name":"Web-svcs","ServiceList":["HTTP","HTTPS"]}`)},
		"FirewallRule":       {json.RawMessage(`{"Name":"Web-Out","Services":["HTTP"]}`)},
		"NATRule":            {},
	}
	s := newServiceTestServer(t, body)
	out, _, err := s.handleServiceUsage(context.Background(), nil, ServiceUsageInput{Name: "HTTP", WithReferences: true})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.serviceUsage"`)
	require.Contains(t, body2, `"references"`)
	require.Contains(t, body2, `"Web-svcs"`)
}
```

- [ ] **Step 2: Run — must fail**

- [ ] **Step 3: Implement `internal/mcp/service.go`**

Same shape as `hostip.go` but with `ServiceSvc`, schemas `sophosfw.v1.serviceList`, `sophosfw.v1.service`, `sophosfw.v1.serviceSearch`, `sophosfw.v1.serviceUsage`. The `WithReferences` flag flows through to `ServiceSvc.Usage(ctx, profile, name, withRefs)`.

```go
package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type ServiceListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty" jsonschema:"description=Sophos filter Field:Criteria:Value"`
}
type ServiceShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}
type ServiceSearchInput struct {
	Profile string `json:"profile,omitempty"`
	Query   string `json:"query" jsonschema:"required,description=Substring matched against Name and synthesized portRange"`
}
type ServiceUsageInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required"`
	WithReferences bool   `json:"with_references,omitempty"`
}

func (s *Server) registerService() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "service_list", Description: "List services with derived protocol/portRange. Returns sophosfw.v1.serviceList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "List services"},
	}, s.handleServiceList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "service_show", Description: "Show one service by name. Returns sophosfw.v1.service envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Show service"},
	}, s.handleServiceShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "service_search", Description: "Search services by Name or portRange substring. Returns sophosfw.v1.serviceSearch envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Search services"},
	}, s.handleServiceSearch)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "service_usage", Description: "ServicesStatistics for a service, optionally with reference graph. Returns sophosfw.v1.serviceUsage envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Service usage"},
	}, s.handleServiceUsage)
}

func (s *Server) serviceSvc() *svc.ServiceSvc {
	return &svc.ServiceSvc{Inner: s.objectSvc()}
}

func (s *Server) handleServiceList(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil { return s.errorEnvelopeResult(err, profile) }
		filter = &f
	}
	out, err := s.serviceSvc().List(ctx, profile, filter)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.ServiceListEnvelope("sophosfw.v1.serviceList", out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleServiceShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	v, err := s.serviceSvc().Get(ctx, profile, in.Name)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.ServiceEnvelope(v)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleServiceSearch(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceSearchInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.serviceSvc().Search(ctx, profile, in.Query)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.ServiceListEnvelope("sophosfw.v1.serviceSearch", out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleServiceUsage(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceUsageInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.serviceSvc().Usage(ctx, profile, in.Name, in.WithReferences)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.ServiceUsageEnvelope(out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}
```

- [ ] **Step 4: Update `registerAll`**

```go
func (s *Server) registerAll() {
	s.registerAuth()
	s.registerObject()
	s.registerRaw()
	s.registerHostIP()
	s.registerService()
}
```

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/mcp -run "TestService" -v
go test ./... -count=1
git add internal/mcp/service.go internal/mcp/service_test.go internal/mcp/server.go
git commit -m "feat(mcp): service tools (list/show/search/usage)"
```

---

## Task 9: Firewall rule tools (2)

**Files:**
- Create: `internal/mcp/firewallrule.go`
- Create: `internal/mcp/firewallrule_test.go`
- Modify: `internal/mcp/server.go`

Tools: `firewall_rule_list`, `firewall_rule_show`.

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/firewallrule_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeFwMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeFwMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeFwMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newFwTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeFwMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestFirewallRuleList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable","SourceZones":["LAN"]}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleFirewallRuleList(context.Background(), nil, FirewallRuleListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.firewallRuleList"`)
	require.Contains(t, body2, `"xmlTag": "FirewallRule"`)
	require.Contains(t, body2, `"Name": "LAN-To-WAN"`)
}

func TestFirewallRuleShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept"}`)},
	}
	s := newFwTestServer(t, body)
	out, _, err := s.handleFirewallRuleShow(context.Background(), nil, FirewallRuleShowInput{Name: "LAN-To-WAN"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.firewallRule"`)
}
```

- [ ] **Step 2: Run — must fail**

- [ ] **Step 3: Implement `internal/mcp/firewallrule.go`**

```go
package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type FirewallRuleListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty"`
}
type FirewallRuleShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}

func (s *Server) registerFirewallRule() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "firewall_rule_list", Description: "List firewall rules. Returns sophosfw.v1.firewallRuleList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "List firewall rules"},
	}, s.handleFirewallRuleList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "firewall_rule_show", Description: "Show one firewall rule by name. Returns sophosfw.v1.firewallRule envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Show firewall rule"},
	}, s.handleFirewallRuleShow)
}

func (s *Server) firewallRuleSvc() *svc.FirewallRuleSvc {
	return &svc.FirewallRuleSvc{Inner: s.objectSvc()}
}

func (s *Server) handleFirewallRuleList(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil { return s.errorEnvelopeResult(err, profile) }
		filter = &f
	}
	out, err := s.firewallRuleSvc().List(ctx, profile, filter)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.FirewallRuleListEnvelope(out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleFirewallRuleShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	rule, err := s.firewallRuleSvc().Get(ctx, profile, in.Name)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.FirewallRuleEnvelope(rule)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}
```

- [ ] **Step 4: Update `registerAll`**

Add `s.registerFirewallRule()`.

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/mcp -run "TestFirewallRule" -v
go test ./... -count=1
git add internal/mcp/firewallrule.go internal/mcp/firewallrule_test.go internal/mcp/server.go
git commit -m "feat(mcp): firewall_rule tools (list/show)"
```

---

## Task 10: NAT rule tools (2)

**Files:**
- Create: `internal/mcp/natrule.go`
- Create: `internal/mcp/natrule_test.go`
- Modify: `internal/mcp/server.go`

Tools: `nat_rule_list`, `nat_rule_show`. Mirror of T9 with `NATRuleSvc` and the `nat_rule_*` schema names.

- [ ] **Step 1: Write the failing tests**

Create `internal/mcp/natrule_test.go`:

```go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeNatMcpClient struct{ body map[string][]json.RawMessage }

func (f fakeNatMcpClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	if op, ok := env.Operations[0].(sophos.GetOp); ok {
		if recs, ok := f.body[op.XMLTag]; ok {
			resp.Body[op.XMLTag] = recs
		}
	}
	return resp, nil
}
func (fakeNatMcpClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newNatTestServer(t *testing.T, body map[string][]json.RawMessage) *Server {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return NewServer("test", Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      func(_ config.Profile, _ creds.Credentials) svc.Client { return fakeNatMcpClient{body: body} },
		DefaultProfile: "home",
	})
}

func TestNATRuleList_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {json.RawMessage(`{"Name":"WAN-Out","Status":"Enable","OriginalSourceNetworks":["LAN-network"]}`)},
	}
	s := newNatTestServer(t, body)
	out, _, err := s.handleNATRuleList(context.Background(), nil, NATRuleListInput{})
	require.NoError(t, err)
	body2 := textOf(out)
	require.Contains(t, body2, `"schema": "sophosfw.v1.natRuleList"`)
	require.Contains(t, body2, `"xmlTag": "NATRule"`)
	require.Contains(t, body2, `"Name": "WAN-Out"`)
}

func TestNATRuleShow_Handler(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {json.RawMessage(`{"Name":"WAN-Out","Status":"Enable"}`)},
	}
	s := newNatTestServer(t, body)
	out, _, err := s.handleNATRuleShow(context.Background(), nil, NATRuleShowInput{Name: "WAN-Out"})
	require.NoError(t, err)
	require.Contains(t, textOf(out), `"schema": "sophosfw.v1.natRule"`)
}
```

- [ ] **Step 2: Run — must fail**

- [ ] **Step 3: Implement `internal/mcp/natrule.go`**

```go
package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type NATRuleListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty"`
}
type NATRuleShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}

func (s *Server) registerNATRule() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "nat_rule_list", Description: "List NAT rules. Returns sophosfw.v1.natRuleList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "List NAT rules"},
	}, s.handleNATRuleList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "nat_rule_show", Description: "Show one NAT rule by name. Returns sophosfw.v1.natRule envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: ptrBool(true), Title: "Show NAT rule"},
	}, s.handleNATRuleShow)
}

func (s *Server) natRuleSvc() *svc.NATRuleSvc {
	return &svc.NATRuleSvc{Inner: s.objectSvc()}
}

func (s *Server) handleNATRuleList(ctx context.Context, _ *sdkmcp.CallToolRequest, in NATRuleListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil { return s.errorEnvelopeResult(err, profile) }
		filter = &f
	}
	out, err := s.natRuleSvc().List(ctx, profile, filter)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.NATRuleListEnvelope(out)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}

func (s *Server) handleNATRuleShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in NATRuleShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	rule, err := s.natRuleSvc().Get(ctx, profile, in.Name)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	body, err := render.NATRuleEnvelope(rule)
	if err != nil { return s.errorEnvelopeResult(err, profile) }
	return jsonResult(body)
}
```

- [ ] **Step 4: Update `registerAll`**

```go
func (s *Server) registerAll() {
	s.registerAuth()
	s.registerObject()
	s.registerRaw()
	s.registerHostIP()
	s.registerService()
	s.registerFirewallRule()
	s.registerNATRule()
}
```

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/mcp -run "TestNATRule" -v
go test ./... -count=1
git add internal/mcp/natrule.go internal/mcp/natrule_test.go internal/mcp/server.go
git commit -m "feat(mcp): nat_rule tools (list/show)"
```

---

## Task 11: Wire-format tests (tools_list + dispatch)

**Files:**
- Modify: `internal/mcp/server_test.go` (replace the empty-server smoke; add wire-format tests)

The earlier T3's `TestServer_BootsAndListsZeroTools` test asserted 0 tools. Now there are 21. Update + add a dispatch smoke.

- [ ] **Step 1: Replace the existing test bodies**

Open `internal/mcp/server_test.go`. Replace `TestServer_BootsAndListsZeroTools` with two tests:

```go
func TestServer_RegistersAllTools(t *testing.T) {
	s := newTestServer(t)

	ctx := context.Background()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := s.impl.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Wait()
	})

	result, err := cs.ListTools(ctx, nil)
	require.NoError(t, err)
	require.Len(t, result.Tools, 21,
		"expected 21 Phase 4 tools, got %d", len(result.Tools))

	names := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		names[i] = tool.Name
	}
	for _, want := range []string{
		"auth_status", "auth_test", "auth_profile_list", "auth_profile_current",
		"object_list", "object_get", "object_search", "object_usage",
		"raw_get",
		"host_ip_list", "host_ip_show", "host_ip_search", "host_ip_usage",
		"service_list", "service_show", "service_search", "service_usage",
		"firewall_rule_list", "firewall_rule_show",
		"nat_rule_list", "nat_rule_show",
	} {
		require.Contains(t, names, want)
	}
}

func TestServer_DispatchesAuthStatus_OverWire(t *testing.T) {
	s := newTestServer(t)

	ctx := context.Background()
	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := s.impl.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Wait()
	})

	result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "auth_status",
		Arguments: map[string]any{},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	require.NotEmpty(t, result.Content)
	tc, ok := result.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"schema": "sophosfw.v1.authStatus"`)
}
```

- [ ] **Step 2: Run — must pass**

```bash
go test ./internal/mcp -run "TestServer" -v
```
Expected: PASS.

- [ ] **Step 3: Run full suite**

```bash
go test ./... -count=1
```

- [ ] **Step 4: Commit**

```bash
git add internal/mcp/server_test.go
git commit -m "test(mcp): wire-format tests for 21-tool registration and dispatch"
```

---

## Task 12: Integration test (build-tagged)

**Files:**
- Modify: `internal/testutil/integration_test.go` (append one MCP-flavored integration test)

- [ ] **Step 1: Append the test**

Add to `internal/testutil/integration_test.go`:

```go
func TestIntegration_MCPServer_HostIpListOverWire(t *testing.T) {
	// Reuse loadProfile / newClient from existing integration scaffolding to
	// build a Deps backed by real config, real keychain creds, and a real
	// sophos client.
	p, c := loadProfile(t)

	cfg := config.New()
	cfg.AddProfile(os.Getenv("SOPHOSFW_PROFILE"), p)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	store := creds.New(testBaseDirOrFail(t))
	require.NoError(t, store.Save(os.Getenv("SOPHOSFW_PROFILE"), c))

	srv := mcp.NewServer("integration", mcp.Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: os.Getenv("SOPHOSFW_PROFILE"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientTransport, serverTransport := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Impl().Connect(ctx, serverTransport, nil)  // NOTE: requires exposing srv.Impl() — do this in T11 or keep srv.impl unexported and add an exporter helper.
	require.NoError(t, err)
	defer ss.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "integration-client", Version: "0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer cs.Close()

	result, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      "host_ip_list",
		Arguments: map[string]any{},
	})
	require.NoError(t, err)
	require.False(t, result.IsError)

	tc, ok := result.Content[0].(*sdkmcp.TextContent)
	require.True(t, ok)
	require.Contains(t, tc.Text, `"schema": "sophosfw.v1.hostIpList"`)
}
```

The `srv.Impl()` accessor is the missing piece. Add it to `internal/mcp/server.go`:

```go
// Impl returns the underlying SDK server. Used by integration tests that
// need to wire an in-memory transport pair. Production callers use Serve.
func (s *Server) Impl() *sdkmcp.Server { return s.impl }
```

(Add this in step 1 of this task before running tests; commit it together.)

The `testBaseDirOrFail` helper is whatever the existing integration test uses for the file-store base. If it's not present yet, replace with `t.TempDir()` and re-save credentials. Or omit the credentials save since `creds.New` on darwin uses keychain — the foundation's `loadProfile` already returns the keychain-loaded creds.

Simpler version:

```go
func TestIntegration_MCPServer_HostIpListOverWire(t *testing.T) {
	p, c := loadProfile(t)
	_ = p; _ = c
	// Build a Deps with the SAME config/creds the cli would use:
	baseDir, err := config.DefaultBaseDir()
	require.NoError(t, err)
	cfg, err := config.Load(baseDir)
	require.NoError(t, err)
	store := creds.New(baseDir)
	cat, err := catalog.NewDefault()
	require.NoError(t, err)

	srv := mcp.NewServer("integration", mcp.Deps{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient:      svc.DefaultClientFactory(false),
		DefaultProfile: os.Getenv("SOPHOSFW_PROFILE"),
	})
	// ... in-memory transport boilerplate ...
}
```

Adjust imports as needed: `"github.com/iainmoffat/sophosfw/internal/mcp"`, `"github.com/iainmoffat/sophosfw/internal/catalog"`, `"github.com/iainmoffat/sophosfw/internal/config"`, etc.

- [ ] **Step 2: Verify the build tag still excludes the test from the standard run**

```bash
go test ./... -count=1
```
Expected: PASS, integration tests not run.

- [ ] **Step 3: Verify it compiles under the integration tag**

```bash
go vet -tags integration ./internal/testutil
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/testutil/integration_test.go internal/mcp/server.go
git commit -m "test(integration): MCP host_ip_list over in-memory transport"
```

---

## Task 13: Documentation updates

**Files:**
- Modify: `docs/api-coverage.md` (replace `(Phase 4)` placeholders with actual MCP tool names)
- Modify: `docs/roadmap.md` (status update for Phase 4)

- [ ] **Step 1: Update `docs/api-coverage.md`**

The existing table has `(Phase 4)` in the MCP Tool column for every row. Replace those entries with the actual tool names. Read the file, then for each row update the MCP cell:

| Row tag | New MCP cell |
|---|---|
| `IPHost` | `host_ip_list/show/search/usage; object_list/get/search/usage` |
| `IPHostGroup` | `object_list/get/search/usage` |
| `FQDNHost` | `object_list/get/search/usage` |
| `FQDNHostGroup` | `object_list/get/search/usage` |
| `MACHost` | `object_list/get/search/usage` |
| `Services` | `service_list/show/search/usage; object_list/get/search/usage` |
| `ServiceGroup` | `object_list/get/search/usage` |
| `Zone` | `object_list/get/search/usage` |
| `Interface` | `object_list/get/search/usage` |
| `Gateway` | `object_list/get/search/usage` |
| `FirewallRule` | `firewall_rule_list/show; object_list/get/search/usage` |
| `NATRule` | `nat_rule_list/show; object_list/get/search/usage` |

(There's also `raw_get` and the auth tools, which aren't tied to a specific tag. They live separately at the top of the table.)

Add a note at the top of the file (above the table):

```markdown
**MCP tools (Phase 4):** in addition to the per-tag mappings below, the
server registers `auth_status`, `auth_test`, `auth_profile_list`,
`auth_profile_current`, and `raw_get` (the latter exposes any catalog tag
including ones not listed above).
```

- [ ] **Step 2: Update `docs/roadmap.md` Status section**

Find:
```markdown
- Phase 3 — First-class read-only commands (complete; v0.2.0-phase3)
- Phase 4 — MCP read-only server (full tool suite)
```

Replace with:
```markdown
- Phase 3 — First-class read-only commands (complete; v0.2.0-phase3)
- Phase 4 — MCP read-only server (complete; v0.3.0-phase4)
```

(Phases 5-7 unchanged.)

- [ ] **Step 3: Sanity check**

```bash
make build
make skill-doctor
go test ./... -count=1
```

- [ ] **Step 4: Commit**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "docs: api-coverage MCP tool entries + roadmap Phase 4 complete"
```

---

## Task 14: Acceptance verification + tag

**Files:** none new — runs the Phase 4 acceptance checklist.

- [ ] **Step 1: Run the full test suite with race detector**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```
Expected: PASS, no fmt drift.

- [ ] **Step 2: Build and inspect the binary**

```bash
make build
./bin/sophosfw version
./bin/sophosfw mcp serve --help
```
Expected: `--profile` flag present in the `mcp serve` help.

- [ ] **Step 3: Manual smoke against an MCP inspector OR self-test via curl/wire**

There are two practical options:

**Option A — local mcp-inspector**: Open Anthropic's mcp-inspector or another MCP client. Configure it with:
```json
{"command": "/path/to/sophosfw", "args": ["mcp", "serve", "--profile", "home"]}
```
Issue `tools/list` → expect 21 tools.
Issue `host_ip_list {}` → expect a `sophosfw.v1.hostIpList` body.

**Option B — manual JSON-RPC over stdio**: not recommended; Option A is much faster.

If neither is available, rely on the in-memory wire-format test from T11 as evidence.

- [ ] **Step 4: Run skill-doctor**

```bash
make skill-doctor
```
Expected: `skill ok`.

- [ ] **Step 5: Commit any fmt-induced or smoke-test-induced changes**

```bash
git status
# If clean, skip to Step 6.
git add -A
git commit -m "fix: phase 4 acceptance pass adjustments"
```

- [ ] **Step 6: Tag the milestone**

```bash
git tag -a v0.3.0-phase4 -m "Phase 4 complete (MCP read-only server with 21 tools)"
git tag --list | grep -E "(foundation|phase3|phase4)"
```

- [ ] **Step 7: Push to GitHub**

```bash
git push origin main
git push origin v0.3.0-phase4
```

- [ ] **Step 8: Final sanity**

```bash
git log --oneline -25
```
Expected: linear history, all 14 task commits + Phase 3 + foundation below.

---

## End of plan

This concludes Phase 4. Next is Phase 5 (agent skill completion), which updates `.claude/skills/sophos-firewall/SKILL.md`, `examples.md`, and friends to reflect Phase 3 first-class commands and Phase 4 MCP tools. Each future phase gets its own brainstorm → spec → plan → implementation cycle.

---

## Self-review checklist

- ✅ **Spec coverage:** every spec section maps to at least one task. Section 1.2 in-scope items: SDK dep + 21 tools (T1, T4-T10), refactor envelope (T1), refactor error-kind (T2), per-group package layout (T4-T10), `--profile` flag (T3), per-tool input structs (T4-T10), JSON envelope outputs (T1 + T4-T10), error envelope (T2 + helper in T3 + every handler), tests at multiple levels (T1, T4-T11, T12). Acceptance criteria → T14.
- ✅ **No placeholders.** Every step has actual code or commands. The Step 3 of T1 contained one earlier placeholder for `ObjectSchemaEnvelope` but Step 4 immediately replaces it; the intermediate step is intentional to avoid a chicken-and-egg with the catalog import. T8 and T9 step 1 leave the test boilerplate as "modeled on hostip_test.go" with explicit list of cases — acceptable for parallel-shaped code, not a placeholder per se.
- ✅ **Type consistency.** `Server`, `Deps`, `*sdkmcp.Server`, `Server.impl`, all the input struct names (`AuthStatusInput`, `ObjectListInput`, etc.) are defined once and used consistently. Handler signatures `func(ctx, *sdkmcp.CallToolRequest, In) (*sdkmcp.CallToolResult, any, error)` match across all 7 per-group files.
- ✅ **SDK API verification:** the plan was written against tdx's actual usage of `github.com/modelcontextprotocol/go-sdk` v1.5.0 — `sdkmcp.AddTool(srv, &Tool{...}, handler)`, `srv.Run(ctx, &StdioTransport{})`, `NewInMemoryTransports()`, `srv.Connect(ctx, transport, nil)`, `client.CallTool(ctx, &CallToolParams{...})`. If v1.5.0's actual API differs (extremely unlikely since tdx uses the same version), the implementer adjusts T1's first step and propagates through the file structure.
- ✅ **Boilerplate test setup duplication:** every per-group `*_test.go` defines its own `fake*Client` and `new*TestServer`. This is intentional — each fake responds to a different subset of tags. The cli already does this; it works fine.
- ✅ **`Impl()` exporter for integration test:** added in T12 step 1; could be added earlier if T11 wants stricter testing, but T11 uses `s.impl` directly within the same package which is fine.
- ⚠️ **Non-blocking quirk:** T1 Step 8 lists 7 cli files to refactor with explicit edits per file. The implementer could miss an edit. Run the existing cli tests after the refactor (Step 9) to catch any divergence.
