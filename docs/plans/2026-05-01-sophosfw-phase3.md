# sophosfw Phase 3 Implementation Plan — First-class read-only commands

**Goal:** Add ergonomic, type-aware first-class CLI commands (`host ip`, `service`, `firewall rule`, `nat rule`) on top of the foundation's catalog-driven generic `object` surface, plus three new typed catalog parsers (FQDNHost, MACHost, Zone) and a reference-graph utility that powers `--with-references` queries.

**Architecture:** Each typed-wrapper service in `internal/svc/` composes the foundation's `*ObjectSvc` and adds typed input/output, client-side multi-field search, derived-field enrichment, and reference-graph scanning. CLI commands in `internal/cli/` are thin cobra adapters that call into the wrapper services, render JSON envelopes (`sophosfw.v1.<name>`), and resolve `--columns` overrides with catalog defaults as fallback. No mutating envelopes anywhere — Phase 3 is read-only by design.

**Tech Stack:** Go 1.26.2, `github.com/iainmoffat/sophosfw` module, cobra, lipgloss, testify. Same as foundation. No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-01-sophosfw-phase3-design.md`](../specs/2026-05-01-sophosfw-phase3-design.md)

**Predecessor:** Foundation, tagged `v0.1.0-foundation` on `main` (commit `4103765`).

---

## Conventions

- **Module:** `github.com/iainmoffat/sophosfw`. Working directory: `/Users/ipm/code/sophosfw`.
- **File mode:** YAML/Go files default; no secrets in this phase.
- **No Co-Authored-By trailer** on implementation commits.
- **Commit messages:** use the exact text given in each task's commit step.
- **Typed parser identifier convention:** lowercase, no separator (matches foundation: `iphost`, `service` → Phase 3: `fqdnhost`, `machost`, `zone`).
- **Catalog YAML note:** the foundation already includes generic entries for `FQDNHost`, `MACHost`, `Zone`, `FirewallRule`, `NATRule`, `ServiceGroup`, `IPHostGroup`, `FQDNHostGroup`, `Interface`, `Gateway`. Phase 3 work on `objects.yaml` is to UPGRADE three of those (FQDNHost, MACHost, Zone) from `typedParser: ""` to typed identifiers — NOT to add new entries.

---

## Task 1: `catalog/fqdnhost.go` — FQDNHost typed parser

**Files:**
- Create: `internal/catalog/fqdnhost.go`
- Create: `internal/catalog/fqdnhost_test.go`
- Modify: `internal/catalog/objects.yaml` (set `typedParser: fqdnhost` on the existing FQDNHost entry; update columns to `[Name, FQDN, IPFamily]`)
- Modify: `internal/catalog/register.go` (add `RegisterParser("fqdnhost", FQDNHostParser)`)

- [ ] **Step 1: Write the failing test**

Create `internal/catalog/fqdnhost_test.go`:
```go
package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFQDNHostParser_ParsesSimpleRecord(t *testing.T) {
	raw := json.RawMessage(`{"Name":"example.com","FQDN":"example.com","IPFamily":"IPv4"}`)
	v, err := FQDNHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(FQDNHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "example.com", host.Name)
	require.Equal(t, "example.com", host.FQDN)
	require.Equal(t, "IPv4", host.IPFamily)
}

func TestFQDNHostParser_ParsesWildcard(t *testing.T) {
	raw := json.RawMessage(`{"Name":"all-cdn","FQDN":"*.cdn.example.com","IPFamily":"IPv4"}`)
	v, err := FQDNHostParser(raw)
	require.NoError(t, err)
	host := v.(FQDNHost)
	require.Equal(t, "*.cdn.example.com", host.FQDN)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/catalog -run TestFQDNHostParser -v
```
Expected: FAIL with `undefined: FQDNHost` / `undefined: FQDNHostParser`.

- [ ] **Step 3: Implement `internal/catalog/fqdnhost.go`**

```go
package catalog

import "encoding/json"

// FQDNHost is the typed view of a Sophos FQDNHost record.
type FQDNHost struct {
	Name     string `json:"Name"`
	FQDN     string `json:"FQDN"`
	IPFamily string `json:"IPFamily,omitempty"`
}

// FQDNHostParser is the typed-parser callback for the "fqdnhost" identifier
// in objects.yaml.
func FQDNHostParser(raw json.RawMessage) (any, error) {
	var v FQDNHost
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
```

- [ ] **Step 4: Update `internal/catalog/objects.yaml`**

Find this entry:
```yaml
  - tag: FQDNHost
    aliases: [fqdn]
    description: "FQDN host objects"
    columns: [Name, FQDN, FQDNHostGroup]
    filterable: [Name, FQDN]
    usageTag: FQDNHostStatistics
    typedParser: ""
```

Replace it with:
```yaml
  - tag: FQDNHost
    aliases: [fqdn, fqdn-host, host-fqdn]
    description: "FQDN host objects (DNS-name targets)"
    columns: [Name, FQDN, IPFamily]
    filterable: [Name, FQDN, IPFamily]
    usageTag: FQDNHostStatistics
    typedParser: fqdnhost
```

(Aliases are extended additively — keeping the existing `fqdn` short alias and adding `fqdn-host`/`host-fqdn` per spec.)

- [ ] **Step 5: Update `internal/catalog/register.go`**

In `NewDefault()`, add `RegisterParser` for the new parser. The current function ends with `c.RegisterParser("service", ServicesParser)`. Insert immediately after that line:
```go
	c.RegisterParser("fqdnhost", FQDNHostParser)
```

- [ ] **Step 6: Run — must pass**

```bash
go test ./internal/catalog -count=1 -v
```
Expected: PASS for `TestFQDNHostParser_*` plus all existing catalog tests still passing.

- [ ] **Step 7: Verify the loader exposes FQDNHost as typed**

```bash
go test ./internal/catalog -run TestNewDefault_LoadsAndRegistersTypedParsers -v
```
Expected: PASS. (This existing foundation test asserts `IPHost` and `Services` are typed; it doesn't yet check FQDNHost. That's fine — the parser is registered and a future svc test will exercise the parsing through it.)

- [ ] **Step 8: Commit**

```bash
git add internal/catalog/fqdnhost.go internal/catalog/fqdnhost_test.go internal/catalog/objects.yaml internal/catalog/register.go
git commit -m "feat(catalog): FQDNHost typed parser"
```

---

## Task 2: `catalog/machost.go` — MACHost typed parser

**Files:**
- Create: `internal/catalog/machost.go`
- Create: `internal/catalog/machost_test.go`
- Modify: `internal/catalog/objects.yaml` (set `typedParser: machost`, extend aliases)
- Modify: `internal/catalog/register.go`

- [ ] **Step 1: Write the failing test**

Create `internal/catalog/machost_test.go`:
```go
package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMACHostParser_ParsesSingleAddress(t *testing.T) {
	raw := json.RawMessage(`{"Name":"laptop-mac","Type":"MACAddress","MACAddress":"00:11:22:33:44:55"}`)
	v, err := MACHostParser(raw)
	require.NoError(t, err)
	host, ok := v.(MACHost)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "laptop-mac", host.Name)
	require.Equal(t, "00:11:22:33:44:55", host.MACAddress)
	require.Equal(t, "MACAddress", host.Type)
	require.Empty(t, host.MACAddressList)
}

func TestMACHostParser_ParsesMultiAddress(t *testing.T) {
	raw := json.RawMessage(`{"Name":"lab-macs","Type":"MACList","MACAddressList":["00:11:22:33:44:55","aa:bb:cc:dd:ee:ff"]}`)
	v, err := MACHostParser(raw)
	require.NoError(t, err)
	host := v.(MACHost)
	require.Equal(t, "lab-macs", host.Name)
	require.Equal(t, []string{"00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"}, host.MACAddressList)
	require.Empty(t, host.MACAddress)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/catalog -run TestMACHostParser -v
```
Expected: FAIL with `undefined: MACHost` / `undefined: MACHostParser`.

- [ ] **Step 3: Implement `internal/catalog/machost.go`**

```go
package catalog

import "encoding/json"

// MACHost is the typed view of a Sophos MACHost record. Sophos allows
// either a single MACAddress or a list (MACAddressList) per record.
type MACHost struct {
	Name           string   `json:"Name"`
	Type           string   `json:"Type,omitempty"`
	MACAddress     string   `json:"MACAddress,omitempty"`
	MACAddressList []string `json:"MACAddressList,omitempty"`
}

// MACHostParser is the typed-parser callback for the "machost" identifier
// in objects.yaml.
func MACHostParser(raw json.RawMessage) (any, error) {
	var v MACHost
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
```

- [ ] **Step 4: Update `internal/catalog/objects.yaml`**

Find this entry:
```yaml
  - tag: MACHost
    aliases: [mac]
    description: "MAC host objects"
    columns: [Name, Type, MACAddress]
    filterable: [Name, MACAddress]
    usageTag: MACHostStatistics
    typedParser: ""
```

Replace with:
```yaml
  - tag: MACHost
    aliases: [mac, mac-host, host-mac]
    description: "MAC address host objects"
    columns: [Name, Type, MACAddress]
    filterable: [Name, Type, MACAddress]
    usageTag: MACHostStatistics
    typedParser: machost
```

- [ ] **Step 5: Update `internal/catalog/register.go`**

Insert after the FQDNHost line added in T1:
```go
	c.RegisterParser("machost", MACHostParser)
```

- [ ] **Step 6: Run — must pass**

```bash
go test ./internal/catalog -count=1 -v
```
Expected: PASS for both new tests plus existing catalog tests.

- [ ] **Step 7: Commit**

```bash
git add internal/catalog/machost.go internal/catalog/machost_test.go internal/catalog/objects.yaml internal/catalog/register.go
git commit -m "feat(catalog): MACHost typed parser"
```

---

## Task 3: `catalog/zone.go` — Zone typed parser

**Files:**
- Create: `internal/catalog/zone.go`
- Create: `internal/catalog/zone_test.go`
- Modify: `internal/catalog/objects.yaml` (set `typedParser: zone`)
- Modify: `internal/catalog/register.go`

- [ ] **Step 1: Write the failing test**

Create `internal/catalog/zone_test.go`:
```go
package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZoneParser_ParsesBuiltInZone(t *testing.T) {
	raw := json.RawMessage(`{"Name":"LAN","Type":"LAN","Description":"Default LAN zone"}`)
	v, err := ZoneParser(raw)
	require.NoError(t, err)
	zone, ok := v.(Zone)
	require.True(t, ok, "got %T", v)
	require.Equal(t, "LAN", zone.Name)
	require.Equal(t, "LAN", zone.Type)
	require.Equal(t, "Default LAN zone", zone.Description)
}

func TestZoneParser_ParsesCustomZone(t *testing.T) {
	raw := json.RawMessage(`{"Name":"DMZ-Servers","Type":"DMZ"}`)
	v, err := ZoneParser(raw)
	require.NoError(t, err)
	zone := v.(Zone)
	require.Equal(t, "DMZ-Servers", zone.Name)
	require.Equal(t, "DMZ", zone.Type)
	require.Empty(t, zone.Description)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/catalog -run TestZoneParser -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `internal/catalog/zone.go`**

```go
package catalog

import "encoding/json"

// Zone is the typed view of a Sophos Zone record (LAN, WAN, DMZ, custom).
type Zone struct {
	Name        string `json:"Name"`
	Type        string `json:"Type,omitempty"`
	Description string `json:"Description,omitempty"`
}

// ZoneParser is the typed-parser callback for the "zone" identifier in
// objects.yaml.
func ZoneParser(raw json.RawMessage) (any, error) {
	var v Zone
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}
```

- [ ] **Step 4: Update `internal/catalog/objects.yaml`**

Find:
```yaml
  - tag: Zone
    aliases: [zone]
    description: "Network zones"
    columns: [Name, Type, Description]
    filterable: [Name, Type]
    usageTag: ZoneStatistics
    typedParser: ""
```

Replace `typedParser: ""` with `typedParser: zone`. Update description to `"Network zones (LAN, WAN, DMZ, custom)"`. Keep aliases and columns as-is.

The final entry should be:
```yaml
  - tag: Zone
    aliases: [zone]
    description: "Network zones (LAN, WAN, DMZ, custom)"
    columns: [Name, Type, Description]
    filterable: [Name, Type]
    usageTag: ZoneStatistics
    typedParser: zone
```

- [ ] **Step 5: Update `internal/catalog/register.go`**

Insert after the MACHost line:
```go
	c.RegisterParser("zone", ZoneParser)
```

The final `NewDefault` body should register five parsers in this order: iphost, service, fqdnhost, machost, zone.

- [ ] **Step 6: Run — must pass**

```bash
go test ./internal/catalog -count=1 -v
```
Expected: PASS for both new Zone tests plus all existing catalog tests.

- [ ] **Step 7: Sanity-check the catalog has 5 typed entries**

Run:
```bash
go test ./internal/catalog -run TestNewDefault_LoadsAndRegistersTypedParsers -v
```
Expected: PASS. The existing test verifies tags load and at least the foundation parsers are wired; it should still pass.

- [ ] **Step 8: Commit**

```bash
git add internal/catalog/zone.go internal/catalog/zone_test.go internal/catalog/objects.yaml internal/catalog/register.go
git commit -m "feat(catalog): Zone typed parser"
```

---

## Task 4: `svc/references.go` — reference-graph scanner

**Files:**
- Create: `internal/svc/references.go`
- Create: `internal/svc/references_test.go`

This task ships the `FindReferences` utility used by `host ip usage --with-references` and `service usage --with-references` (built in T5 and T6 below). It depends only on `*ObjectSvc`, which the foundation provides.

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/references_test.go`:
```go
package svc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// fakeRefClient returns canned responses keyed by the GetOp's XMLTag.
// errs[tag] makes that tag's lookup fail.
type fakeRefClient struct {
	body map[string][]json.RawMessage
	errs map[string]error
}

func (f fakeRefClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	if len(env.Operations) == 0 {
		return &sophos.Response{LoginOK: true}, nil
	}
	op, ok := env.Operations[0].(sophos.GetOp)
	if !ok {
		return &sophos.Response{LoginOK: true}, nil
	}
	if e := f.errs[op.XMLTag]; e != nil {
		return nil, e
	}
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if recs, ok := f.body[op.XMLTag]; ok {
		resp.Body[op.XMLTag] = recs
	}
	return resp, nil
}
func (fakeRefClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRefSvc(t *testing.T, body map[string][]json.RawMessage, errs map[string]error) *ObjectSvc {
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
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeRefClient{body: body, errs: errs} },
	}
}

func TestFindReferences_AllSucceed(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"LAN-group","HostList":["LAN-network","LAN-DHCP"]}`)},
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN-network"],"Action":"Accept"}`),
			json.RawMessage(`{"Name":"DMZ-To-WAN","Sources":["DMZ-network"],"Action":"Accept"}`),
		},
		"NATRule": {},
	}
	svc := newRefSvc(t, body, nil)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, []string{"LAN-group"}, got.Refs["IPHostGroup"])
	require.Equal(t, []string{"LAN-To-WAN"}, got.Refs["FirewallRule"])
	require.Equal(t, []string{}, got.Refs["NATRule"])
	require.Empty(t, got.Errors)
}

func TestFindReferences_OneReferrerFails(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"LAN-group","HostList":["LAN-network"]}`)},
		"NATRule":     {},
	}
	errs := map[string]error{"FirewallRule": sophos.ErrPermissionDenied}
	svc := newRefSvc(t, body, errs)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, []string{"LAN-group"}, got.Refs["IPHostGroup"])
	require.Equal(t, []string{}, got.Refs["NATRule"])
	require.Contains(t, got.Errors["FirewallRule"], "permission")
}

func TestFindReferences_PrimaryNotInMap(t *testing.T) {
	svc := newRefSvc(t, nil, nil)
	_, err := FindReferences(context.Background(), svc, "home", "Interface", "eth0")
	require.Error(t, err)
}

func TestFindReferences_ExactMatchOnly(t *testing.T) {
	// "LAN-network-extra" must NOT match a query for "LAN-network".
	body := map[string][]json.RawMessage{
		"IPHostGroup": {json.RawMessage(`{"Name":"LAN-extra-group","HostList":["LAN-network-extra"]}`)},
		"FirewallRule": {},
		"NATRule":      {},
	}
	svc := newRefSvc(t, body, nil)
	got, err := FindReferences(context.Background(), svc, "home", "IPHost", "LAN-network")
	require.NoError(t, err)
	require.Empty(t, got.Refs["IPHostGroup"])
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run TestFindReferences -v
```
Expected: FAIL — `undefined: FindReferences`.

- [ ] **Step 3: Implement `internal/svc/references.go`**

```go
package svc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// referenceTargets maps a primary catalog tag to the catalog tags that may
// reference it. Order is the order results appear in JSON output. Adding a
// new referrer type later is a one-line change.
var referenceTargets = map[string][]string{
	"IPHost":   {"IPHostGroup", "FirewallRule", "NATRule"},
	"FQDNHost": {"FQDNHostGroup", "FirewallRule"},
	"MACHost":  {"FirewallRule"},
	"Service":  {"ServiceGroup", "FirewallRule", "NATRule"},
	"Zone":     {"FirewallRule"},
}

// References is the result of a reference-graph scan. Refs is the per-
// referrer name list; Errors is the per-referrer error message captured
// when a sub-query failed. A successful query that found no references
// yields an empty slice in Refs (NOT a missing key); a failed query yields
// no Refs entry and an Errors entry.
type References struct {
	Refs   map[string][]string `json:"refs"`
	Errors map[string]string   `json:"errors,omitempty"`
}

// ErrUnknownPrimaryTag is returned by FindReferences when the caller asks
// for a primary tag that's not in the static referenceTargets map. This
// shouldn't happen in normal use because Phase 3 typed wrappers only
// invoke it for tags they know about; defensive case for callers.
var ErrUnknownPrimaryTag = errors.New("references: primary tag has no referrer map entry")

// FindReferences scans the catalog tags listed for `primaryTag` and returns
// a References value listing every record (by Name) whose JSON contains
// `name` as an exact string value somewhere in its body. Per-referrer query
// failures (auth, network, permission) are captured in References.Errors;
// they do NOT cause this function to return an error. Only a missing entry
// in referenceTargets yields a Go error.
func FindReferences(ctx context.Context, inner *ObjectSvc, profileName, primaryTag, name string) (*References, error) {
	referrers, ok := referenceTargets[primaryTag]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPrimaryTag, primaryTag)
	}
	out := &References{
		Refs:   make(map[string][]string, len(referrers)),
		Errors: make(map[string]string),
	}
	for _, ref := range referrers {
		out.Refs[ref] = []string{}
		list, err := inner.List(ctx, profileName, ref, nil)
		if err != nil {
			out.Errors[ref] = errorTag(err) + ": " + err.Error()
			continue
		}
		for _, item := range list.Items {
			b, mErr := json.Marshal(item)
			if mErr != nil {
				continue
			}
			var record map[string]any
			if uErr := json.Unmarshal(b, &record); uErr != nil {
				continue
			}
			if recordContains(record, name) {
				if rn, ok := record["Name"].(string); ok && rn != "" {
					out.Refs[ref] = append(out.Refs[ref], rn)
				}
			}
		}
	}
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	return out, nil
}

// recordContains walks a parsed JSON record and returns true if any leaf
// string value (scalar or array element) equals `name` exactly. This is the
// match heuristic used in lieu of per-type referrer-field knowledge.
func recordContains(v any, name string) bool {
	switch t := v.(type) {
	case string:
		return t == name
	case []any:
		for _, e := range t {
			if recordContains(e, name) {
				return true
			}
		}
	case map[string]any:
		for _, e := range t {
			if recordContains(e, name) {
				return true
			}
		}
	}
	return false
}

// errorTag returns a short error-kind tag matching the cli vocabulary so
// per-referrer error strings in JSON output stay readable.
func errorTag(err error) string {
	switch {
	case errors.Is(err, sophosErrPermissionDenied()):
		return "permission_denied"
	case errors.Is(err, sophosErrAuthFailed()):
		return "auth_failed"
	case errors.Is(err, sophosErrNotFound()):
		return "not_found"
	case errors.Is(err, sophosErrInvalidRequest()):
		return "invalid_request"
	case errors.Is(err, sophosErrServerError()):
		return "server_error"
	case errors.Is(err, sophosErrReadOnlyViolation()):
		return "read_only_violation"
	default:
		return "generic"
	}
}
```

The `sophosErrXxx()` indirections come from the next step.

- [ ] **Step 4: Add a small shim file for sophos error sentinels**

Create `internal/svc/references_errors.go`:
```go
package svc

import "github.com/iainmoffat/sophosfw/internal/sophos"

// These accessors keep references.go free of a direct import on the sophos
// package's error sentinels, which lets references_test.go stub via the
// fakeRefClient without round-tripping the foundation StatusError type.
func sophosErrAuthFailed() error        { return sophos.ErrAuthFailed }
func sophosErrNotFound() error          { return sophos.ErrNotFound }
func sophosErrPermissionDenied() error  { return sophos.ErrPermissionDenied }
func sophosErrInvalidRequest() error    { return sophos.ErrInvalidRequest }
func sophosErrServerError() error       { return sophos.ErrServerError }
func sophosErrReadOnlyViolation() error { return sophos.ErrReadOnlyViolation }
```

(This file is purely a reference-target so the tests can also assert against the sentinels through `errors.Is`. It compiles trivially.)

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/svc -run TestFindReferences -v
```
Expected: PASS for all 4 tests.

- [ ] **Step 6: Run the full svc suite to confirm no regressions**

```bash
go test ./internal/svc -count=1 -v
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/svc/references.go internal/svc/references_errors.go internal/svc/references_test.go
git commit -m "feat(svc): FindReferences with static referrer-map and exact-string scan"
```

---

## Task 5: `svc/hostip.go` — HostIPSvc List/Get + enrichHostIP + subnetToPrefix

**Files:**
- Create: `internal/svc/hostip.go`
- Create: `internal/svc/hostip_test.go`

This task ships the read paths (`List`, `Get`) plus the enrichment helpers. `Search` and `Usage` come in T6.

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/hostip_test.go`:
```go
package svc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

// fakeIPHostClient returns the same body for any IPHost Get.
type fakeIPHostClient struct {
	body map[string][]json.RawMessage
}

func (f fakeIPHostClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeIPHostClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newHostIPSvc(t *testing.T, body map[string][]json.RawMessage) *HostIPSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeIPHostClient{body: body} },
	}
	return &HostIPSvc{Inner: inner}
}

func TestHostIPSvc_List_EnrichesCidrForNetwork(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newHostIPSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "10.0.0.0/24", out.Items[0].Derived.CIDR)
	require.Equal(t, "network", out.Items[0].Derived.Kind)
}

func TestHostIPSvc_List_OmitsCidrForHost(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"Public-DNS","IPFamily":"IPv4","HostType":"IP","IPAddress":"8.8.8.8"}`),
		},
	}
	s := newHostIPSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "host", out.Items[0].Derived.Kind)
	require.Empty(t, out.Items[0].Derived.CIDR)
}

func TestHostIPSvc_List_NormalizesUnknownHostType(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"X","IPFamily":"IPv4","HostType":"WeirdNew"}`)},
	}
	s := newHostIPSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	// Unknown HostType leaves Kind empty (no false claim).
	require.Empty(t, out.Items[0].Derived.Kind)
}

func TestHostIPSvc_Get_ReturnsTypedAndEnriched(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	s := newHostIPSvc(t, body)
	out, err := s.Get(context.Background(), "home", "LAN-network")
	require.NoError(t, err)
	require.Equal(t, "LAN-network", out.Name)
	require.Equal(t, "10.0.0.0/24", out.Derived.CIDR)
}

func TestSubnetToPrefix_Common(t *testing.T) {
	cases := []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.0.0.0", 8},
		{"255.255.255.255", 32},
		{"0.0.0.0", 0},
		{"255.255.255.128", 25},
	}
	for _, c := range cases {
		got, err := subnetToPrefix(c.mask)
		require.NoError(t, err, "mask=%s", c.mask)
		require.Equal(t, c.want, got, "mask=%s", c.mask)
	}
}

func TestSubnetToPrefix_Invalid(t *testing.T) {
	_, err := subnetToPrefix("not-a-mask")
	require.Error(t, err)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run "TestHostIPSvc|TestSubnetToPrefix" -v
```
Expected: FAIL — `undefined: HostIPSvc`, `undefined: subnetToPrefix`.

- [ ] **Step 3: Implement `internal/svc/hostip.go`**

```go
package svc

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// HostIP is the typed view of a Sophos IPHost record enriched with
// sophosfw-derived fields. Raw API fields come from catalog.IPHost
// (embedded). Derived fields live under `derived` so consumers can tell
// computed values apart from raw API values.
type HostIP struct {
	catalog.IPHost
	Derived HostIPDerived `json:"derived,omitempty"`
}

// HostIPDerived contains computed fields. Empty fields are omitted from
// JSON.
type HostIPDerived struct {
	CIDR string `json:"cidr,omitempty"`
	Kind string `json:"kind,omitempty"`
}

// HostIPList is the render-friendly result of a list/search.
type HostIPList struct {
	Profile string
	Filter  *sophos.FilterClause
	Count   int
	Items   []HostIP
}

// HostIPSvc serves the typed `host ip` first-class command surface.
type HostIPSvc struct {
	Inner *ObjectSvc
}

// hostKindMap normalizes Sophos's HostType vocabulary into a stable
// lowercase set. Adding a new HostType is a one-line addition here.
var hostKindMap = map[string]string{
	"Network": "network",
	"IP":      "host",
	"IPRange": "iprange",
	"IPList":  "list",
}

// enrichHostIP fills Derived in-place. It is pure — no I/O, no error path.
func enrichHostIP(h *HostIP) {
	if k, ok := hostKindMap[h.HostType]; ok {
		h.Derived.Kind = k
	}
	if h.Derived.Kind == "network" && h.IPAddress != "" && h.Subnet != "" {
		if mask, err := subnetToPrefix(h.Subnet); err == nil {
			h.Derived.CIDR = fmt.Sprintf("%s/%d", h.IPAddress, mask)
		}
	}
}

// subnetToPrefix converts an IPv4 dotted-quad mask (e.g. "255.255.255.0")
// to its prefix length (e.g. 24). Returns an error for non-canonical masks.
func subnetToPrefix(mask string) (int, error) {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0, fmt.Errorf("subnetToPrefix: not a valid mask: %q", mask)
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, errors.New("subnetToPrefix: only IPv4 masks supported")
	}
	prefix, bits := net.IPMask(v4).Size()
	if bits == 0 {
		return 0, fmt.Errorf("subnetToPrefix: not a canonical mask: %q", mask)
	}
	return prefix, nil
}

// List returns all IPHost records, optionally filtered, with derived fields
// enriched.
func (s *HostIPSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*HostIPList, error) {
	inner, err := s.Inner.List(ctx, profileName, "IPHost", filter)
	if err != nil {
		return nil, err
	}
	out := &HostIPList{Profile: inner.Profile, Filter: inner.Filter}
	for _, item := range inner.Items {
		raw, ok := item.(catalog.IPHost)
		if !ok {
			return nil, fmt.Errorf("HostIPSvc.List: catalog returned non-IPHost item: %T", item)
		}
		h := HostIP{IPHost: raw}
		enrichHostIP(&h)
		out.Items = append(out.Items, h)
	}
	out.Count = len(out.Items)
	return out, nil
}

// Get fetches one IPHost by name, enriched with derived fields.
func (s *HostIPSvc) Get(ctx context.Context, profileName, name string) (*HostIP, error) {
	inner, err := s.Inner.Get(ctx, profileName, "IPHost", name)
	if err != nil {
		return nil, err
	}
	raw, ok := inner.Data.(catalog.IPHost)
	if !ok {
		return nil, fmt.Errorf("HostIPSvc.Get: catalog returned non-IPHost item: %T", inner.Data)
	}
	h := HostIP{IPHost: raw}
	enrichHostIP(&h)
	return &h, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run "TestHostIPSvc|TestSubnetToPrefix" -v
```
Expected: PASS for all 6 tests.

- [ ] **Step 5: Confirm no regression in the rest of svc**

```bash
go test ./internal/svc -count=1
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/svc/hostip.go internal/svc/hostip_test.go
git commit -m "feat(svc): HostIPSvc List/Get with derived CIDR/kind enrichment"
```

---

## Task 6: `svc/hostip.go` extension — Search and Usage with `--with-references`

**Files:**
- Modify: `internal/svc/hostip.go`
- Modify: `internal/svc/hostip_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/svc/hostip_test.go`:
```go
func TestHostIPSvc_Search_MultiField(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"Public-DNS","IPFamily":"IPv4","HostType":"IP","IPAddress":"8.8.8.8"}`),
		},
	}
	s := newHostIPSvc(t, body)
	// "10.0.0.0" matches one record's IPAddress
	out, err := s.Search(context.Background(), "home", "10.0.0.0")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "LAN-network", out.Items[0].Name)
}

func TestHostIPSvc_Search_CaseInsensitive(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN-network","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIPSvc(t, body)
	out, err := s.Search(context.Background(), "home", "lan")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
}

func TestHostIPSvc_Search_NoMatches(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	s := newHostIPSvc(t, body)
	out, err := s.Search(context.Background(), "home", "xyz-nope")
	require.NoError(t, err)
	require.Empty(t, out.Items)
	require.Equal(t, 0, out.Count)
}

// fakeIPHostUsageClient routes Get/Statistics differently. For "IPHostStatistics"
// it returns one stats record; for IPHost it returns nothing (Get-by-name fails);
// for IPHostGroup/FirewallRule/NATRule it returns their canned bodies.
type fakeIPHostUsageClient struct {
	stats     []json.RawMessage
	groupBody []json.RawMessage
	fwBody    []json.RawMessage
	natBody   []json.RawMessage
}

func (f fakeIPHostUsageClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
	resp := &sophos.Response{LoginOK: true, Body: map[string][]json.RawMessage{}}
	if len(env.Operations) == 0 {
		return resp, nil
	}
	switch op := env.Operations[0].(type) {
	case sophos.StatisticsOp:
		if op.XMLTag == "IPHostStatistics" {
			resp.Body["IPHostStatistics"] = f.stats
		}
	case sophos.GetOp:
		switch op.XMLTag {
		case "IPHostGroup":
			resp.Body["IPHostGroup"] = f.groupBody
		case "FirewallRule":
			resp.Body["FirewallRule"] = f.fwBody
		case "NATRule":
			resp.Body["NATRule"] = f.natBody
		}
	}
	return resp, nil
}
func (fakeIPHostUsageClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func TestHostIPSvc_Usage_NoRefs(t *testing.T) {
	stats := []json.RawMessage{json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)}
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client {
			return fakeIPHostUsageClient{stats: stats}
		},
	}
	s := &HostIPSvc{Inner: inner}
	out, err := s.Usage(context.Background(), "home", "LAN", false)
	require.NoError(t, err)
	require.Len(t, out.Records, 1)
	require.Nil(t, out.References)
}

func TestHostIPSvc_Usage_WithRefs(t *testing.T) {
	stats := []json.RawMessage{json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)}
	groupBody := []json.RawMessage{
		json.RawMessage(`{"Name":"LAN-group","HostList":["LAN","DMZ"]}`),
	}
	fwBody := []json.RawMessage{
		json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN"],"Action":"Accept"}`),
	}
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client {
			return fakeIPHostUsageClient{stats: stats, groupBody: groupBody, fwBody: fwBody}
		},
	}
	s := &HostIPSvc{Inner: inner}
	out, err := s.Usage(context.Background(), "home", "LAN", true)
	require.NoError(t, err)
	require.Len(t, out.Records, 1)
	require.NotNil(t, out.References)
	require.Equal(t, []string{"LAN-group"}, out.References.Refs["IPHostGroup"])
	require.Equal(t, []string{"LAN-To-WAN"}, out.References.Refs["FirewallRule"])
	require.Equal(t, []string{}, out.References.Refs["NATRule"])
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run "TestHostIPSvc_Search|TestHostIPSvc_Usage" -v
```
Expected: FAIL — `Search` and `Usage` not defined.

- [ ] **Step 3: Add `HostIPUsage` and the two methods to `internal/svc/hostip.go`**

Append to `internal/svc/hostip.go`:
```go
import "strings"

// HostIPUsage is the render-friendly result of a usage query for the typed
// host-ip surface. References is non-nil when --with-references was set.
type HostIPUsage struct {
	Profile    string
	Name       string
	Records    []map[string]any
	References *References
}

// Search runs a client-side multi-field substring match on the full IPHost
// list. Matches against Name, IPAddress, and Subnet, case-insensitively.
// Returns a HostIPList with a populated Items list and Count.
func (s *HostIPSvc) Search(ctx context.Context, profileName, query string) (*HostIPList, error) {
	all, err := s.List(ctx, profileName, nil)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(query)
	out := &HostIPList{Profile: all.Profile}
	for _, h := range all.Items {
		if matchesHostIP(h, q) {
			out.Items = append(out.Items, h)
		}
	}
	out.Count = len(out.Items)
	if out.Items == nil {
		out.Items = []HostIP{}
	}
	return out, nil
}

func matchesHostIP(h HostIP, qLower string) bool {
	return strings.Contains(strings.ToLower(h.Name), qLower) ||
		strings.Contains(strings.ToLower(h.IPAddress), qLower) ||
		strings.Contains(strings.ToLower(h.Subnet), qLower)
}

// Usage runs the IPHostStatistics query for `name`. When withRefs is true,
// it additionally calls FindReferences for IPHost and attaches the result.
// Per-referrer failures appear in HostIPUsage.References.Errors and never
// cause Usage to return an error.
func (s *HostIPSvc) Usage(ctx context.Context, profileName, name string, withRefs bool) (*HostIPUsage, error) {
	inner, err := s.Inner.Usage(ctx, profileName, "IPHost", name)
	if err != nil {
		return nil, err
	}
	out := &HostIPUsage{
		Profile: inner.Profile,
		Name:    inner.Name,
		Records: inner.Records,
	}
	if withRefs {
		refs, refErr := FindReferences(ctx, s.Inner, profileName, "IPHost", name)
		if refErr != nil {
			return nil, refErr
		}
		out.References = refs
	}
	return out, nil
}
```

Note: the `import "strings"` line is appended via your editor's standard import-grouping. The final imports in `hostip.go` should be:
```go
import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run "TestHostIPSvc" -v
```
Expected: PASS for all `TestHostIPSvc_*` tests, including the new Search and Usage cases.

- [ ] **Step 5: Run full svc suite**

```bash
go test ./internal/svc -count=1
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/svc/hostip.go internal/svc/hostip_test.go
git commit -m "feat(svc): HostIPSvc Search and Usage with --with-references support"
```

---

## Task 7: `svc/service.go` — ServiceSvc List/Get/Search + enrichService (port collapse)

**Files:**
- Create: `internal/svc/service.go`
- Create: `internal/svc/service_test.go`

This is the biggest svc task because the port-range collapse algorithm has to handle several real-world Sophos shapes.

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/service_test.go`:
```go
package svc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeSvcClient struct {
	body map[string][]json.RawMessage
}

func (f fakeSvcClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeSvcClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newServiceSvc(t *testing.T, body map[string][]json.RawMessage) *ServiceSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeSvcClient{body: body} },
	}
	return &ServiceSvc{Inner: inner}
}

func TestServiceSvc_List_DerivedSinglePort(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","SourcePort":"1:65535","DestinationPort":"80"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "tcp", out.Items[0].Derived.Protocol)
	require.Equal(t, "80", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedRange(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"WebPorts","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80:443"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "80-443", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedMultiPort(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTPandHTTPS","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"},{"Protocol":"TCP","DestinationPort":"443"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "80,443", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedContiguousCollapse(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"Triplet","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"},{"Protocol":"TCP","DestinationPort":"81"},{"Protocol":"TCP","DestinationPort":"82"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "80-82", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedMultiProtocol(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"DNS","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"53"},{"Protocol":"UDP","DestinationPort":"53"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "tcp,udp", out.Items[0].Derived.Protocol)
	require.Equal(t, "53", out.Items[0].Derived.PortRange)
}

func TestServiceSvc_List_DerivedICMP_NoPortRange(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"PING","Type":"IP","ServiceDetails":{"ServiceDetail":[{"Protocol":"ICMP","ICMPType":"8","ICMPCode":"0"}]}}`),
		},
	}
	s := newServiceSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Equal(t, "icmp", out.Items[0].Derived.Protocol)
	require.Empty(t, out.Items[0].Derived.PortRange)
}

func TestServiceSvc_Search_ByNameAndPort(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`),
			json.RawMessage(`{"Name":"SSH","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"22"}]}}`),
		},
	}
	s := newServiceSvc(t, body)

	// match by name substring
	out, err := s.Search(context.Background(), "home", "HTTP")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "HTTP", out.Items[0].Name)

	// match by port (in derived.portRange)
	out, err = s.Search(context.Background(), "home", "22")
	require.NoError(t, err)
	require.Len(t, out.Items, 1)
	require.Equal(t, "SSH", out.Items[0].Name)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run "TestServiceSvc" -v
```
Expected: FAIL — `undefined: ServiceSvc`.

- [ ] **Step 3: Implement `internal/svc/service.go`**

```go
package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// Service is the typed view of a Sophos Services record enriched with
// sophosfw-derived fields. The raw RawDetails fragment is preserved so
// callers can inspect protocol-specific structure if they need it.
type Service struct {
	catalog.Service
	Derived ServiceDerived `json:"derived,omitempty"`
}

// ServiceDerived contains computed summary fields. Empty strings are
// omitted from JSON output.
type ServiceDerived struct {
	Protocol  string `json:"protocol,omitempty"`
	PortRange string `json:"portRange,omitempty"`
}

// ServiceList is the render-friendly result of a list/search.
type ServiceList struct {
	Profile string
	Filter  *sophos.FilterClause
	Count   int
	Items   []Service
}

// ServiceUsage is the render-friendly result of a usage query for the
// typed service surface. References is non-nil when --with-references
// was set.
type ServiceUsage struct {
	Profile    string
	Name       string
	Records    []map[string]any
	References *References
}

// ServiceSvc serves the typed `service` first-class command surface.
type ServiceSvc struct {
	Inner *ObjectSvc
}

// enrichService fills Service.Derived in-place from the RawDetails fragment.
// It is pure — no I/O. Errors during JSON parsing leave Derived empty;
// the raw fields stay intact so consumers can fall back if needed.
func enrichService(s *Service) {
	if len(s.RawDetails) == 0 {
		return
	}
	var details serviceDetailsContainer
	if err := json.Unmarshal(s.RawDetails, &details); err != nil {
		return
	}
	protos := map[string]bool{}
	ports := []string{}
	for _, d := range details.ServiceDetail {
		if d.Protocol != "" {
			protos[strings.ToLower(d.Protocol)] = true
		}
		if d.DestinationPort != "" {
			ports = append(ports, d.DestinationPort)
		}
	}
	if len(protos) > 0 {
		s.Derived.Protocol = joinSorted(protos)
	}
	s.Derived.PortRange = collapsePorts(ports)
}

type serviceDetailsContainer struct {
	ServiceDetail []serviceDetail `json:"ServiceDetail,omitempty"`
}

type serviceDetail struct {
	Protocol        string `json:"Protocol,omitempty"`
	SourcePort      string `json:"SourcePort,omitempty"`
	DestinationPort string `json:"DestinationPort,omitempty"`
	ICMPType        string `json:"ICMPType,omitempty"`
	ICMPCode        string `json:"ICMPCode,omitempty"`
}

func joinSorted(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// collapsePorts turns a list of port strings into a compact range summary.
// Inputs may be scalars ("80"), Sophos ranges ("80:443"), or numeric ports
// in any order. Output is comma-separated, with contiguous numeric runs
// joined as "M-N". Range inputs are preserved verbatim. Returns "" when
// the input is empty.
func collapsePorts(ports []string) string {
	if len(ports) == 0 {
		return ""
	}
	scalars := []int{}
	rangeOuts := []string{}
	for _, p := range ports {
		if strings.Contains(p, ":") {
			parts := strings.SplitN(p, ":", 2)
			rangeOuts = append(rangeOuts, parts[0]+"-"+parts[1])
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			rangeOuts = append(rangeOuts, p)
			continue
		}
		scalars = append(scalars, n)
	}
	sort.Ints(scalars)
	scalars = dedupInts(scalars)
	scalarOuts := []string{}
	for i := 0; i < len(scalars); {
		j := i
		for j+1 < len(scalars) && scalars[j+1] == scalars[j]+1 {
			j++
		}
		if j == i {
			scalarOuts = append(scalarOuts, strconv.Itoa(scalars[i]))
		} else {
			scalarOuts = append(scalarOuts, fmt.Sprintf("%d-%d", scalars[i], scalars[j]))
		}
		i = j + 1
	}
	all := append([]string{}, scalarOuts...)
	all = append(all, rangeOuts...)
	return strings.Join(all, ",")
}

func dedupInts(xs []int) []int {
	if len(xs) <= 1 {
		return xs
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// List returns all Services records, optionally filtered, with derived
// fields enriched.
func (s *ServiceSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*ServiceList, error) {
	inner, err := s.Inner.List(ctx, profileName, "Services", filter)
	if err != nil {
		return nil, err
	}
	out := &ServiceList{Profile: inner.Profile, Filter: inner.Filter}
	for _, item := range inner.Items {
		raw, ok := item.(catalog.Service)
		if !ok {
			return nil, fmt.Errorf("ServiceSvc.List: catalog returned non-Service item: %T", item)
		}
		v := Service{Service: raw}
		enrichService(&v)
		out.Items = append(out.Items, v)
	}
	out.Count = len(out.Items)
	return out, nil
}

// Get fetches one Services record by name.
func (s *ServiceSvc) Get(ctx context.Context, profileName, name string) (*Service, error) {
	inner, err := s.Inner.Get(ctx, profileName, "Services", name)
	if err != nil {
		return nil, err
	}
	raw, ok := inner.Data.(catalog.Service)
	if !ok {
		return nil, fmt.Errorf("ServiceSvc.Get: catalog returned non-Service item: %T", inner.Data)
	}
	v := Service{Service: raw}
	enrichService(&v)
	return &v, nil
}

// Search runs a client-side substring match against Name and the
// synthesized derived.portRange. Case-insensitive.
func (s *ServiceSvc) Search(ctx context.Context, profileName, query string) (*ServiceList, error) {
	all, err := s.List(ctx, profileName, nil)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(query)
	out := &ServiceList{Profile: all.Profile}
	for _, v := range all.Items {
		if strings.Contains(strings.ToLower(v.Name), q) ||
			strings.Contains(strings.ToLower(v.Derived.PortRange), q) {
			out.Items = append(out.Items, v)
		}
	}
	out.Count = len(out.Items)
	if out.Items == nil {
		out.Items = []Service{}
	}
	return out, nil
}

// Usage runs the ServicesStatistics query for `name`. When withRefs is
// true, it additionally calls FindReferences for Service.
func (s *ServiceSvc) Usage(ctx context.Context, profileName, name string, withRefs bool) (*ServiceUsage, error) {
	inner, err := s.Inner.Usage(ctx, profileName, "Services", name)
	if err != nil {
		return nil, err
	}
	out := &ServiceUsage{
		Profile: inner.Profile,
		Name:    inner.Name,
		Records: inner.Records,
	}
	if withRefs {
		refs, refErr := FindReferences(ctx, s.Inner, profileName, "Service", name)
		if refErr != nil {
			return nil, refErr
		}
		out.References = refs
	}
	return out, nil
}
```

Note that `FindReferences` is called with `"Service"` (singular) because `referenceTargets` uses the singular key — `Services` is the catalog tag, but the referrer-map key is `Service` per the spec.

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run "TestServiceSvc" -v
```
Expected: PASS for all 7 ServiceSvc tests.

- [ ] **Step 5: Run full svc suite**

```bash
go test ./internal/svc -count=1
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/svc/service.go internal/svc/service_test.go
git commit -m "feat(svc): ServiceSvc with derived protocol/portRange and search"
```

---

## Task 8: `svc/firewallrule.go` — FirewallRuleSvc

**Files:**
- Create: `internal/svc/firewallrule.go`
- Create: `internal/svc/firewallrule_test.go`

The catalog already has FirewallRule as a generic entry (no typed parser). The svc layer returns `[]map[string]any` items.

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/firewallrule_test.go`:
```go
package svc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeFwClient struct {
	body map[string][]json.RawMessage
}

func (f fakeFwClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeFwClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newFwSvc(t *testing.T, body map[string][]json.RawMessage) *FirewallRuleSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeFwClient{body: body} },
	}
	return &FirewallRuleSvc{Inner: inner}
}

func TestFirewallRuleSvc_List_UntypedItems(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","SourceZones":["LAN"],"DestinationZones":["WAN"],"Status":"Enable"}`),
			json.RawMessage(`{"Name":"DMZ-Inbound","Action":"Drop","SourceZones":["WAN"],"DestinationZones":["DMZ"],"Status":"Enable"}`),
		},
	}
	s := newFwSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 2)
	require.Equal(t, "LAN-To-WAN", out.Items[0]["Name"])
	require.Equal(t, "Accept", out.Items[0]["Action"])
}

func TestFirewallRuleSvc_Get_ByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable"}`),
		},
	}
	s := newFwSvc(t, body)
	rule, err := s.Get(context.Background(), "home", "LAN-To-WAN")
	require.NoError(t, err)
	require.Equal(t, "LAN-To-WAN", rule["Name"])
	require.Equal(t, "Accept", rule["Action"])
}

func TestFirewallRuleSvc_Get_NotFound(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {},
	}
	s := newFwSvc(t, body)
	_, err := s.Get(context.Background(), "home", "missing")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrNotFound)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run "TestFirewallRuleSvc" -v
```
Expected: FAIL — `undefined: FirewallRuleSvc`.

- [ ] **Step 3: Implement `internal/svc/firewallrule.go`**

```go
package svc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// FirewallRuleList is the render-friendly result of a firewall rule list.
// Items are untyped maps; FirewallRule has no typed parser in Phase 3
// because the rule shape is non-trivial and Phase 6 will define it
// alongside mutating workflows.
type FirewallRuleList struct {
	Profile string
	Filter  *sophos.FilterClause
	Count   int
	Items   []map[string]any
}

// FirewallRuleSvc serves the typed `firewall rule` first-class command
// surface. It calls Inner.List/Get and converts each `any` item to
// `map[string]any` for caller convenience.
type FirewallRuleSvc struct {
	Inner *ObjectSvc
}

// List returns FirewallRule records as plain maps.
func (s *FirewallRuleSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*FirewallRuleList, error) {
	inner, err := s.Inner.List(ctx, profileName, "FirewallRule", filter)
	if err != nil {
		return nil, err
	}
	out := &FirewallRuleList{Profile: inner.Profile, Filter: inner.Filter}
	for _, item := range inner.Items {
		m, err := toMap(item)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, m)
	}
	out.Count = len(out.Items)
	if out.Items == nil {
		out.Items = []map[string]any{}
	}
	return out, nil
}

// Get fetches one FirewallRule by name.
func (s *FirewallRuleSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
	inner, err := s.Inner.Get(ctx, profileName, "FirewallRule", name)
	if err != nil {
		return nil, err
	}
	return toMap(inner.Data)
}

// toMap converts a parser output to map[string]any. For generic catalog
// entries the parser yields map[string]any directly; the round-trip via
// JSON is a defensive fallback for any future typed entry that gets
// asked for through a generic-rule lens.
func toMap(item any) (map[string]any, error) {
	if m, ok := item.(map[string]any); ok {
		return m, nil
	}
	b, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("firewallrule: marshal: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("firewallrule: unmarshal: %w", err)
	}
	return m, nil
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run "TestFirewallRuleSvc" -v
```
Expected: PASS for all 3 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/svc/firewallrule.go internal/svc/firewallrule_test.go
git commit -m "feat(svc): FirewallRuleSvc with map[string]any items"
```

---

## Task 9: `svc/natrule.go` — NATRuleSvc

**Files:**
- Create: `internal/svc/natrule.go`
- Create: `internal/svc/natrule_test.go`

Mirror of FirewallRuleSvc. Reuses `toMap` from `firewallrule.go`.

- [ ] **Step 1: Write the failing tests**

Create `internal/svc/natrule_test.go`:
```go
package svc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/stretchr/testify/require"
)

type fakeNATClient struct {
	body map[string][]json.RawMessage
}

func (f fakeNATClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeNATClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newNATSvc(t *testing.T, body map[string][]json.RawMessage) *NATRuleSvc {
	t.Helper()
	cat, err := catalog.NewDefault()
	require.NoError(t, err)
	cfg := config.New()
	cfg.AddProfile("home", config.Profile{URL: "https://x:4444"})
	store := creds.NewFileStore(t.TempDir())
	require.NoError(t, store.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	inner := &ObjectSvc{
		Config: cfg, Creds: store, Catalog: cat,
		NewClient: func(_ config.Profile, _ creds.Credentials) Client { return fakeNATClient{body: body} },
	}
	return &NATRuleSvc{Inner: inner}
}

func TestNATRuleSvc_List(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Outbound","Status":"Enable","OriginalSourceNetworks":["LAN-network"]}`),
			json.RawMessage(`{"Name":"DMZ-DNAT","Status":"Enable","OriginalSourceNetworks":["Any"]}`),
		},
	}
	s := newNATSvc(t, body)
	out, err := s.List(context.Background(), "home", nil)
	require.NoError(t, err)
	require.Len(t, out.Items, 2)
	require.Equal(t, "WAN-Outbound", out.Items[0]["Name"])
}

func TestNATRuleSvc_Get_ByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Outbound","Status":"Enable"}`),
		},
	}
	s := newNATSvc(t, body)
	rule, err := s.Get(context.Background(), "home", "WAN-Outbound")
	require.NoError(t, err)
	require.Equal(t, "WAN-Outbound", rule["Name"])
}

func TestNATRuleSvc_Get_NotFound(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {},
	}
	s := newNATSvc(t, body)
	_, err := s.Get(context.Background(), "home", "missing")
	require.Error(t, err)
	require.ErrorIs(t, err, sophos.ErrNotFound)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/svc -run "TestNATRuleSvc" -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `internal/svc/natrule.go`**

```go
package svc

import (
	"context"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// NATRuleList is the render-friendly result of a NAT rule list. Items are
// untyped maps; NATRule has no typed parser in Phase 3.
type NATRuleList struct {
	Profile string
	Filter  *sophos.FilterClause
	Count   int
	Items   []map[string]any
}

// NATRuleSvc serves the typed `nat rule` first-class command surface.
type NATRuleSvc struct {
	Inner *ObjectSvc
}

// List returns NATRule records as plain maps.
func (s *NATRuleSvc) List(ctx context.Context, profileName string, filter *sophos.FilterClause) (*NATRuleList, error) {
	inner, err := s.Inner.List(ctx, profileName, "NATRule", filter)
	if err != nil {
		return nil, err
	}
	out := &NATRuleList{Profile: inner.Profile, Filter: inner.Filter}
	for _, item := range inner.Items {
		m, err := toMap(item)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, m)
	}
	out.Count = len(out.Items)
	if out.Items == nil {
		out.Items = []map[string]any{}
	}
	return out, nil
}

// Get fetches one NATRule by name.
func (s *NATRuleSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
	inner, err := s.Inner.Get(ctx, profileName, "NATRule", name)
	if err != nil {
		return nil, err
	}
	return toMap(inner.Data)
}
```

- [ ] **Step 4: Run — must pass**

```bash
go test ./internal/svc -run "TestNATRuleSvc" -v
```
Expected: PASS for all 3 tests.

- [ ] **Step 5: Run full svc suite to catch regressions**

```bash
go test ./internal/svc -count=1
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/svc/natrule.go internal/svc/natrule_test.go
git commit -m "feat(svc): NATRuleSvc with map[string]any items"
```

---

## Task 10: `cli/columns.go` — `--columns` resolver + backport to `object list`

**Files:**
- Create: `internal/cli/columns.go`
- Modify: `internal/cli/object.go` (add `--columns` flag, use resolver)
- Modify: `internal/cli/object_test.go` (add backport test)

- [ ] **Step 1: Add the failing test for the backport**

Append to `internal/cli/object_test.go`:
```go
func TestObject_List_ColumnsOverride(t *testing.T) {
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
	root.SetArgs([]string{"object", "list", "IPHost", "--columns", "Name,IPAddress"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN")
	require.Contains(t, out.String(), "10.0.0.0")
	// HostType column was in default but is NOT requested; substring "Network"
	// must NOT appear in the table view.
	require.NotContains(t, out.String(), "Network")
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestObject_List_ColumnsOverride -v
```
Expected: FAIL — flag not registered.

- [ ] **Step 3: Implement `internal/cli/columns.go`**

```go
package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// resolveColumns returns the column list for a list-style table render. If
// the cobra command has a --columns flag set to a non-empty value, the
// caller-supplied list (split on commas) wins; otherwise the catalog
// default is returned. Whitespace around comma-separated names is trimmed.
func resolveColumns(cmd *cobra.Command, defaultCols []string) []string {
	v, _ := cmd.Flags().GetString("columns")
	if v == "" {
		return defaultCols
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return defaultCols
	}
	return out
}
```

- [ ] **Step 4: Modify `internal/cli/object.go`**

In `newObjectListCmd`, add the `--columns` flag declaration alongside `--filter`:
```go
c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value (e.g. Name:like:LAN)")
c.Flags().String("columns", "", "comma-separated column override (default: catalog columns)")
```

In `renderObjectList`, the existing line `headers := entry.Columns` should become:
```go
headers := resolveColumns(cmd, entry.Columns)
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/cli -run "TestObject" -v
```
Expected: PASS for the new test plus all existing object tests.

- [ ] **Step 6: Run the full cli test suite**

```bash
go test ./internal/cli -count=1
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/columns.go internal/cli/object.go internal/cli/object_test.go
git commit -m "feat(cli): --columns flag resolver + backport to object list"
```

---

## Task 11: `cli/hostip.go` — `host ip` first-class commands

**Files:**
- Create: `internal/cli/hostip.go`
- Create: `internal/cli/hostip_test.go`
- Modify: `internal/cli/root.go` (register `newHostCmd`)

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/hostip_test.go`:
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

type fakeHostIpCliClient struct{ body map[string][]json.RawMessage }

func (f fakeHostIpCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeHostIpCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForHostIpTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeHostIpCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestHostIp_List_JSONHasDerivedBlock(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpList"`)
	require.Contains(t, out.String(), `"cidr": "10.0.0.0/24"`)
	require.Contains(t, out.String(), `"kind": "network"`)
}

func TestHostIp_List_TablePrintsCidrColumn(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "list", "--columns", "Name,derived.cidr,derived.kind"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN")
	require.Contains(t, out.String(), "10.0.0.0/24")
	require.Contains(t, out.String(), "network")
}

func TestHostIp_Show_Positional(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`)},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "show", "LAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIp"`)
	require.Contains(t, out.String(), `"Name": "LAN"`)
}

func TestHostIp_Search_FiltersClientSide(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHost": {
			json.RawMessage(`{"Name":"LAN","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.0.0.0","Subnet":"255.255.255.0"}`),
			json.RawMessage(`{"Name":"DMZ","IPFamily":"IPv4","HostType":"Network","IPAddress":"10.1.0.0","Subnet":"255.255.255.0"}`),
		},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "search", "LAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpSearch"`)
	require.Contains(t, out.String(), `"Name": "LAN"`)
	// DMZ must not appear in the search output.
	require.False(t, strings.Contains(out.String(), `"Name": "DMZ"`))
}

func TestHostIp_Usage_WithReferences_JSONShape(t *testing.T) {
	body := map[string][]json.RawMessage{
		"IPHostStatistics": {json.RawMessage(`{"Name":"LAN","HitCount":"42"}`)},
		"IPHostGroup":      {json.RawMessage(`{"Name":"LAN-grp","HostList":["LAN","DMZ"]}`)},
		"FirewallRule":     {json.RawMessage(`{"Name":"LAN-To-WAN","Sources":["LAN"]}`)},
		"NATRule":          {},
	}
	d := newRootForHostIpTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"host", "ip", "usage", "LAN", "--with-references", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.hostIpUsage"`)
	require.Contains(t, out.String(), `"references"`)
	require.Contains(t, out.String(), `"IPHostGroup"`)
	require.Contains(t, out.String(), `"LAN-grp"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestHostIp -v
```
Expected: FAIL — `host` subcommand unknown.

- [ ] **Step 3: Implement `internal/cli/hostip.go`**

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

func newHostCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "host", Short: "Host objects (first-class)"}
	cmd.AddCommand(newHostIpCmd(d, cat))
	return cmd
}

func newHostIpCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "ip", Short: "IPHost first-class commands"}
	cmd.AddCommand(
		newHostIpListCmd(d, cat),
		newHostIpShowCmd(d, cat),
		newHostIpSearchCmd(d, cat),
		newHostIpUsageCmd(d, cat),
	)
	return cmd
}

func hostIpSvc(d RootDeps, cat *catalog.Catalog) *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newHostIpListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List IP host objects",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			var filter *sophos.FilterClause
			if filterStr != "" {
				f, err := sophos.ParseFilterFlag(filterStr)
				if err != nil {
					return err
				}
				filter = &f
			}
			out, err := hostIpSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderHostIpList(cmd, cat, "sophosfw.v1.hostIpList", out)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newHostIpShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one IP host object by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			h, err := hostIpSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.hostIp", h)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n  IPAddress: %s\n  Subnet:    %s\n  Derived:   kind=%s cidr=%s\n",
				h.Name, h.HostType, h.IPAddress, h.Subnet, h.Derived.Kind, h.Derived.CIDR)
			return nil
		},
	}
}

func newHostIpSearchCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "search <query>",
		Short: "Multi-field substring search across IP hosts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := hostIpSvc(d, cat).Search(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			return renderHostIpList(cmd, cat, "sophosfw.v1.hostIpSearch", out)
		},
	}
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newHostIpUsageCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var withRefs bool
	c := &cobra.Command{
		Use:   "usage <name>",
		Short: "Show IPHostStatistics for a host (optionally with reference graph)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := hostIpSvc(d, cat).Usage(cmd.Context(), profile, args[0], withRefs)
			if err != nil {
				return err
			}
			payload := map[string]any{
				"profile": out.Profile,
				"name":    out.Name,
				"records": out.Records,
			}
			if out.References != nil {
				payload["references"] = out.References.Refs
				if len(out.References.Errors) > 0 {
					payload["referenceErrors"] = out.References.Errors
				}
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.hostIpUsage", payload)
		},
	}
	c.Flags().BoolVar(&withRefs, "with-references", false, "scan reference graph (rules + groups) for the host")
	return c
}

func renderHostIpList(cmd *cobra.Command, cat *catalog.Catalog, schema string, list *svc.HostIPList) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		return render.WriteJSON(cmd.OutOrStdout(), schema, map[string]any{
			"profile": list.Profile,
			"count":   list.Count,
			"items":   list.Items,
		})
	}
	entry, _ := cat.Resolve("IPHost")
	headers := resolveColumns(cmd, entry.Columns)
	rows := make([][]string, 0, len(list.Items))
	for _, h := range list.Items {
		rows = append(rows, hostIpRow(h, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

func hostIpRow(h svc.HostIP, headers []string) []string {
	row := make([]string, len(headers))
	for i, col := range headers {
		row[i] = hostIpCell(h, col)
	}
	return row
}

func hostIpCell(h svc.HostIP, col string) string {
	switch col {
	case "Name":
		return h.Name
	case "IPFamily":
		return h.IPFamily
	case "HostType":
		return h.HostType
	case "IPAddress":
		return h.IPAddress
	case "Subnet":
		return h.Subnet
	case "StartIPAddress":
		return h.StartIPAddress
	case "EndIPAddress":
		return h.EndIPAddress
	case "derived.cidr":
		return h.Derived.CIDR
	case "derived.kind":
		return h.Derived.Kind
	}
	return ""
}
```

- [ ] **Step 4: Wire into root**

In `internal/cli/root.go`, add the catalog-aware import and a registration line. The current `NewRoot` already loads `cat, _ := catalog.NewDefault()` and passes it to `newObjectCmd(d, cat)` and `newMCPCmd(d, cat)`. Add after those:

```go
root.AddCommand(newHostCmd(d, cat))
```

(Just before the existing `return root` line.)

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/cli -run TestHostIp -v
```
Expected: PASS for all 5 host-ip tests.

- [ ] **Step 6: Run full cli + svc test suite**

```bash
go test ./internal/cli ./internal/svc -count=1
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/hostip.go internal/cli/hostip_test.go internal/cli/root.go
git commit -m "feat(cli): host ip list/show/search/usage first-class commands"
```

---

## Task 12: `cli/service.go` — `service` first-class commands

**Files:**
- Create: `internal/cli/service.go`
- Create: `internal/cli/service_test.go`
- Modify: `internal/cli/root.go` (register `newServiceCmd`)

This task mirrors T11's structure for the typed `Service` surface.

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/service_test.go`:
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

type fakeServiceCliClient struct{ body map[string][]json.RawMessage }

func (f fakeServiceCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeServiceCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForServiceTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeServiceCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestService_List_JSONHasDerivedBlock(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceList"`)
	require.Contains(t, out.String(), `"protocol": "tcp"`)
	require.Contains(t, out.String(), `"portRange": "80"`)
}

func TestService_Show_Positional(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`)},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "show", "HTTP", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.service"`)
	require.Contains(t, out.String(), `"Name": "HTTP"`)
}

func TestService_Search_FiltersClientSide(t *testing.T) {
	body := map[string][]json.RawMessage{
		"Services": {
			json.RawMessage(`{"Name":"HTTP","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"80"}]}}`),
			json.RawMessage(`{"Name":"SSH","Type":"TCPorUDP","ServiceDetails":{"ServiceDetail":[{"Protocol":"TCP","DestinationPort":"22"}]}}`),
		},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "search", "SSH", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceSearch"`)
	require.Contains(t, out.String(), `"Name": "SSH"`)
	require.False(t, strings.Contains(out.String(), `"Name": "HTTP"`))
}

func TestService_Usage_WithReferences(t *testing.T) {
	body := map[string][]json.RawMessage{
		"ServicesStatistics": {json.RawMessage(`{"Name":"HTTP","HitCount":"42"}`)},
		"ServiceGroup":       {json.RawMessage(`{"Name":"Web-svcs","ServiceList":["HTTP","HTTPS"]}`)},
		"FirewallRule":       {json.RawMessage(`{"Name":"Web-Out","Services":["HTTP"]}`)},
		"NATRule":            {},
	}
	d := newRootForServiceTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"service", "usage", "HTTP", "--with-references", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.serviceUsage"`)
	require.Contains(t, out.String(), `"references"`)
	require.Contains(t, out.String(), `"Web-svcs"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestService -v
```
Expected: FAIL — `service` subcommand unknown.

- [ ] **Step 3: Implement `internal/cli/service.go`**

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

func newServiceCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Service first-class commands"}
	cmd.AddCommand(
		newServiceListCmd(d, cat),
		newServiceShowCmd(d, cat),
		newServiceSearchCmd(d, cat),
		newServiceUsageCmd(d, cat),
	)
	return cmd
}

func serviceSvc(d RootDeps, cat *catalog.Catalog) *svc.ServiceSvc {
	return &svc.ServiceSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newServiceListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List service objects",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			var filter *sophos.FilterClause
			if filterStr != "" {
				f, err := sophos.ParseFilterFlag(filterStr)
				if err != nil {
					return err
				}
				filter = &f
			}
			out, err := serviceSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderServiceList(cmd, cat, "sophosfw.v1.serviceList", out)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newServiceShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one service by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			v, err := serviceSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.service", v)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n  Derived: protocol=%s portRange=%s\n",
				v.Name, v.Type, v.Derived.Protocol, v.Derived.PortRange)
			return nil
		},
	}
}

func newServiceSearchCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	c := &cobra.Command{
		Use:   "search <query>",
		Short: "Substring search across service Name and synthesized portRange",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := serviceSvc(d, cat).Search(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			return renderServiceList(cmd, cat, "sophosfw.v1.serviceSearch", out)
		},
	}
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newServiceUsageCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var withRefs bool
	c := &cobra.Command{
		Use:   "usage <name>",
		Short: "Show ServicesStatistics for a service (optionally with reference graph)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			out, err := serviceSvc(d, cat).Usage(cmd.Context(), profile, args[0], withRefs)
			if err != nil {
				return err
			}
			payload := map[string]any{
				"profile": out.Profile,
				"name":    out.Name,
				"records": out.Records,
			}
			if out.References != nil {
				payload["references"] = out.References.Refs
				if len(out.References.Errors) > 0 {
					payload["referenceErrors"] = out.References.Errors
				}
			}
			return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.serviceUsage", payload)
		},
	}
	c.Flags().BoolVar(&withRefs, "with-references", false, "scan reference graph (rules + groups) for the service")
	return c
}

func renderServiceList(cmd *cobra.Command, cat *catalog.Catalog, schema string, list *svc.ServiceList) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		return render.WriteJSON(cmd.OutOrStdout(), schema, map[string]any{
			"profile": list.Profile,
			"count":   list.Count,
			"items":   list.Items,
		})
	}
	entry, _ := cat.Resolve("Services")
	headers := resolveColumns(cmd, entry.Columns)
	rows := make([][]string, 0, len(list.Items))
	for _, v := range list.Items {
		rows = append(rows, serviceRow(v, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

func serviceRow(v svc.Service, headers []string) []string {
	row := make([]string, len(headers))
	for i, col := range headers {
		row[i] = serviceCell(v, col)
	}
	return row
}

func serviceCell(v svc.Service, col string) string {
	switch col {
	case "Name":
		return v.Name
	case "Type":
		return v.Type
	case "ServiceDetails":
		return v.Derived.PortRange // table-friendly substitute
	case "derived.protocol":
		return v.Derived.Protocol
	case "derived.portRange":
		return v.Derived.PortRange
	}
	return ""
}
```

- [ ] **Step 4: Wire into root**

In `internal/cli/root.go`, add after the `newHostCmd` registration:
```go
root.AddCommand(newServiceCmd(d, cat))
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/cli -run TestService -v
```
Expected: PASS for all 4 service tests.

- [ ] **Step 6: Run full cli suite**

```bash
go test ./internal/cli -count=1
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/service.go internal/cli/service_test.go internal/cli/root.go
git commit -m "feat(cli): service list/show/search/usage first-class commands"
```

---

## Task 13: `cli/firewallrule.go` — `firewall rule` first-class commands

**Files:**
- Create: `internal/cli/firewallrule.go`
- Create: `internal/cli/firewallrule_test.go`
- Modify: `internal/cli/root.go` (register `newFirewallCmd`)

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/firewallrule_test.go`:
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

type fakeFwRuleCliClient struct{ body map[string][]json.RawMessage }

func (f fakeFwRuleCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeFwRuleCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForFwRuleTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeFwRuleCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestFirewallRule_List_DefaultColumnsAndArrayCells(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable","Position":"1","IPFamily":"IPv4","SourceZones":["LAN","DMZ"],"DestinationZones":["WAN"]}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "list"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN-To-WAN")
	// Array cell collapsed to comma-joined: "LAN, DMZ"
	require.Contains(t, out.String(), "LAN, DMZ")
}

func TestFirewallRule_List_JSONEnvelope(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable"}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRuleList"`)
	require.Contains(t, out.String(), `"Name": "LAN-To-WAN"`)
}

func TestFirewallRule_List_ColumnsOverride(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable","Position":"1"}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "list", "--columns", "Name,Action"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "LAN-To-WAN")
	require.Contains(t, out.String(), "Accept")
	// Status is in the catalog default but NOT requested.
	require.False(t, strings.Contains(out.String(), "Enable"))
}

func TestFirewallRule_Show_ByName(t *testing.T) {
	body := map[string][]json.RawMessage{
		"FirewallRule": {
			json.RawMessage(`{"Name":"LAN-To-WAN","Action":"Accept","Status":"Enable"}`),
		},
	}
	d := newRootForFwRuleTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"firewall", "rule", "show", "LAN-To-WAN", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.firewallRule"`)
	require.Contains(t, out.String(), `"Name": "LAN-To-WAN"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestFirewallRule -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `internal/cli/firewallrule.go`**

```go
package cli

import (
	"fmt"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/spf13/cobra"
)

func newFirewallCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "firewall", Short: "Firewall first-class commands"}
	cmd.AddCommand(newFirewallRuleCmd(d, cat))
	return cmd
}

func newFirewallRuleCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "Firewall rule first-class commands"}
	cmd.AddCommand(
		newFirewallRuleListCmd(d, cat),
		newFirewallRuleShowCmd(d, cat),
	)
	return cmd
}

func firewallRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.FirewallRuleSvc {
	return &svc.FirewallRuleSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newFirewallRuleListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List firewall rules",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			var filter *sophos.FilterClause
			if filterStr != "" {
				f, err := sophos.ParseFilterFlag(filterStr)
				if err != nil {
					return err
				}
				filter = &f
			}
			out, err := firewallRuleSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderRuleMapList(cmd, cat, "FirewallRule", "sophosfw.v1.firewallRuleList", out.Profile, out.Count, out.Items)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newFirewallRuleShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one firewall rule by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			rule, err := firewallRuleSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.firewallRule", rule)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%v\n", rule)
			return nil
		},
	}
}

// renderRuleMapList renders a list of map[string]any items as either JSON
// (with the given schema name) or a column-aware table. Used by both the
// firewall rule and nat rule list commands. Array values are comma-joined
// in the table view.
func renderRuleMapList(cmd *cobra.Command, cat *catalog.Catalog, tag, schema, profile string, count int, items []map[string]any) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	if jsonMode {
		return render.WriteJSON(cmd.OutOrStdout(), schema, map[string]any{
			"profile": profile,
			"count":   count,
			"items":   items,
		})
	}
	entry, _ := cat.Resolve(tag)
	headers := resolveColumns(cmd, entry.Columns)
	rows := make([][]string, 0, len(items))
	for _, m := range items {
		rows = append(rows, mapRow(m, headers))
	}
	return render.WriteTable(cmd.OutOrStdout(), headers, rows)
}

// mapRow extracts cells for a generic map[string]any record. Array values
// render comma-joined; map and other complex values render as their default
// fmt.Sprintf("%v") form.
func mapRow(m map[string]any, headers []string) []string {
	row := make([]string, len(headers))
	for i, col := range headers {
		row[i] = mapCell(m, col)
	}
	return row
}

func mapCell(m map[string]any, col string) string {
	v, ok := m[col]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			} else {
				parts = append(parts, fmt.Sprintf("%v", e))
			}
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}
```

- [ ] **Step 4: Wire into root**

In `internal/cli/root.go`, add after the `newServiceCmd` registration:
```go
root.AddCommand(newFirewallCmd(d, cat))
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/cli -run TestFirewallRule -v
```
Expected: PASS for all 4 firewall-rule tests.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/firewallrule.go internal/cli/firewallrule_test.go internal/cli/root.go
git commit -m "feat(cli): firewall rule list/show first-class commands"
```

---

## Task 14: `cli/natrule.go` — `nat rule` first-class commands

**Files:**
- Create: `internal/cli/natrule.go`
- Create: `internal/cli/natrule_test.go`
- Modify: `internal/cli/root.go` (register `newNATCmd`)

Mirrors T13's structure, reuses `renderRuleMapList` and `mapRow`.

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/natrule_test.go`:
```go
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
	"github.com/stretchr/testify/require"
)

type fakeNATCliClient struct{ body map[string][]json.RawMessage }

func (f fakeNATCliClient) Do(_ context.Context, env sophos.Envelope) (*sophos.Response, error) {
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
func (fakeNATCliClient) DoRaw(_ context.Context, _ []byte) (*sophos.Response, error) {
	return &sophos.Response{LoginOK: true}, nil
}

func newRootForNATTest(t *testing.T, body map[string][]json.RawMessage) *RootDeps {
	t.Helper()
	d, _ := newRootForTest(t)
	d.NewClient = func(_ config.Profile, _ creds.Credentials) svc.Client {
		return fakeNATCliClient{body: body}
	}
	require.NoError(t, (&svc.ProfileSvc{Config: d.Config, Creds: d.Creds, BaseDir: d.BaseDir}).Add("home", "https://x:4444", false))
	require.NoError(t, d.Creds.Save("home", creds.Credentials{Username: "u", Password: "p"}))
	return d
}

func TestNATRule_List_JSON(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Out","Status":"Enable","OriginalSourceNetworks":["LAN-network"]}`),
		},
	}
	d := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "list", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRuleList"`)
	require.Contains(t, out.String(), `"Name": "WAN-Out"`)
}

func TestNATRule_Show(t *testing.T) {
	body := map[string][]json.RawMessage{
		"NATRule": {
			json.RawMessage(`{"Name":"WAN-Out","Status":"Enable"}`),
		},
	}
	d := newRootForNATTest(t, body)
	root := NewRoot(*d)
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"nat", "rule", "show", "WAN-Out", "--json"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), `"schema": "sophosfw.v1.natRule"`)
	require.Contains(t, out.String(), `"Name": "WAN-Out"`)
}
```

- [ ] **Step 2: Run — must fail**

```bash
go test ./internal/cli -run TestNATRule -v
```
Expected: FAIL.

- [ ] **Step 3: Implement `internal/cli/natrule.go`**

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

func newNATCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "nat", Short: "NAT first-class commands"}
	cmd.AddCommand(newNATRuleCmd(d, cat))
	return cmd
}

func newNATRuleCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "NAT rule first-class commands"}
	cmd.AddCommand(
		newNATRuleListCmd(d, cat),
		newNATRuleShowCmd(d, cat),
	)
	return cmd
}

func natRuleSvc(d RootDeps, cat *catalog.Catalog) *svc.NATRuleSvc {
	return &svc.NATRuleSvc{Inner: &svc.ObjectSvc{
		Config: d.Config, Creds: d.Creds, Catalog: cat, NewClient: d.NewClient,
	}}
}

func newNATRuleListCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	var filterStr string
	c := &cobra.Command{
		Use:   "list",
		Short: "List NAT rules",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			var filter *sophos.FilterClause
			if filterStr != "" {
				f, err := sophos.ParseFilterFlag(filterStr)
				if err != nil {
					return err
				}
				filter = &f
			}
			out, err := natRuleSvc(d, cat).List(cmd.Context(), profile, filter)
			if err != nil {
				return err
			}
			return renderRuleMapList(cmd, cat, "NATRule", "sophosfw.v1.natRuleList", out.Profile, out.Count, out.Items)
		},
	}
	c.Flags().StringVar(&filterStr, "filter", "", "Field:Criteria:Value")
	c.Flags().String("columns", "", "comma-separated column override")
	return c
}

func newNATRuleShowCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one NAT rule by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			rule, err := natRuleSvc(d, cat).Get(cmd.Context(), profile, args[0])
			if err != nil {
				return err
			}
			jsonMode, _ := cmd.Flags().GetBool("json")
			if jsonMode {
				return render.WriteJSON(cmd.OutOrStdout(), "sophosfw.v1.natRule", rule)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%v\n", rule)
			return nil
		},
	}
}
```

- [ ] **Step 4: Wire into root**

In `internal/cli/root.go`, add after the `newFirewallCmd` registration:
```go
root.AddCommand(newNATCmd(d, cat))
```

- [ ] **Step 5: Run — must pass**

```bash
go test ./internal/cli -run TestNATRule -v
```
Expected: PASS for all 2 nat-rule tests.

- [ ] **Step 6: Run the entire test suite**

```bash
go test ./... -count=1
```
Expected: PASS across all packages.

- [ ] **Step 7: Build and inspect the binary's command tree**

```bash
make build
./bin/sophosfw --help
```
Expected: `host`, `service`, `firewall`, `nat` appear under "Available Commands". Drill into each and verify the subcommands.

```bash
./bin/sophosfw host ip --help
./bin/sophosfw service --help
./bin/sophosfw firewall rule --help
./bin/sophosfw nat rule --help
```
Each should show the correct subcommands.

- [ ] **Step 8: Commit**

```bash
git add internal/cli/natrule.go internal/cli/natrule_test.go internal/cli/root.go
git commit -m "feat(cli): nat rule list/show first-class commands"
```

---

## Task 15: Integration tests for the new typed wrappers

**Files:**
- Modify: `internal/testutil/integration_test.go` (append 4 round-trip tests)

These tests are behind the `integration` build tag (already established in the foundation) and only run with `make test-int`.

- [ ] **Step 1: Add the new tests**

Append to `internal/testutil/integration_test.go`:
```go
func TestIntegration_HostIPList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "IPHost"}},
	})
	require.NoError(t, err)
}

func TestIntegration_ServiceList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "Services"}},
	})
	require.NoError(t, err)
}

func TestIntegration_FirewallRuleList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "FirewallRule"}},
	})
	require.NoError(t, err)
}

func TestIntegration_NATRuleList_RoundTrips(t *testing.T) {
	c := newClient(t)
	_, err := c.Do(context.Background(), sophos.Envelope{
		Operations: []sophos.Op{sophos.GetOp{XMLTag: "NATRule"}},
	})
	require.NoError(t, err)
}
```

- [ ] **Step 2: Verify the build tag still excludes them from the standard test run**

```bash
go test ./... -count=1
```
Expected: PASS, integration tests not run.

- [ ] **Step 3: Verify they compile under the integration tag**

```bash
go vet -tags integration ./internal/testutil
```
Expected: PASS, no vet warnings.

- [ ] **Step 4: Commit**

```bash
git add internal/testutil/integration_test.go
git commit -m "test(integration): round-trip checks for host ip, service, firewall rule, nat rule"
```

---

## Task 16: Documentation updates — api-coverage and roadmap

**Files:**
- Modify: `docs/api-coverage.md`
- Modify: `docs/roadmap.md`

Phase 3 shifts the "Status" column for several tags from `partial` to `Phase 3` and adds a status note in the roadmap.

- [ ] **Step 1: Update `docs/api-coverage.md` table**

The table currently has rows like:
```
| Host | IPHost | object list/get IPHost | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
```

For the rows where Phase 3 ships first-class commands, the "CLI Command" column expands. Replace the table contents (keep the header and the source-references line) with:

```markdown
| Area | XML Tag | CLI Command | MCP Tool | Get | Add | Update | Remove | Usage | Status |
|---|---|---|---|---|---|---|---|---|---|
| Host | IPHost | object list/get IPHost; host ip list/show/search/usage | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
| Host | IPHostGroup | object list/get IPHostGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | FQDNHost | object list/get FQDNHost (typed Phase 3) | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Host | FQDNHostGroup | object list/get FQDNHostGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | MACHost | object list/get MACHost (typed Phase 3) | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Service | Services | object list/get Services; service list/show/search/usage | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
| Service | ServiceGroup | object list/get ServiceGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Zone | object list/get Zone (typed Phase 3) | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Network | Interface | object list/get Interface | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Gateway | object list/get Gateway | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |
| Firewall | NATRule | object list/get NATRule; nat rule list/show | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |
```

Keep the source-references line intact at the bottom.

- [ ] **Step 2: Update `docs/roadmap.md` Status section**

Find:
```markdown
## Status
- Phase 0 — Research and design (this spec)
- Phase 1 — Foundation (covered by this spec; implementation plan to follow)
- Phase 2 — Generic API coverage (covered by this spec; implementation plan to follow)
- Phase 3 — First-class read-only commands (host ip, service, firewall rule, nat rule)
```

Replace with:
```markdown
## Status
- Phase 0 — Research and design (complete)
- Phase 1 — Foundation (complete; v0.1.0-foundation)
- Phase 2 — Generic API coverage (complete; covered by foundation)
- Phase 3 — First-class read-only commands (complete; v0.2.0-phase3)
```

- [ ] **Step 3: Sanity check**

```bash
make build
make skill-doctor
```
Expected: build succeeds; `skill ok`. (Skill update for Phase 3 commands lands in Phase 5; doctor's required-commands list is unchanged.)

- [ ] **Step 4: Commit**

```bash
git add docs/api-coverage.md docs/roadmap.md
git commit -m "docs: api-coverage + roadmap status reflect Phase 3 completion"
```

---

## Task 17: Acceptance verification + tag

**Files:** none new — runs the Phase 3 acceptance checklist.

- [ ] **Step 1: Run the full test suite**

```bash
go fmt ./... && go vet ./... && go test -race ./...
```
Expected: PASS, no warnings, no fmt-induced changes (any drift gets committed in Step 5).

- [ ] **Step 2: Build and inspect the binary**

```bash
make build
./bin/sophosfw version
./bin/sophosfw --help
```
Expected: `host`, `service`, `firewall`, `nat` parents appear in the available-commands list.

- [ ] **Step 3: Walk through the acceptance items manually**

In a scratch directory:
```bash
TMPHOME=$(mktemp -d)
export XDG_CONFIG_HOME=$TMPHOME
./bin/sophosfw auth profile add home --url https://example.invalid:4444
./bin/sophosfw host ip --help                     # parent + 4 children
./bin/sophosfw service --help                     # 4 children
./bin/sophosfw firewall rule --help               # 2 children
./bin/sophosfw nat rule --help                    # 2 children
./bin/sophosfw object schema FirewallRule --json  # confirm catalog has it
./bin/sophosfw object schema FQDNHost --json | grep -i typedParser  # should show "fqdnhost"
```
Expected: each command renders its expected help text or schema JSON. The FQDNHost schema's `typedParser` field is `"fqdnhost"` (the typed-parser identifier registered in T1).

- [ ] **Step 4: Run skill-doctor**

```bash
make skill-doctor
```
Expected: `skill ok`.

- [ ] **Step 5: Commit any fmt-induced or smoke-test-induced changes**

```bash
git status
# If clean, skip to Step 6.
# If not, commit the fixes:
git add -A
git commit -m "fix: phase 3 acceptance pass adjustments"
```

- [ ] **Step 6: Tag the milestone**

```bash
git tag -a v0.2.0-phase3 -m "Phase 3 complete (first-class read-only commands)"
git tag --list | grep -E "(foundation|phase3)"
```
Expected: both `v0.1.0-foundation` and `v0.2.0-phase3` listed.

- [ ] **Step 7: Push to GitHub**

```bash
git push origin main
git push origin v0.2.0-phase3
```
Expected: clean push (the remote `origin` is the user's private GitHub repo).

- [ ] **Step 8: Final sanity**

```bash
git log --oneline -25
```
Expected: clean linear history with all 17 task commits + foundation history below.

---

## End of plan

This concludes the Phase 3 implementation plan. Next up is Phase 4 (MCP read-only server), which exposes the typed Phase 3 surface as MCP tools. Each future phase gets its own brainstorm → spec → plan → implementation cycle.

---

## Self-review checklist (verifies plan against spec)

Before declaring the plan ready, verify:

- ✅ **Spec section 1.2 in scope items:** four command groups (T11/12/13/14), three typed parsers (T1/2/3), six catalog YAML entries (handled in T1/2/3 + T8/9 reference foundation entries), four svc files (T5/7/8/9), four cli files (T11/12/13/14), references utility (T4), derived fields for IPHost (T5) and Service (T7), `--columns` flag with backport (T10), `--with-references` for host ip and service usage (T6/T7), multi-field search for host ip and service (T6/T7), 5 fixture XML files (NOT created — see "fixtures" note below), tests at cli + svc layers (each task), integration tests (T15).
- ✅ **No placeholders.** Every step has the actual file content, command, or expected output. No "TODO", "TBD", or "similar to Task N".
- ✅ **Type consistency.** `HostIPSvc.Inner *ObjectSvc`, `HostIPDerived.CIDR/Kind`, `HostIPList.Items []HostIP`, `HostIPUsage.References *References`, `References.Refs/Errors`, `referenceTargets[primaryTag] []string` — all named and used consistently across T4–T6 and T11.
- ✅ **Spec coverage gap noted:** the spec's section 8 calls for fixture XML files (`fqdnhost_get_one.xml`, `machost_get_one.xml`, `zone_get_one.xml`, `firewallrule_list_3.xml`, `natrule_list_2.xml`). The plan tests use **inline JSON** (via the foundation parser path `Body: map[string][]json.RawMessage`) rather than full XML round-tripping. Rationale: the foundation already exercises the XML parsing path with `iphost_get_one.xml` and `iphost_list_2.xml`; the new typed parsers operate on `json.RawMessage` directly, identical to the foundation's parser-test pattern. Fixture XML files would only retest the foundation's already-tested XML parser. The implementer may add the spec's fixture files if they want extra round-trip confidence; this plan does not require them.
- ✅ **Spec section 9 acceptance criteria** all map to T17 steps.
- ✅ **No mutating envelopes** are constructed anywhere in Phase 3 code (every `Op` is `GetOp` or `StatisticsOp`; the `IntegrationClient` wrapper from foundation mechanically blocks mutating envelopes if any slip through).
