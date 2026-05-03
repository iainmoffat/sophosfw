package svc

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/safety"
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
	Audit *AuditLog // optional; nil = no audit logging (Write is a no-op anyway)
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
	// Sophos sometimes returns a stub record (all fields empty) for a
	// name that doesn't exist, instead of an empty result. Treat as
	// not_found so callers see a consistent kind.
	if raw.Name == "" {
		return nil, fmt.Errorf("IPHost %q: %w", name, sophos.ErrNotFound)
	}
	h := HostIP{IPHost: raw}
	enrichHostIP(&h)
	return &h, nil
}

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

// HostIPCreateInput is the validated input for HostIPSvc.Create / Update.
type HostIPCreateInput struct {
	Name           string
	IPFamily       string // "IPv4" or "IPv6"; default "IPv4" if empty
	HostType       string // "Network" | "IP" | "IPRange" | "IPList"
	IPAddress      string
	Subnet         string
	StartIPAddress string
	EndIPAddress   string
	IPAddressList  string
}

// HostIPMutationResult is the render-friendly result of a successful
// mutation (or the dry-run preview of one).
type HostIPMutationResult struct {
	Profile   string
	Operation string // "create" | "update" | "delete"
	Name      string
	DryRun    bool
	Preview   *Preview // populated when DryRun=true
	Item      *HostIP  // populated when applied; re-fetched post-write
}

// validateHostIPCreate checks per-HostType required fields. Server-side
// semantics (e.g. CIDR validity, IP range ordering) are NOT checked here;
// Sophos rejects those. We only catch missing-required-field cases.
func validateHostIPCreate(in HostIPCreateInput) error {
	if in.Name == "" {
		return fmt.Errorf("%w: --name is required", sophos.ErrInvalidRequest)
	}
	switch in.HostType {
	case "Network":
		if in.IPAddress == "" || in.Subnet == "" {
			return fmt.Errorf("%w: HostType=Network requires IPAddress and Subnet", sophos.ErrInvalidRequest)
		}
	case "IP":
		if in.IPAddress == "" {
			return fmt.Errorf("%w: HostType=IP requires IPAddress", sophos.ErrInvalidRequest)
		}
	case "IPRange":
		if in.StartIPAddress == "" || in.EndIPAddress == "" {
			return fmt.Errorf("%w: HostType=IPRange requires StartIPAddress and EndIPAddress", sophos.ErrInvalidRequest)
		}
	case "IPList":
		if in.IPAddressList == "" {
			return fmt.Errorf("%w: HostType=IPList requires IPAddressList", sophos.ErrInvalidRequest)
		}
	default:
		return fmt.Errorf("%w: unknown HostType %q (expected Network|IP|IPRange|IPList)", sophos.ErrInvalidRequest, in.HostType)
	}
	if in.IPFamily != "" && in.IPFamily != "IPv4" && in.IPFamily != "IPv6" {
		return fmt.Errorf("%w: IPFamily must be IPv4 or IPv6", sophos.ErrInvalidRequest)
	}
	return nil
}

// marshalIPHost emits the inner XML for a Set/Remove envelope. Fields are
// emitted only when non-empty. The order matches Sophos's typical
// representation (Name first, then HostType, IPFamily, then type-specific
// fields).
func marshalIPHost(in HostIPCreateInput) []byte {
	family := in.IPFamily
	if family == "" {
		family = "IPv4"
	}
	var b strings.Builder
	// xml.EscapeText writes to a strings.Builder whose Write never returns an
	// error, so the error returns from these calls are safe to discard.
	b.WriteString("<IPHost>")
	b.WriteString("<Name>")
	_ = xml.EscapeText(&b, []byte(in.Name))
	b.WriteString("</Name>")
	b.WriteString("<HostType>")
	_ = xml.EscapeText(&b, []byte(in.HostType))
	b.WriteString("</HostType>")
	b.WriteString("<IPFamily>")
	_ = xml.EscapeText(&b, []byte(family))
	b.WriteString("</IPFamily>")
	if in.IPAddress != "" {
		b.WriteString("<IPAddress>")
		_ = xml.EscapeText(&b, []byte(in.IPAddress))
		b.WriteString("</IPAddress>")
	}
	if in.Subnet != "" {
		b.WriteString("<Subnet>")
		_ = xml.EscapeText(&b, []byte(in.Subnet))
		b.WriteString("</Subnet>")
	}
	if in.StartIPAddress != "" {
		b.WriteString("<StartIPAddress>")
		_ = xml.EscapeText(&b, []byte(in.StartIPAddress))
		b.WriteString("</StartIPAddress>")
	}
	if in.EndIPAddress != "" {
		b.WriteString("<EndIPAddress>")
		_ = xml.EscapeText(&b, []byte(in.EndIPAddress))
		b.WriteString("</EndIPAddress>")
	}
	if in.IPAddressList != "" {
		b.WriteString("<IPAddressList>")
		_ = xml.EscapeText(&b, []byte(in.IPAddressList))
		b.WriteString("</IPAddressList>")
	}
	b.WriteString("</IPHost>")
	return []byte(b.String())
}

// Create issues <Set operation="add"><IPHost>...</IPHost></Set>.
//   - dryRun=true: validate, build envelope, return Preview, NO wire call.
//   - dryRun=false: validate, pre-flight read-only check, build, send,
//     audit-log, refetch (one Do call to get the post-write state).
func (s *HostIPSvc) Create(ctx context.Context, profileName string, input HostIPCreateInput, dryRun bool) (*HostIPMutationResult, error) {
	return s.mutate(ctx, profileName, "create", input.Name, input, "", false, dryRun)
}

// mutate is the shared implementation of Create/Update/Delete. operation is
// "create"|"update"|"delete". For delete, input is zeroed (only Name used).
// expectedHash and ignoreHash apply only to update/delete.
func (s *HostIPSvc) mutate(
	ctx context.Context,
	profileName, operation, name string,
	input HostIPCreateInput,
	expectedHash string,
	ignoreHash bool,
	dryRun bool,
) (out *HostIPMutationResult, err error) {
	// 1. Resolve profile — if this fails we have no Profile name to record.
	profile, profName, perr := s.Inner.Config.ActiveProfile(profileName)
	if perr != nil {
		return nil, perr
	}

	// Build the audit entry skeleton early so every pre-flight rejection path
	// can be captured in the audit log.
	auditEntry := AuditEntry{
		Profile:    profName,
		Operation:  operation,
		ObjectType: "IPHost",
		ObjectName: name,
	}
	if expectedHash != "" {
		auditEntry.ExpectedDiffHash = expectedHash
	}
	if ignoreHash {
		auditEntry.ExpectedDiffHash = "ignored"
	}

	// Defer a write that fires on any error before an explicit Result is set.
	defer func() {
		if err != nil && s.Audit != nil && auditEntry.Result == "" {
			auditEntry.Result = "error:" + ErrorKind(err)
			auditEntry.ErrorMessage = err.Error()
			_ = s.Audit.Write(auditEntry)
		}
	}()

	// 2. Read-only pre-flight check.
	if profile.ReadOnly {
		return nil, fmt.Errorf("%w: profile %q is read-only", sophos.ErrReadOnlyViolation, profName)
	}

	// 3. Catalog mutable check.
	catEntry, ok := s.Inner.Catalog.Resolve("IPHost")
	if !ok || !catEntry.Mutable {
		return nil, fmt.Errorf("%w: IPHost is not marked mutable in the catalog", ErrUnsupportedInPhase)
	}

	// 4. For create/update, validate the input.
	if operation != "delete" {
		if err := validateHostIPCreate(input); err != nil {
			return nil, err
		}
	} else if name == "" {
		return nil, fmt.Errorf("%w: --name is required for delete", sophos.ErrInvalidRequest)
	}

	// 5. For update/delete, fetch and check diff hash.
	if operation == "update" || operation == "delete" {
		if expectedHash == "" && !ignoreHash {
			return nil, fmt.Errorf("%w: expectedDiffHash is required for %s (or pass --ignore-diff-hash)", sophos.ErrInvalidRequest, operation)
		}
		if !ignoreHash {
			current, getErr := s.Get(ctx, profileName, name)
			if getErr != nil {
				return nil, getErr
			}
			gotHash, hashErr := DiffHash(current.IPHost) // hash the raw catalog.IPHost, not svc.HostIP
			if hashErr != nil {
				return nil, hashErr
			}
			if gotHash != expectedHash {
				return nil, fmt.Errorf("%w (have %s, expected %s)", ErrDiffHashMismatch, gotHash, expectedHash)
			}
		}
	}

	// 6. Build the envelope.
	c, credsErr := s.Inner.Creds.Load(profName)
	if credsErr != nil {
		return nil, credsErr
	}
	var (
		full        []byte
		envelopeErr error
	)
	switch operation {
	case "create":
		full, envelopeErr = sophos.BuildSetEnvelope("add", marshalIPHost(input), c.Username, c.Password)
	case "update":
		full, envelopeErr = sophos.BuildSetEnvelope("update", marshalIPHost(input), c.Username, c.Password)
	case "delete":
		var buf bytes.Buffer
		buf.WriteString("<IPHost><Name>")
		if err := xml.EscapeText(&buf, []byte(name)); err != nil {
			return nil, err
		}
		buf.WriteString("</Name></IPHost>")
		full, envelopeErr = sophos.BuildRemoveEnvelope(buf.Bytes(), c.Username, c.Password)
	}
	if envelopeErr != nil {
		return nil, envelopeErr
	}

	// 7. Populate RedactedXML now that we have the full envelope.
	auditEntry.RedactedXML = string(safetyRedact(full))

	// 8. Dry-run path.
	if dryRun {
		mutating, verbs := safetyIsMutating(full)
		pv := &Preview{
			Profile:        profName,
			Mutating:       mutating,
			Verbs:          verbs,
			RedactedXML:    auditEntry.RedactedXML,
			WouldSendBytes: len(full),
		}
		auditEntry.Result = "ok (dry-run)"
		_ = s.Audit.Write(auditEntry)
		return &HostIPMutationResult{
			Profile: profName, Operation: operation, Name: name,
			DryRun: true, Preview: pv,
		}, nil
	}

	// 9. Apply path: send the envelope.
	cl := s.Inner.NewClient(profile, c)
	if _, sendErr := cl.DoRaw(ctx, full); sendErr != nil {
		auditEntry.Result = "error:" + ErrorKind(sendErr)
		auditEntry.ErrorMessage = sendErr.Error()
		_ = s.Audit.Write(auditEntry)
		return nil, sendErr
	}
	auditEntry.Result = "ok"
	_ = s.Audit.Write(auditEntry)

	// 10. For create/update, re-fetch to return the post-write state.
	if operation == "delete" {
		return &HostIPMutationResult{
			Profile: profName, Operation: operation, Name: name, DryRun: false,
		}, nil
	}
	item, fetchErr := s.Get(ctx, profileName, name)
	if fetchErr != nil {
		// Mutation succeeded but re-fetch failed; return success with no Item.
		return &HostIPMutationResult{
			Profile: profName, Operation: operation, Name: name, DryRun: false,
		}, nil
	}
	return &HostIPMutationResult{
		Profile: profName, Operation: operation, Name: name, DryRun: false,
		Item: item,
	}, nil
}

// safetyIsMutating and safetyRedact are tiny indirections so this file
// doesn't need to import the safety package directly. They forward to the
// real helpers; if the implementer prefers a direct import they can
// inline these.
func safetyIsMutating(xml []byte) (bool, []string) { return safety.IsMutating(xml) }
func safetyRedact(xml []byte) []byte               { return safety.RedactXML(xml) }

// Update issues <Set operation="update"><IPHost>...</IPHost></Set>. Requires
// expectedHash unless ignoreHash=true. Compares against the current record's
// hash; mismatch returns ErrDiffHashMismatch. If dryRun is true, returns a
// Preview envelope without sending; if false, applies the update and returns
// the refetched item.
func (s *HostIPSvc) Update(
	ctx context.Context,
	profileName string,
	input HostIPCreateInput,
	expectedHash string,
	ignoreHash bool,
	dryRun bool,
) (*HostIPMutationResult, error) {
	return s.mutate(ctx, profileName, "update", input.Name, input, expectedHash, ignoreHash, dryRun)
}

// Delete issues <Remove><IPHost><Name>X</Name></IPHost></Remove>. Same hash
// semantics as Update. If dryRun is true, returns a Preview envelope without
// sending; if false, sends the Remove envelope.
func (s *HostIPSvc) Delete(
	ctx context.Context,
	profileName, name, expectedHash string,
	ignoreHash, dryRun bool,
) (*HostIPMutationResult, error) {
	return s.mutate(ctx, profileName, "delete", name, HostIPCreateInput{Name: name}, expectedHash, ignoreHash, dryRun)
}
