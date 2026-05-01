package svc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

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
