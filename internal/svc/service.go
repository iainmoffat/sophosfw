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
	var raw catalog.Service
	switch d := inner.Data.(type) {
	case catalog.Service:
		raw = d
	case map[string]any:
		if err := decodeObjectDataInto(d, &raw); err != nil {
			return nil, fmt.Errorf("ServiceSvc.Get: decode Service: %w", err)
		}
	default:
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
