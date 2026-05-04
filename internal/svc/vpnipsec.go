package svc

import (
	"context"
	"time"
)

// VPNIPsecSvc provides read + draft + mutating coverage for the
// VPNIPsecConnection catalog tag (site-to-site IPsec tunnels). T2
// implements read-side only; T3 extends with the draft cycle and
// mutating methods (mirror of Phase 7-9 firewall_rule).
type VPNIPsecSvc struct {
	Inner   *ObjectSvc
	Audit   *AuditLog
	BaseDir string
	Now     func() time.Time // injectable for tests; defaults to time.Now() (T3 mutating methods)
	Version string
}

// Get fetches a single VPNIPsecConnection record by name. The returned
// map includes the `_diffHash` field injected by ObjectSvc.Get for
// mutable catalog entries (Phase 12 T5). Returns an error wrapping
// sophos.ErrNotFound when no record matches.
func (s *VPNIPsecSvc) Get(ctx context.Context, profileName, name string) (map[string]any, error) {
	inner, err := s.Inner.Get(ctx, profileName, "VPNIPsecConnection", name)
	if err != nil {
		return nil, err
	}
	return toMap(inner.Data)
}
