// Package mcp vpnipsec.go: MCP tool surface for site-to-site IPsec VPN
// tunnels (VPNIPsecConnection). Mirrors firewallrule.go (read tools) +
// firewallrule_mutation.go (mutating tools). Each mutating tool carries
// the Phase 14 profileSet field for multi-profile fan-out.
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// VPNIPsecListInput is the input for vpn_ipsec_list.
type VPNIPsecListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty"`
}

// VPNIPsecShowInput is the input for vpn_ipsec_show.
type VPNIPsecShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}

// VPNIPsecCreateInput is the input for vpn_ipsec_create.
type VPNIPsecCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the tunnel name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the full VPNIPsecConnection body as a JSON object. Required top-level keys: Name, Status, ConnectionType. The Name in body must match the name argument. Use vpn_ipsec_show on an existing tunnel to learn the shape."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

// VPNIPsecUpdateInput is the input for vpn_ipsec_update.
type VPNIPsecUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys same as create."`
	ExpectedDiffHash       string         `json:"expectedDiffHash" jsonschema:"required" jsonschema_description:"hash from a prior vpn_ipsec_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// VPNIPsecDeleteInput is the input for vpn_ipsec_delete.
type VPNIPsecDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash" jsonschema:"required" jsonschema_description:"hash from a prior vpn_ipsec_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

func (s *Server) registerVPNIPsec() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ipsec_list",
		Description: "List site-to-site IPsec VPN tunnels (VPNIPsecConnection). Returns sophosfw.v1.vpnIPsecList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List IPsec VPN tunnels"},
	}, s.handleVPNIPsecList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ipsec_show",
		Description: "Get one VPNIPsecConnection by name. Response always includes _diffHash, which vpn_ipsec_update and vpn_ipsec_delete require as expectedDiffHash.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show IPsec VPN tunnel"},
	}, s.handleVPNIPsecShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ipsec_create",
		Description: "Create a new VPNIPsecConnection. Requires confirm: true. Use dryRun: true to preview the envelope without sending. Returns sophosfw.v1.vpnIPsecPush on apply or sophosfw.v1.preview on dry-run. The body must include Name, Status, ConnectionType.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create IPsec VPN tunnel"},
	}, s.handleVPNIPsecCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ipsec_update",
		Description: "Update an existing VPNIPsecConnection. Requires confirm: true AND expectedDiffHash from a prior vpn_ipsec_show (or ignoreExpectedDiffHash: true). Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update IPsec VPN tunnel"},
	}, s.handleVPNIPsecUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ipsec_delete",
		Description: "Delete a VPNIPsecConnection by name. Requires confirm: true AND expectedDiffHash from a prior vpn_ipsec_show (or ignoreExpectedDiffHash: true).",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete IPsec VPN tunnel"},
	}, s.handleVPNIPsecDelete)
}

func (s *Server) vpnIPsecMcpSvc() *svc.VPNIPsecSvc {
	return &svc.VPNIPsecSvc{
		Inner:   s.objectSvc(),
		Audit:   s.deps.Audit,
		BaseDir: s.deps.BaseDir,
		Version: s.version,
	}
}

func (s *Server) handleVPNIPsecList(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNIPsecListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.objectSvc().List(ctx, profile, "VPNIPsecConnection", filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	items := make([]map[string]any, 0, len(out.Items))
	for _, raw := range out.Items {
		if m, ok := raw.(map[string]any); ok {
			items = append(items, m)
		}
	}
	body, err := render.VPNIPsecListEnvelope(out.Profile, len(items), items)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleVPNIPsecShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNIPsecShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	tunnel, err := s.vpnIPsecMcpSvc().Get(ctx, profile, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	// VPNIPsecSvc.Get goes through ObjectSvc.Get which already injects
	// _diffHash for catalog-mutable types (Phase 12 T5). Defense in depth:
	// re-inject if missing so agents can always rely on it.
	if tunnel != nil {
		if _, ok := tunnel["_diffHash"]; !ok {
			hash, hashErr := svc.DiffHash(tunnel)
			if hashErr != nil {
				return s.errorEnvelopeResult(hashErr, profile)
			}
			tunnel["_diffHash"] = hash
		}
	}
	body, err := render.VPNIPsecEnvelope(tunnel)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleVPNIPsecCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNIPsecCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profiles[0])
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profiles[0])
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name

	if len(profiles) == 1 {
		result, err := s.vpnIPsecMcpSvc().CreateInline(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := renderMcpVPNIPsecMutation(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.vpnIPsecMcpSvc().CreateInline(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "vpn_ipsec_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleVPNIPsecUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNIPsecUpdateInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profiles[0])
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profiles[0])
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profiles[0])
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name

	if len(profiles) == 1 {
		result, err := s.vpnIPsecMcpSvc().UpdateInline(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := renderMcpVPNIPsecMutation(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.vpnIPsecMcpSvc().UpdateInline(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "vpn_ipsec_update", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleVPNIPsecDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNIPsecDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profiles[0])
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profiles[0])
	}

	if len(profiles) == 1 {
		result, err := s.vpnIPsecMcpSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := renderMcpVPNIPsecMutation(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.vpnIPsecMcpSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "vpn_ipsec_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func renderMcpVPNIPsecMutation(r *svc.VPNIPsecPushResult) ([]byte, error) {
	if r.DryRun {
		return render.PreviewEnvelope(r.Preview)
	}
	return render.VPNIPsecPushEnvelope(r)
}
