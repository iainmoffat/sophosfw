// Package mcp — VPNProfile MCP surface (Phase 15, Task 9).
//
// `vpn_ike_profile_list | vpn_ike_profile_show | vpn_ike_profile_create
// | vpn_ike_profile_update | vpn_ike_profile_delete` MCP tools over the
// body-as-map VPNProfileSvc. Mirrors `iphostgroup_mutation.go` for the
// three mutating tools and adds list/show modeled after T8's vpn_ipsec
// read surface (with the generic ObjectList/Object envelopes since
// VPNProfile has no type-specific envelope helpers).
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// VPNProfileListInput is the input for vpn_ike_profile_list.
type VPNProfileListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty"`
}

// VPNProfileShowInput is the input for vpn_ike_profile_show.
type VPNProfileShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}

// VPNProfileCreateInput is the create handler argument shape.
//
// Required body keys: Name, AuthenticationMode. The body Name must
// match the name argument (the handler force-sets it after the sanity
// check).
type VPNProfileCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the VPNProfile (IKE profile) name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the VPNProfile body as a JSON object. Required keys: Name, AuthenticationMode. The body Name must match the name argument. Use vpn_ike_profile_show on an existing profile to learn the shape."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

// VPNProfileUpdateInput is the update handler argument shape.
type VPNProfileUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name, AuthenticationMode."`
	ExpectedDiffHash       string         `json:"expectedDiffHash" jsonschema:"required" jsonschema_description:"hash from a prior vpn_ike_profile_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// VPNProfileDeleteInput is the delete handler argument shape.
type VPNProfileDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash" jsonschema:"required" jsonschema_description:"hash from a prior vpn_ike_profile_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerVPNProfile registers the five vpn_ike_profile_* tools. Called
// from server.registerAll().
func (s *Server) registerVPNProfile() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ike_profile_list",
		Description: "List IKE profiles (VPNProfile). Returns sophosfw.v1.objectList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List IKE profiles"},
	}, s.handleVPNProfileList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ike_profile_show",
		Description: "Get one VPNProfile by name. Response always includes _diffHash, which vpn_ike_profile_update and vpn_ike_profile_delete require as expectedDiffHash.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show IKE profile"},
	}, s.handleVPNProfileShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ike_profile_create",
		Description: "Create a new VPNProfile (IKE profile). Requires confirm: true. Use dryRun: true to preview without sending. Required body keys: Name, AuthenticationMode. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create IKE profile"},
	}, s.handleVPNProfileCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ike_profile_update",
		Description: "Update an existing VPNProfile. Requires confirm: true AND expectedDiffHash from a prior vpn_ike_profile_show (or ignoreExpectedDiffHash: true). Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update IKE profile"},
	}, s.handleVPNProfileUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_ike_profile_delete",
		Description: "Delete a VPNProfile by name. Requires confirm: true AND expectedDiffHash from a prior vpn_ike_profile_show (or ignoreExpectedDiffHash: true).",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete IKE profile"},
	}, s.handleVPNProfileDelete)
}

// vpnProfileSvc resolves a VPNProfileSvc from the server's deps.
func (s *Server) vpnProfileSvc() *svc.VPNProfileSvc {
	return &svc.VPNProfileSvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleVPNProfileList(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNProfileListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.objectSvc().List(ctx, profile, "VPNProfile", filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectListEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleVPNProfileShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNProfileShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	obj, err := s.objectSvc().Get(ctx, profile, "VPNProfile", in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	// ObjectSvc.Get already injects _diffHash for catalog-mutable types.
	// Defense in depth: re-inject if missing so agents can always rely
	// on it.
	if m, ok := obj.Data.(map[string]any); ok {
		if _, has := m["_diffHash"]; !has {
			hash, hashErr := svc.DiffHash(m)
			if hashErr != nil {
				return s.errorEnvelopeResult(hashErr, profile)
			}
			m["_diffHash"] = hash
		}
	}
	body, err := render.ObjectEnvelope(obj)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleVPNProfileCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNProfileCreateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.vpnProfileSvc().Create(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.vpnProfileSvc().Create(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "vpn_profile_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleVPNProfileUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNProfileUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.vpnProfileSvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.vpnProfileSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "vpn_profile_update", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleVPNProfileDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in VPNProfileDeleteInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.vpnProfileSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.vpnProfileSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "vpn_profile_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}
