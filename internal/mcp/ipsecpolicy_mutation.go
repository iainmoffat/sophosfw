// Package mcp — IPsecPolicy MCP surface (Phase 15, Task 9).
//
// `vpn_policy_list | vpn_policy_show | vpn_policy_create |
// vpn_policy_update | vpn_policy_delete` MCP tools over the body-as-map
// IPsecPolicySvc. Mirrors `iphostgroup_mutation.go` for the three
// mutating tools and adds list/show modeled after T8's vpn_ipsec read
// surface (with the generic ObjectList/Object envelopes since
// IPsecPolicy has no type-specific envelope helpers).
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// IPsecPolicyListInput is the input for vpn_policy_list.
type IPsecPolicyListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty"`
}

// IPsecPolicyShowInput is the input for vpn_policy_show.
type IPsecPolicyShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}

// IPsecPolicyCreateInput is the create handler argument shape.
//
// Required body keys: Name. The body Name must match the name argument
// (the handler force-sets it after the sanity check).
type IPsecPolicyCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the IPsecPolicy name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the IPsecPolicy body as a JSON object. Required keys: Name. The body Name must match the name argument. Use vpn_policy_show on an existing policy to learn the shape."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

// IPsecPolicyUpdateInput is the update handler argument shape.
type IPsecPolicyUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name."`
	ExpectedDiffHash       string         `json:"expectedDiffHash" jsonschema:"required" jsonschema_description:"hash from a prior vpn_policy_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// IPsecPolicyDeleteInput is the delete handler argument shape.
type IPsecPolicyDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash" jsonschema:"required" jsonschema_description:"hash from a prior vpn_policy_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerIPsecPolicy registers the five vpn_policy_* tools. Called
// from server.registerAll().
func (s *Server) registerIPsecPolicy() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_policy_list",
		Description: "List IPsec policies (IPsecPolicy). Returns sophosfw.v1.objectList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List IPsec policies"},
	}, s.handleIPsecPolicyList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_policy_show",
		Description: "Get one IPsecPolicy by name. Response always includes _diffHash, which vpn_policy_update and vpn_policy_delete require as expectedDiffHash.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show IPsec policy"},
	}, s.handleIPsecPolicyShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_policy_create",
		Description: "Create a new IPsecPolicy. Requires confirm: true. Use dryRun: true to preview without sending. Required body keys: Name. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create IPsec policy"},
	}, s.handleIPsecPolicyCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_policy_update",
		Description: "Update an existing IPsecPolicy. Requires confirm: true AND expectedDiffHash from a prior vpn_policy_show (or ignoreExpectedDiffHash: true). Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update IPsec policy"},
	}, s.handleIPsecPolicyUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "vpn_policy_delete",
		Description: "Delete an IPsecPolicy by name. Requires confirm: true AND expectedDiffHash from a prior vpn_policy_show (or ignoreExpectedDiffHash: true).",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete IPsec policy"},
	}, s.handleIPsecPolicyDelete)
}

// ipsecPolicySvc resolves an IPsecPolicySvc from the server's deps.
func (s *Server) ipsecPolicySvc() *svc.IPsecPolicySvc {
	return &svc.IPsecPolicySvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleIPsecPolicyList(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPsecPolicyListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.objectSvc().List(ctx, profile, "IPsecPolicy", filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectListEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleIPsecPolicyShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPsecPolicyShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	obj, err := s.objectSvc().Get(ctx, profile, "IPsecPolicy", in.Name)
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

func (s *Server) handleIPsecPolicyCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPsecPolicyCreateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.ipsecPolicySvc().Create(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.ipsecPolicySvc().Create(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "ipsec_policy_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleIPsecPolicyUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPsecPolicyUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.ipsecPolicySvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.ipsecPolicySvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "ipsec_policy_update", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleIPsecPolicyDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPsecPolicyDeleteInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.ipsecPolicySvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.ipsecPolicySvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "ipsec_policy_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}
