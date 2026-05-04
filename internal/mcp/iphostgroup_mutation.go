// Package mcp — IPHostGroup mutating MCP surface (Phase 12, Task 6).
//
// `host_group_create | host_group_update | host_group_delete` MCP tools
// over the body-as-map IPHostGroupSvc. Canonical template for the other
// Phase 12 per-type MCP files; subsequent types substitute names per
// the table in docs/superpowers/plans/2026-05-03-sophosfw-phase12.md.
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// IPHostGroupCreateInput is the create handler argument shape.
//
// Required body keys: Name, IPFamily. The body Name must match the
// name argument (the handler force-sets it after the sanity check).
type IPHostGroupCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the IPHostGroup name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the IPHostGroup body as a JSON object. Required keys: Name, IPFamily. The body Name must match the name argument. Use object_get with objectType: \"IPHostGroup\" on an existing group to learn the shape."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

// IPHostGroupUpdateInput is the update handler argument shape. Mirrors
// FirewallRuleUpdateInput.
type IPHostGroupUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name, IPFamily."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of IPHostGroup; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// IPHostGroupDeleteInput is the delete handler argument shape.
type IPHostGroupDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of IPHostGroup; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerIPHostGroup registers the three host_group_* tools. Called
// from server.registerAll().
func (s *Server) registerIPHostGroup() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_group_create",
		Description: "Create a new IPHostGroup. Requires confirm: true. Use dryRun: true to preview without sending. Required body keys: Name, IPFamily. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create IP host group"},
	}, s.handleIPHostGroupCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_group_update",
		Description: "Update an existing IPHostGroup. Requires confirm: true AND expectedDiffHash from a prior object_get of IPHostGroup. Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update IP host group"},
	}, s.handleIPHostGroupUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_group_delete",
		Description: "Delete an IPHostGroup by name. Requires confirm: true AND expectedDiffHash from a prior object_get of IPHostGroup.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete IP host group"},
	}, s.handleIPHostGroupDelete)
}

// iphostGroupSvc resolves an IPHostGroupSvc from the server's deps.
// Mirrors firewallRuleSvc / hostIpSvc on the MCP side.
func (s *Server) iphostGroupSvc() *svc.IPHostGroupSvc {
	return &svc.IPHostGroupSvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleIPHostGroupCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPHostGroupCreateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.iphostGroupSvc().Create(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.iphostGroupSvc().Create(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "ip_host_group_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleIPHostGroupUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPHostGroupUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.iphostGroupSvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.iphostGroupSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "ip_host_group_update", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleIPHostGroupDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in IPHostGroupDeleteInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.iphostGroupSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.iphostGroupSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "ip_host_group_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

// renderObjectMutation is the shared MCP renderer for
// ObjectMutationResult. Dry-run paths emit a sophosfw.v1.preview
// envelope; apply paths emit the per-type ObjectMutationEnvelope. Used
// by all six Phase 12 per-type MCP files.
func (s *Server) renderObjectMutation(r *svc.ObjectMutationResult, profile string) (*sdkmcp.CallToolResult, any, error) {
	if r.DryRun {
		body, err := render.PreviewEnvelope(r.Preview)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		return jsonResult(body)
	}
	body, err := render.ObjectMutationEnvelope(r)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
