// Package mcp — FQDNHostGroup mutating MCP surface (Phase 12, Task 8).
//
// `host_fqdn_group_create | host_fqdn_group_update | host_fqdn_group_delete` MCP tools
// over the body-as-map FQDNHostGroupSvc. Mechanical mirror of
// internal/mcp/iphostgroup_mutation.go.
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// FQDNHostGroupCreateInput is the create handler argument shape.
//
// Required body keys: Name, IPFamily. The body Name must match the name
// argument (the handler force-sets it after the sanity check).
type FQDNHostGroupCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the FQDNHostGroup name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the FQDNHostGroup body as a JSON object. Required keys: Name, IPFamily. The body Name must match the name argument. Use object_get with objectType: \"FQDNHostGroup\" on an existing group to learn the shape."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

// FQDNHostGroupUpdateInput is the update handler argument shape. Mirrors
// IPHostGroupUpdateInput.
type FQDNHostGroupUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name, IPFamily."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of FQDNHostGroup; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// FQDNHostGroupDeleteInput is the delete handler argument shape.
type FQDNHostGroupDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of FQDNHostGroup; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerFQDNHostGroup registers the three host_fqdn_group_* tools. Called
// from server.registerAll().
func (s *Server) registerFQDNHostGroup() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_fqdn_group_create",
		Description: "Create a new FQDNHostGroup. Requires confirm: true. Use dryRun: true to preview without sending. Required body keys: Name, IPFamily. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create FQDN host group"},
	}, s.handleFQDNHostGroupCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_fqdn_group_update",
		Description: "Update an existing FQDNHostGroup. Requires confirm: true AND expectedDiffHash from a prior object_get of FQDNHostGroup. Use dryRun: true to preview. Required body keys: Name, IPFamily.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update FQDN host group"},
	}, s.handleFQDNHostGroupUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_fqdn_group_delete",
		Description: "Delete a FQDNHostGroup by name. Requires confirm: true AND expectedDiffHash from a prior object_get of FQDNHostGroup.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete FQDN host group"},
	}, s.handleFQDNHostGroupDelete)
}

// fqdnHostGroupSvc resolves an FQDNHostGroupSvc from the server's deps.
// Mirrors iphostGroupSvc on the MCP side.
func (s *Server) fqdnHostGroupSvc() *svc.FQDNHostGroupSvc {
	return &svc.FQDNHostGroupSvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleFQDNHostGroupCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FQDNHostGroupCreateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.fqdnHostGroupSvc().Create(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.fqdnHostGroupSvc().Create(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "fqdn_host_group_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleFQDNHostGroupUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FQDNHostGroupUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.fqdnHostGroupSvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.fqdnHostGroupSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "fqdn_host_group_update", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleFQDNHostGroupDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in FQDNHostGroupDeleteInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.fqdnHostGroupSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.fqdnHostGroupSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "fqdn_host_group_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}
