// Package mcp — ServiceGroup mutating MCP surface (Phase 12, Task 11).
//
// `service_group_create | service_group_update | service_group_delete` MCP
// tools over the body-as-map ServiceGroupSvc. Mechanical mirror of
// internal/mcp/fqdnhostgroup_mutation.go.
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ServiceGroupCreateInput is the create handler argument shape.
//
// Required body keys: Name. The body Name must match the name argument
// (the handler force-sets it after the sanity check).
type ServiceGroupCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the ServiceGroup name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the ServiceGroup body as a JSON object. Required keys: Name. Use object_get with objectType: \"ServiceGroup\" on an existing group to learn the shape (ServiceList holds member Service refs)."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

// ServiceGroupUpdateInput is the update handler argument shape. Mirrors
// FQDNHostGroupUpdateInput.
type ServiceGroupUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of ServiceGroup; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// ServiceGroupDeleteInput is the delete handler argument shape.
type ServiceGroupDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of ServiceGroup; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerServiceGroup registers the three service_group_* tools. Called
// from server.registerAll().
func (s *Server) registerServiceGroup() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_group_create",
		Description: "Create a new ServiceGroup. Requires confirm: true. Use dryRun: true to preview without sending. Required body keys: Name. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create service group"},
	}, s.handleServiceGroupCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_group_update",
		Description: "Update an existing ServiceGroup. Requires confirm: true AND expectedDiffHash from a prior object_get of ServiceGroup. Use dryRun: true to preview. Required body keys: Name.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update service group"},
	}, s.handleServiceGroupUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_group_delete",
		Description: "Delete a ServiceGroup by name. Requires confirm: true AND expectedDiffHash from a prior object_get of ServiceGroup.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete service group"},
	}, s.handleServiceGroupDelete)
}

// serviceGroupSvc resolves a ServiceGroupSvc from the server's deps.
// Mirrors fqdnHostGroupSvc on the MCP side.
func (s *Server) serviceGroupSvc() *svc.ServiceGroupSvc {
	return &svc.ServiceGroupSvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleServiceGroupCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceGroupCreateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.serviceGroupSvc().Create(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.serviceGroupSvc().Create(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "service_group_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleServiceGroupUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceGroupUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.serviceGroupSvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.serviceGroupSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "service_group_update", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleServiceGroupDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceGroupDeleteInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.serviceGroupSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.serviceGroupSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "service_group_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}
