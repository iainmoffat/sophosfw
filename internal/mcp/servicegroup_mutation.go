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
	Profile string         `json:"profile,omitempty"`
	Name    string         `json:"name" jsonschema:"required" jsonschema_description:"the ServiceGroup name"`
	Body    map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the ServiceGroup body as a JSON object. Required keys: Name. Use object_get with objectType: \"ServiceGroup\" on an existing group to learn the shape (ServiceList holds member Service refs)."`
	Confirm bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun  bool           `json:"dryRun,omitempty"`
}

// ServiceGroupUpdateInput is the update handler argument shape. Mirrors
// FQDNHostGroupUpdateInput.
type ServiceGroupUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
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
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profile)
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name

	result, err := s.serviceGroupSvc().Create(ctx, profile, in.Name, in.Body, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}

func (s *Server) handleServiceGroupUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceGroupUpdateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profile)
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name

	result, err := s.serviceGroupSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}

func (s *Server) handleServiceGroupDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceGroupDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	result, err := s.serviceGroupSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}
