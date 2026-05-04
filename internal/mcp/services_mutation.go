// Package mcp — Services mutating MCP surface (Phase 12, Task 10).
//
// `service_create | service_update | service_delete` MCP tools over
// the body-as-map ServicesSvc. Mechanical mirror of
// internal/mcp/fqdnhost_mutation.go.
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ServicesCreateInput is the create handler argument shape.
//
// Required body keys: Name, Type, ServiceDetails. Type is one of
// "TCPorUDP", "IP", "ICMP", "ICMPv6". The shape of ServiceDetails
// varies by Type — call object_get with objectType: "Services" on an
// existing service to learn the schema. The body Name must match the
// name argument (the handler force-sets it after the sanity check).
type ServicesCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the Service name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the Service body as a JSON object. Required keys: Name, Type, ServiceDetails. Type is one of TCPorUDP, IP, ICMP, ICMPv6. ServiceDetails shape varies by Type — call object_get with objectType: \"Services\" on an existing service to learn the schema. The body Name must match the name argument."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

// ServicesUpdateInput is the update handler argument shape. Mirrors
// FQDNHostUpdateInput.
type ServicesUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name, Type, ServiceDetails. ServiceDetails shape varies by Type."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of Services; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// ServicesDeleteInput is the delete handler argument shape.
type ServicesDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of Services; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerServices registers the three service_* tools. Called from
// server.registerAll().
func (s *Server) registerServices() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_create",
		Description: "Create a new Service. Required body keys: Name, Type, ServiceDetails. Type is \"TCPorUDP\", \"IP\", \"ICMP\", or \"ICMPv6\". The shape of ServiceDetails varies by Type — call object_get with objectType: \"Services\" on an existing service to learn the schema. Requires confirm: true. Use dryRun: true to preview without sending. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create service"},
	}, s.handleServicesCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_update",
		Description: "Update an existing Service. Requires confirm: true AND expectedDiffHash from a prior object_get of Services. Use dryRun: true to preview. Required body keys: Name, Type, ServiceDetails. ServiceDetails shape varies by Type.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update service"},
	}, s.handleServicesUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_delete",
		Description: "Delete a Service by name. Requires confirm: true AND expectedDiffHash from a prior object_get of Services.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete service"},
	}, s.handleServicesDelete)
}

// servicesSvc resolves a ServicesSvc from the server's deps.
// Mirrors fqdnHostSvc on the MCP side.
func (s *Server) servicesSvc() *svc.ServicesSvc {
	return &svc.ServicesSvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleServicesCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServicesCreateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.servicesSvc().Create(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.servicesSvc().Create(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "services_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleServicesUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServicesUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.servicesSvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.servicesSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "services_update", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleServicesDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServicesDeleteInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.servicesSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.servicesSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "services_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}
