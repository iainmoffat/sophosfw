// Package mcp — FQDNHost mutating MCP surface (Phase 12, Task 7).
//
// `host_fqdn_create | host_fqdn_update | host_fqdn_delete` MCP tools
// over the body-as-map FQDNHostSvc. Mechanical mirror of
// internal/mcp/iphostgroup_mutation.go.
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// FQDNHostCreateInput is the create handler argument shape.
//
// Required body keys: Name, FQDN, IPFamily. Wildcard FQDNs
// (*.example.com) are accepted. The body Name must match the name
// argument (the handler force-sets it after the sanity check).
type FQDNHostCreateInput struct {
	Profile string         `json:"profile,omitempty"`
	Name    string         `json:"name" jsonschema:"required" jsonschema_description:"the FQDNHost name"`
	Body    map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the FQDNHost body as a JSON object. Required keys: Name, FQDN, IPFamily. Wildcard FQDNs (*.example.com) are accepted. The body Name must match the name argument. Use object_get with objectType: \"FQDNHost\" on an existing host to learn the shape."`
	Confirm bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun  bool           `json:"dryRun,omitempty"`
}

// FQDNHostUpdateInput is the update handler argument shape. Mirrors
// IPHostGroupUpdateInput.
type FQDNHostUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name, FQDN, IPFamily. Wildcard FQDNs (*.example.com) are accepted."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of FQDNHost; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// FQDNHostDeleteInput is the delete handler argument shape.
type FQDNHostDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of FQDNHost; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerFQDNHost registers the three host_fqdn_* tools. Called
// from server.registerAll().
func (s *Server) registerFQDNHost() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_fqdn_create",
		Description: "Create a new FQDNHost. Requires confirm: true. Use dryRun: true to preview without sending. Required body keys: Name, FQDN, IPFamily. Wildcard FQDNs (*.example.com) are accepted. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create FQDN host"},
	}, s.handleFQDNHostCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_fqdn_update",
		Description: "Update an existing FQDNHost. Requires confirm: true AND expectedDiffHash from a prior object_get of FQDNHost. Use dryRun: true to preview. Required body keys: Name, FQDN, IPFamily. Wildcard FQDNs (*.example.com) are accepted.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update FQDN host"},
	}, s.handleFQDNHostUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_fqdn_delete",
		Description: "Delete a FQDNHost by name. Requires confirm: true AND expectedDiffHash from a prior object_get of FQDNHost.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete FQDN host"},
	}, s.handleFQDNHostDelete)
}

// fqdnHostSvc resolves an FQDNHostSvc from the server's deps.
// Mirrors iphostGroupSvc on the MCP side.
func (s *Server) fqdnHostSvc() *svc.FQDNHostSvc {
	return &svc.FQDNHostSvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleFQDNHostCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FQDNHostCreateInput) (*sdkmcp.CallToolResult, any, error) {
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

	result, err := s.fqdnHostSvc().Create(ctx, profile, in.Name, in.Body, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}

func (s *Server) handleFQDNHostUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FQDNHostUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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

	result, err := s.fqdnHostSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}

func (s *Server) handleFQDNHostDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in FQDNHostDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	result, err := s.fqdnHostSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}
