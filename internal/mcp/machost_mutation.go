// Package mcp — MACHost mutating MCP surface (Phase 12, Task 9).
//
// `host_mac_create | host_mac_update | host_mac_delete` MCP tools
// over the body-as-map MACHostSvc. Mostly a mechanical mirror of
// internal/mcp/iphostgroup_mutation.go; MACHostSvc adds a client-side
// XOR validator for MACAddress vs MACAddressList.
package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// MACHostCreateInput is the create handler argument shape.
//
// Required body keys: Name, Type. Body must set EXACTLY ONE of
// MACAddress (string) or MACAddressList (list). Type is "MACAddress"
// or "MACList". The body Name must match the name argument (the
// handler force-sets it after the sanity check).
type MACHostCreateInput struct {
	Profile string         `json:"profile,omitempty"`
	Name    string         `json:"name" jsonschema:"required" jsonschema_description:"the MACHost name"`
	Body    map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the MACHost body as a JSON object. Required keys: Name, Type. Body must set exactly one of MACAddress (string) or MACAddressList (list of strings). Type is \"MACAddress\" or \"MACList\". The body Name must match the name argument. Use object_get with objectType: \"MACHost\" on an existing host to learn the shape."`
	Confirm bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun  bool           `json:"dryRun,omitempty"`
}

// MACHostUpdateInput is the update handler argument shape. Mirrors
// IPHostGroupUpdateInput.
type MACHostUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys: Name, Type. Body must set exactly one of MACAddress (string) or MACAddressList (list of strings). Type is \"MACAddress\" or \"MACList\"."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of MACHost; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

// MACHostDeleteInput is the delete handler argument shape.
type MACHostDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of MACHost; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

// registerMACHost registers the three host_mac_* tools. Called
// from server.registerAll().
func (s *Server) registerMACHost() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_mac_create",
		Description: "Create a new MACHost. Required body keys: Name, Type. Body must set exactly one of MACAddress (string) or MACAddressList (list). Type is \"MACAddress\" or \"MACList\". Requires confirm: true. Use dryRun: true to preview without sending. The body Name must match the name argument.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create MAC host"},
	}, s.handleMACHostCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_mac_update",
		Description: "Update an existing MACHost. Required body keys: Name, Type. Body must set exactly one of MACAddress (string) or MACAddressList (list). Requires confirm: true AND expectedDiffHash from a prior object_get of MACHost. Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update MAC host"},
	}, s.handleMACHostUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_mac_delete",
		Description: "Delete a MACHost by name. Requires confirm: true AND expectedDiffHash from a prior object_get of MACHost.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete MAC host"},
	}, s.handleMACHostDelete)
}

// macHostSvc resolves an MACHostSvc from the server's deps.
// Mirrors iphostGroupSvc on the MCP side.
func (s *Server) macHostSvc() *svc.MACHostSvc {
	return &svc.MACHostSvc{
		Inner: s.objectSvc(),
		Audit: s.deps.Audit,
	}
}

func (s *Server) handleMACHostCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in MACHostCreateInput) (*sdkmcp.CallToolResult, any, error) {
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

	result, err := s.macHostSvc().Create(ctx, profile, in.Name, in.Body, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}

func (s *Server) handleMACHostUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in MACHostUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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

	result, err := s.macHostSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}

func (s *Server) handleMACHostDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in MACHostDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	result, err := s.macHostSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return s.renderObjectMutation(result, profile)
}
