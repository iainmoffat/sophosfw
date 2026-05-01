package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// AuthStatusInput is the input schema for auth_status.
type AuthStatusInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default or config currentProfile"`
}

// AuthTestInput is the input schema for auth_test.
type AuthTestInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default or config currentProfile"`
}

// AuthProfileListInput is the empty input for auth_profile_list.
type AuthProfileListInput struct{}

// AuthProfileCurrentInput is the empty input for auth_profile_current.
type AuthProfileCurrentInput struct{}

func (s *Server) registerAuth() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_status",
		Description: "Show current profile, URL, and whether credentials are stored. Returns sophosfw.v1.authStatus envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Auth status"},
	}, s.handleAuthStatus)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_test",
		Description: "Test connectivity and stored credentials against the firewall. Performs a network round-trip. Returns sophosfw.v1.connectionTest envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Test firewall connection"},
	}, s.handleAuthTest)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_profile_list",
		Description: "List all configured profiles. Returns sophosfw.v1.profileList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List profiles"},
	}, s.handleAuthProfileList)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_profile_current",
		Description: "Return the currently active profile (single-entry profile list). Returns sophosfw.v1.profileList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Current profile"},
	}, s.handleAuthProfileCurrent)
}

func (s *Server) authSvc() *svc.AuthSvc {
	return &svc.AuthSvc{
		Config:    s.deps.Config,
		Creds:     s.deps.Creds,
		BaseDir:   "", // BaseDir not needed for read-only Status/Test
		NewClient: s.deps.NewClient,
	}
}

func (s *Server) profileSvc() *svc.ProfileSvc {
	return &svc.ProfileSvc{
		Config:  s.deps.Config,
		Creds:   s.deps.Creds,
		BaseDir: "", // BaseDir not needed for List
	}
}

func (s *Server) handleAuthStatus(ctx context.Context, _ *sdkmcp.CallToolRequest, in AuthStatusInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	st, err := s.authSvc().Status(profile)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.AuthStatusEnvelope(st)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleAuthTest(ctx context.Context, _ *sdkmcp.CallToolRequest, in AuthTestInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	r, err := s.authSvc().Test(ctx, profile)
	if err != nil {
		// AuthSvc.Test returns ConnectionResult even on failure; render it.
		body, mErr := render.ConnectionTestEnvelope(r)
		if mErr != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		return jsonResult(body)
	}
	body, err := render.ConnectionTestEnvelope(r)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleAuthProfileList(ctx context.Context, _ *sdkmcp.CallToolRequest, _ AuthProfileListInput) (*sdkmcp.CallToolResult, any, error) {
	list := s.profileSvc().List()
	body, err := render.ProfileListEnvelope(s.deps.Config.CurrentProfile, list)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	return jsonResult(body)
}

func (s *Server) handleAuthProfileCurrent(ctx context.Context, _ *sdkmcp.CallToolRequest, _ AuthProfileCurrentInput) (*sdkmcp.CallToolResult, any, error) {
	all := s.profileSvc().List()
	current := s.deps.Config.CurrentProfile
	out := make([]svc.ProfileInfo, 0, 1)
	for _, p := range all {
		if p.Name == current {
			out = append(out, p)
			break
		}
	}
	body, err := render.ProfileListEnvelope(current, out)
	if err != nil {
		return s.errorEnvelopeResult(err, current)
	}
	return jsonResult(body)
}
