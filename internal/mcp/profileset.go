// Package mcp profileset.go: server-side helpers that translate the
// per-tool `profile` / `profileSet` Input fields into a list of target
// profiles, and render a *svc.FanoutResult as a sophosfw.v1.fanoutResult
// envelope tool result.
//
// MCP-side mirror of internal/cli/profileset.go. The CLI variant deals
// in cobra flags and human-vs-JSON output modes; the MCP variant works
// off raw Input strings and always emits JSON (MCP has no human text
// channel).
package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// AuthProfileSetListInput is the empty input for auth_profile_set_list.
type AuthProfileSetListInput struct{}

// registerProfileSet adds the read-only profile-set discovery tool.
// Profile set management (add/remove) stays CLI-only — agents can read
// groups but not mutate them.
func (s *Server) registerProfileSet() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "auth_profile_set_list",
		Description: "List defined profile sets (named groups of firewall profiles). Read-only; returns map of set name -> array of profile names. Use the set name as profileSet on a mutating tool to fan-out across all members.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List profile sets"},
	}, s.handleAuthProfileSetList)
}

// handleAuthProfileSetList returns the configured profileSets map under a
// sophosfw.v1.profileSetList envelope. The body is `{schema, sets}` where
// sets is map[name][]profile (may be nil if none are defined).
func (s *Server) handleAuthProfileSetList(_ context.Context, _ *sdkmcp.CallToolRequest, _ AuthProfileSetListInput) (*sdkmcp.CallToolResult, any, error) {
	out := map[string]any{
		"schema": "sophosfw.v1.profileSetList",
		"sets":   s.deps.Config.ProfileSets,
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	return jsonResult(body)
}

// resolveTargetProfilesMcp returns the ordered list of profile names a
// mutating tool should operate against. Inputs come straight from the
// tool's `profile` and `profileSet` fields. Both-set is rejected with
// ErrInvalidRequest. profileSet wins when set; otherwise the lone
// `profile` (or server default, via resolveProfile) is returned as a
// one-element slice — preserving the existing single-profile fast path.
func (s *Server) resolveTargetProfilesMcp(profile, profileSet string) ([]string, error) {
	if profile != "" && profileSet != "" {
		return nil, fmt.Errorf("%w: profile and profileSet are mutually exclusive", sophos.ErrInvalidRequest)
	}
	if profileSet != "" {
		return s.deps.Config.ResolveProfileSet(profileSet)
	}
	return []string{s.resolveProfile(profile)}, nil
}

// renderFanoutResult emits a *svc.FanoutResult as a sophosfw.v1.fanoutResult
// JSON envelope wrapped in an MCP tool result. Unlike the CLI's printFanout,
// MCP does not branch to a separate sentinel error: per-profile status is
// already encoded in the envelope (`status: "ok" | "error" | "skipped"`),
// so a successful fan-out tool call is one that returned an envelope —
// agents inspect `.results[*].status` for per-profile detail.
func (s *Server) renderFanoutResult(fr *svc.FanoutResult) (*sdkmcp.CallToolResult, any, error) {
	body, err := render.FanoutEnvelope(fr)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	return jsonResult(body)
}
