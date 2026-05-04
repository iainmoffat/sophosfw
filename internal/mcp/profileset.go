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
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

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
