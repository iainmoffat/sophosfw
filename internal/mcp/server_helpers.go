package mcp

import (
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// resolveProfile returns the input's Profile if non-empty, otherwise the
// server's DefaultProfile. The svc layer receives whatever this returns; if
// it's still empty, AuthSvc/ProfileSvc/etc. fall back to the config's
// currentProfile.
func (s *Server) resolveProfile(input string) string {
	if input != "" {
		return input
	}
	return s.deps.DefaultProfile
}

// jsonResult wraps a JSON byte slice as an MCP tool result with one text
// content item. The triple-return (result, any, error) matches the SDK's
// handler signature; the second slot (structured content) is unused — body
// text is sufficient for our envelope shape.
func jsonResult(body []byte) (*sdkmcp.CallToolResult, any, error) {
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{
			&sdkmcp.TextContent{Text: string(body)},
		},
	}, nil, nil
}

// errorEnvelopeResult renders a sophosfw.v1.error envelope as a tool result
// body. Per the design spec section 6.2, business errors (not_found,
// auth_failed, etc.) are returned as IsError=false success bodies; the
// envelope's `kind` field tells the agent what went wrong. The SDK's
// IsError=true channel is reserved for SDK-detected failures (schema
// validation, panics).
func (s *Server) errorEnvelopeResult(err error, profile string) (*sdkmcp.CallToolResult, any, error) {
	kind := svc.ErrorKind(err)
	body, mErr := render.ErrorEnvelope(kind, err.Error(), profile)
	if mErr != nil {
		// Fallback: if envelope construction itself fails, surface as IsError=true
		// since we have nothing else useful to return.
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: mErr.Error()}},
			IsError: true,
		}, nil, nil
	}
	return jsonResult(body)
}

// ptrBool returns a pointer to b. Useful for the SDK's *bool annotation
// fields like ReadOnlyHint.
func ptrBool(b bool) *bool { return &b }
