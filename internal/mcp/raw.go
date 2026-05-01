package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type RawGetInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
	XmlTag  string `json:"xmlTag" jsonschema:"required" jsonschema_description:"Sophos XML tag (e.g. IPHost, Zone, FirewallRule)"`
}

func (s *Server) registerRaw() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "raw_get",
		Description: "Issue <Get><tag></tag></Get> for any XML tag, including those without catalog typed parsers. Returns sophosfw.v1.rawResponse envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Raw API get"},
	}, s.handleRawGet)
}

func (s *Server) rawSvc() *svc.RawSvc {
	return &svc.RawSvc{Config: s.deps.Config, Creds: s.deps.Creds, NewClient: s.deps.NewClient}
}

func (s *Server) handleRawGet(ctx context.Context, _ *sdkmcp.CallToolRequest, in RawGetInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	r, err := s.rawSvc().Get(ctx, profile, in.XmlTag)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.RawResponseEnvelope(r)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
