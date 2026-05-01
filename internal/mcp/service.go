package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type ServiceListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty" jsonschema_description:"Sophos filter Field:Criteria:Value"`
}
type ServiceShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}
type ServiceSearchInput struct {
	Profile string `json:"profile,omitempty"`
	Query   string `json:"query" jsonschema:"required" jsonschema_description:"Substring matched against Name and synthesized portRange"`
}
type ServiceUsageInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required"`
	WithReferences bool   `json:"with_references,omitempty"`
}

func (s *Server) registerService() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_list",
		Description: "List services with derived protocol/portRange. Returns sophosfw.v1.serviceList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List services"},
	}, s.handleServiceList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_show",
		Description: "Show one service by name. Returns sophosfw.v1.service envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show service"},
	}, s.handleServiceShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_search",
		Description: "Search services by Name or portRange substring. Returns sophosfw.v1.serviceSearch envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Search services"},
	}, s.handleServiceSearch)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "service_usage",
		Description: "ServicesStatistics for a service, optionally with reference graph. Returns sophosfw.v1.serviceUsage envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Service usage"},
	}, s.handleServiceUsage)
}

func (s *Server) serviceSvc() *svc.ServiceSvc {
	return &svc.ServiceSvc{Inner: s.objectSvc()}
}

func (s *Server) handleServiceList(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.serviceSvc().List(ctx, profile, filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ServiceListEnvelope("sophosfw.v1.serviceList", out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleServiceShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	v, err := s.serviceSvc().Get(ctx, profile, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ServiceEnvelope(v)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleServiceSearch(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceSearchInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.serviceSvc().Search(ctx, profile, in.Query)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ServiceListEnvelope("sophosfw.v1.serviceSearch", out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleServiceUsage(ctx context.Context, _ *sdkmcp.CallToolRequest, in ServiceUsageInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.serviceSvc().Usage(ctx, profile, in.Name, in.WithReferences)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ServiceUsageEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
