package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type HostIpListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty" jsonschema_description:"Sophos filter Field:Criteria:Value"`
}
type HostIpShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required" jsonschema_description:"Object name"`
}
type HostIpSearchInput struct {
	Profile string `json:"profile,omitempty"`
	Query   string `json:"query" jsonschema:"required" jsonschema_description:"Substring matched against Name, IPAddress, Subnet (case-insensitive)"`
}
type HostIpUsageInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required" jsonschema_description:"Object name"`
	WithReferences bool   `json:"with_references,omitempty" jsonschema_description:"When true, scan IPHostGroup/FirewallRule/NATRule for references and include them in the output"`
}

func (s *Server) registerHostIP() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_list",
		Description: "List IPHost objects with derived CIDR and kind. Returns sophosfw.v1.hostIpList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List IP hosts"},
	}, s.handleHostIpList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_show",
		Description: "Show one IP host object by name. Returns sophosfw.v1.hostIp envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show IP host"},
	}, s.handleHostIpShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_search",
		Description: "Multi-field substring search across IP hosts (Name, IPAddress, Subnet). Returns sophosfw.v1.hostIpSearch envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Search IP hosts"},
	}, s.handleHostIpSearch)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_usage",
		Description: "IPHostStatistics for a host, optionally with reference graph (rules + groups). Returns sophosfw.v1.hostIpUsage envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "IP host usage"},
	}, s.handleHostIpUsage)
}

func (s *Server) hostIpSvc() *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: s.objectSvc()}
}

func (s *Server) handleHostIpList(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.hostIpSvc().List(ctx, profile, filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.HostIPListEnvelope("sophosfw.v1.hostIpList", out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleHostIpShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	h, err := s.hostIpSvc().Get(ctx, profile, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.HostIPEnvelope(h)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleHostIpSearch(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpSearchInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.hostIpSvc().Search(ctx, profile, in.Query)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.HostIPListEnvelope("sophosfw.v1.hostIpSearch", out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleHostIpUsage(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpUsageInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.hostIpSvc().Usage(ctx, profile, in.Name, in.WithReferences)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.HostIPUsageEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
