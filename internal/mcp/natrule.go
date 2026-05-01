package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type NATRuleListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty"`
}
type NATRuleShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}

func (s *Server) registerNATRule() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "nat_rule_list", Description: "List NAT rules. Returns sophosfw.v1.natRuleList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List NAT rules"},
	}, s.handleNATRuleList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "nat_rule_show", Description: "Show one NAT rule by name. Returns sophosfw.v1.natRule envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show NAT rule"},
	}, s.handleNATRuleShow)
}

func (s *Server) natRuleSvc() *svc.NATRuleSvc {
	return &svc.NATRuleSvc{Inner: s.objectSvc()}
}

func (s *Server) handleNATRuleList(ctx context.Context, _ *sdkmcp.CallToolRequest, in NATRuleListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.natRuleSvc().List(ctx, profile, filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.NATRuleListEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleNATRuleShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in NATRuleShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	rule, err := s.natRuleSvc().Get(ctx, profile, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.NATRuleEnvelope(rule)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
