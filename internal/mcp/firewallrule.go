package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type FirewallRuleListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty"`
}
type FirewallRuleShowInput struct {
	Profile string `json:"profile,omitempty"`
	Name    string `json:"name" jsonschema:"required"`
}

func (s *Server) registerFirewallRule() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "firewall_rule_list", Description: "List firewall rules. Returns sophosfw.v1.firewallRuleList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List firewall rules"},
	}, s.handleFirewallRuleList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "firewall_rule_show", Description: "Show one firewall rule by name. Returns sophosfw.v1.firewallRule envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show firewall rule"},
	}, s.handleFirewallRuleShow)
}

func (s *Server) firewallRuleSvc() *svc.FirewallRuleSvc {
	return &svc.FirewallRuleSvc{Inner: s.objectSvc()}
}

func (s *Server) handleFirewallRuleList(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.firewallRuleSvc().List(ctx, profile, filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.FirewallRuleListEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleFirewallRuleShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	rule, err := s.firewallRuleSvc().Get(ctx, profile, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.FirewallRuleEnvelope(rule)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
