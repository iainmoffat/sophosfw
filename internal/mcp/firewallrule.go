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
		Name: "firewall_rule_show", Description: "Get one FirewallRule by name. Response always includes _diffHash, which firewall_rule_update and firewall_rule_delete require as expectedDiffHash.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show firewall rule"},
	}, s.handleFirewallRuleShow)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "firewall_rule_create",
		Description: "Create a new FirewallRule. Requires confirm: true. Use dryRun: true to preview the envelope without sending. Returns sophosfw.v1.firewallRulePush on apply or sophosfw.v1.preview on dry-run. The body must include Name, Status, IPFamily, PolicyType plus a NetworkPolicy object.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create firewall rule"},
	}, s.handleFirewallRuleCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "firewall_rule_update",
		Description: "Update an existing FirewallRule. Requires confirm: true AND expectedDiffHash from a prior firewall_rule_show. Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update firewall rule"},
	}, s.handleFirewallRuleUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "firewall_rule_delete",
		Description: "Delete a FirewallRule by name. Requires confirm: true AND expectedDiffHash from a prior firewall_rule_show.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete firewall rule"},
	}, s.handleFirewallRuleDelete)
}

func (s *Server) firewallRuleSvc() *svc.FirewallRuleSvc {
	return &svc.FirewallRuleSvc{
		Inner:   s.objectSvc(),
		Audit:   s.deps.Audit,
		BaseDir: s.deps.BaseDir,
	}
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
	// Phase 10: include _diffHash in show response so agents can use it
	// for firewall_rule_update / firewall_rule_delete.
	if rule != nil {
		hash, hashErr := svc.DiffHash(rule)
		if hashErr != nil {
			return s.errorEnvelopeResult(hashErr, profile)
		}
		rule["_diffHash"] = hash
	}
	body, err := render.FirewallRuleEnvelope(rule)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
