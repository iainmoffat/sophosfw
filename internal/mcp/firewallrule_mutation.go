package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type FirewallRuleCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the rule name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the full FirewallRule body as a JSON object. Required top-level keys: Name, Status, IPFamily, PolicyType. The Name in body must match the name argument. Use firewall_rule_show on an existing rule to learn the shape."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

type FirewallRuleUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the edited body. Required keys same as create."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior firewall_rule_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

type FirewallRuleDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior firewall_rule_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

func (s *Server) handleFirewallRuleCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profiles[0])
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profiles[0])
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name

	if len(profiles) == 1 {
		result, err := s.firewallRuleSvc().CreateInline(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := renderMcpFirewallRuleMutation(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.firewallRuleSvc().CreateInline(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "firewall_rule_create", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleFirewallRuleUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleUpdateInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profiles[0])
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profiles[0])
	}
	if bn, _ := in.Body["Name"].(string); bn != "" && bn != in.Name {
		return s.errorEnvelopeResult(fmt.Errorf("%w: body Name %q does not match name argument %q", sophos.ErrInvalidRequest, bn, in.Name), profiles[0])
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name

	if len(profiles) == 1 {
		result, err := s.firewallRuleSvc().UpdateInline(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := renderMcpFirewallRuleMutation(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.firewallRuleSvc().UpdateInline(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "firewall_rule_push", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleFirewallRuleDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in FirewallRuleDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profiles[0])
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profiles[0])
	}

	if len(profiles) == 1 {
		result, err := s.firewallRuleSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := renderMcpFirewallRuleMutation(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.firewallRuleSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	fr := svc.Run(ctx, "firewall_rule_delete", profiles, op, in.DryRun)
	return s.renderFanoutResult(fr)
}

func renderMcpFirewallRuleMutation(r *svc.FirewallRulePushResult) ([]byte, error) {
	if r.DryRun {
		return render.PreviewEnvelope(r.Preview)
	}
	return render.FirewallRulePushEnvelope(r)
}
