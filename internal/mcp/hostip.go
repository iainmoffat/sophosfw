package mcp

import (
	"context"
	"fmt"

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
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_create",
		Description: "Create a new IPHost. Requires confirm: true. Use dryRun: true to preview without applying. Returns sophosfw.v1.hostIpMutation on apply or sophosfw.v1.preview on dry-run.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create IP host"},
	}, s.handleHostIpCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_update",
		Description: "Update an existing IPHost. Requires confirm: true AND expectedDiffHash from a prior host_ip_show. Use dryRun: true to preview.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update IP host"},
	}, s.handleHostIpUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "host_ip_delete",
		Description: "Delete an IPHost by name. Requires confirm: true AND expectedDiffHash from a prior host_ip_show.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete IP host"},
	}, s.handleHostIpDelete)
}

func (s *Server) hostIpSvc() *svc.HostIPSvc {
	return &svc.HostIPSvc{Inner: s.objectSvc(), Audit: s.deps.Audit}
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
	hash, hashErr := svc.DiffHash(h.IPHost)
	if hashErr != nil {
		return s.errorEnvelopeResult(hashErr, profile)
	}
	body, err := render.HostIPEnvelopeWithDiffHash(h, hash)
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

type HostIpCreateInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required" jsonschema_description:"object name"`
	IpFamily       string `json:"ipFamily,omitempty"`
	HostType       string `json:"hostType" jsonschema:"required" jsonschema_description:"Network|IP|IPRange|IPList"`
	IpAddress      string `json:"ipAddress,omitempty"`
	Subnet         string `json:"subnet,omitempty"`
	StartIpAddress string `json:"startIpAddress,omitempty"`
	EndIpAddress   string `json:"endIpAddress,omitempty"`
	IpAddressList  string `json:"ipAddressList,omitempty"`
	Confirm        bool   `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun         bool   `json:"dryRun,omitempty"`
}

type HostIpUpdateInput struct {
	HostIpCreateInput
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior host_ip_show; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
}

type HostIpDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

func (s *Server) handleHostIpCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	input := svc.HostIPCreateInput{
		Name: in.Name, IPFamily: in.IpFamily, HostType: in.HostType,
		IPAddress: in.IpAddress, Subnet: in.Subnet,
		StartIPAddress: in.StartIpAddress, EndIPAddress: in.EndIpAddress,
		IPAddressList: in.IpAddressList,
	}
	result, err := s.hostIpSvc().Create(ctx, profile, input, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpHostIpMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleHostIpUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpUpdateInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	input := svc.HostIPCreateInput{
		Name: in.Name, IPFamily: in.IpFamily, HostType: in.HostType,
		IPAddress: in.IpAddress, Subnet: in.Subnet,
		StartIPAddress: in.StartIpAddress, EndIPAddress: in.EndIpAddress,
		IPAddressList: in.IpAddressList,
	}
	result, err := s.hostIpSvc().Update(ctx, profile, input, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpHostIpMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleHostIpDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in HostIpDeleteInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profile)
	}
	if in.ExpectedDiffHash == "" && !in.IgnoreExpectedDiffHash {
		return s.errorEnvelopeResult(fmt.Errorf("%w: expectedDiffHash is required (or set ignoreExpectedDiffHash: true)", sophos.ErrInvalidRequest), profile)
	}
	result, err := s.hostIpSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := renderMcpHostIpMutation(result)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func renderMcpHostIpMutation(r *svc.HostIPMutationResult) ([]byte, error) {
	if r.DryRun {
		return render.PreviewEnvelope(r.Preview)
	}
	return render.HostIpMutationEnvelope(r)
}
