package mcp

import (
	"context"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

type ScheduleListInput struct {
	Profile string `json:"profile,omitempty"`
	Filter  string `json:"filter,omitempty" jsonschema_description:"Field:Criteria:Value"`
}

type ScheduleShowInput struct {
	Profile        string `json:"profile,omitempty"`
	Name           string `json:"name" jsonschema:"required"`
	WithReferences bool   `json:"withReferences,omitempty" jsonschema_description:"When true, scan FirewallRule records for this schedule and include them beside the record"`
}

func (s *Server) registerSchedule() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "schedule_list", Description: "List schedules. Returns sophosfw.v1.scheduleList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List schedules"},
	}, s.handleScheduleList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "schedule_show", Description: "Show one schedule by name. Optionally include firewall rule references. Returns sophosfw.v1.schedule envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Show schedule"},
	}, s.handleScheduleShow)
	s.registerScheduleMutations()
}

func (s *Server) scheduleSvc() *svc.ScheduleSvc {
	return &svc.ScheduleSvc{Inner: s.objectSvc(), Audit: s.deps.Audit}
}

func (s *Server) handleScheduleList(ctx context.Context, _ *sdkmcp.CallToolRequest, in ScheduleListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.scheduleSvc().List(ctx, profile, filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ScheduleListEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleScheduleShow(ctx context.Context, _ *sdkmcp.CallToolRequest, in ScheduleShowInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	out, err := s.scheduleSvc().Show(ctx, profile, in.Name, in.WithReferences)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ScheduleShowEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
