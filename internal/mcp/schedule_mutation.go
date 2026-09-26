package mcp

import (
	"context"
	"fmt"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

const scheduleBodyDescription = "the Schedule body. Required keys: Name, Type (must be Recurring), ScheduleDetails.ScheduleDetail (object or array of {Days, StartTime, StopTime}). Times are HH:MM on a 15-minute grid; StopTime may be 23:59; StartTime must be before StopTime (split periods at midnight)."

type ScheduleCreateInput struct {
	Profile    string         `json:"profile,omitempty"`
	ProfileSet string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name       string         `json:"name" jsonschema:"required" jsonschema_description:"the Schedule name"`
	Body       map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the Schedule body. Required keys: Name, Type (must be Recurring), ScheduleDetails.ScheduleDetail (object or array of {Days, StartTime, StopTime}). Times are HH:MM on a 15-minute grid; StopTime may be 23:59; StartTime must be before StopTime (split periods at midnight)."`
	Confirm    bool           `json:"confirm" jsonschema:"required" jsonschema_description:"must be true to apply"`
	DryRun     bool           `json:"dryRun,omitempty"`
}

type ScheduleUpdateInput struct {
	Profile                string         `json:"profile,omitempty"`
	ProfileSet             string         `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string         `json:"name" jsonschema:"required"`
	Body                   map[string]any `json:"body" jsonschema:"required" jsonschema_description:"the Schedule body. Required keys: Name, Type (must be Recurring), ScheduleDetails.ScheduleDetail (object or array of {Days, StartTime, StopTime}). Times are HH:MM on a 15-minute grid; StopTime may be 23:59; StartTime must be before StopTime (split periods at midnight)."`
	ExpectedDiffHash       string         `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of Schedule; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool           `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to push without supplying expectedDiffHash"`
	Confirm                bool           `json:"confirm" jsonschema:"required"`
	DryRun                 bool           `json:"dryRun,omitempty"`
}

type ScheduleDeleteInput struct {
	Profile                string `json:"profile,omitempty"`
	ProfileSet             string `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, confirm:true authorizes mutation across ALL profiles in the set."`
	Name                   string `json:"name" jsonschema:"required"`
	ExpectedDiffHash       string `json:"expectedDiffHash,omitempty" jsonschema_description:"hash from a prior object_get of Schedule; required unless ignoreExpectedDiffHash=true"`
	IgnoreExpectedDiffHash bool   `json:"ignoreExpectedDiffHash,omitempty" jsonschema_description:"set true to delete without supplying expectedDiffHash"`
	Confirm                bool   `json:"confirm" jsonschema:"required"`
	DryRun                 bool   `json:"dryRun,omitempty"`
}

func (s *Server) registerScheduleMutations() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "schedule_create", Description: "Create a new Schedule. Requires confirm: true. Use dryRun: true to preview without sending. " + scheduleBodyDescription,
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Create schedule"},
	}, s.handleScheduleCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "schedule_update", Description: "Update an existing Schedule. Requires confirm: true AND expectedDiffHash from a prior object_get of Schedule. Use dryRun: true to preview. " + scheduleBodyDescription,
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, Title: "Update schedule"},
	}, s.handleScheduleUpdate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name: "schedule_delete", Description: "Delete a Schedule by name. Requires confirm: true AND expectedDiffHash from a prior object_get of Schedule. Refused while any firewall rule references the schedule, or if the reference scan cannot complete.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptrBool(true), Title: "Delete schedule"},
	}, s.handleScheduleDelete)
}

func (s *Server) handleScheduleCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in ScheduleCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	if !in.Confirm {
		return s.errorEnvelopeResult(fmt.Errorf("%w: confirm: true is required to mutate", sophos.ErrInvalidRequest), profiles[0])
	}
	if err := validateScheduleMcpBodyName(in.Body, in.Name); err != nil {
		return s.errorEnvelopeResult(err, profiles[0])
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name
	if len(profiles) == 1 {
		result, err := s.scheduleSvc().Create(ctx, profiles[0], in.Name, in.Body, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.scheduleSvc().Create(ctx, profile, in.Name, in.Body, preflight || in.DryRun)
	}
	return s.renderFanoutResult(svc.Run(ctx, "schedule_create", profiles, op, in.DryRun))
}

func (s *Server) handleScheduleUpdate(ctx context.Context, _ *sdkmcp.CallToolRequest, in ScheduleUpdateInput) (*sdkmcp.CallToolResult, any, error) {
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
	if err := validateScheduleMcpBodyName(in.Body, in.Name); err != nil {
		return s.errorEnvelopeResult(err, profiles[0])
	}
	if in.Body == nil {
		in.Body = map[string]any{}
	}
	in.Body["Name"] = in.Name
	if len(profiles) == 1 {
		result, err := s.scheduleSvc().Update(ctx, profiles[0], in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.scheduleSvc().Update(ctx, profile, in.Name, in.Body, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	return s.renderFanoutResult(svc.Run(ctx, "schedule_update", profiles, op, in.DryRun))
}

func (s *Server) handleScheduleDelete(ctx context.Context, _ *sdkmcp.CallToolRequest, in ScheduleDeleteInput) (*sdkmcp.CallToolResult, any, error) {
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
		result, err := s.scheduleSvc().Delete(ctx, profiles[0], in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, in.DryRun)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return s.renderObjectMutation(result, profiles[0])
	}
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		return s.scheduleSvc().Delete(ctx, profile, in.Name, in.ExpectedDiffHash, in.IgnoreExpectedDiffHash, preflight || in.DryRun)
	}
	return s.renderFanoutResult(svc.Run(ctx, "schedule_delete", profiles, op, in.DryRun))
}

func validateScheduleMcpBodyName(body map[string]any, name string) error {
	if value, exists := body["Name"]; exists {
		bodyName, ok := value.(string)
		if !ok || strings.TrimSpace(bodyName) == "" {
			return fmt.Errorf("%w: body Name must be a non-empty string", sophos.ErrInvalidRequest)
		}
		if bodyName != name {
			return fmt.Errorf("%w: body Name %q does not match positional arg %q", sophos.ErrInvalidRequest, bodyName, name)
		}
	}
	return nil
}
