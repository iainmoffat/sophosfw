package mcp

import (
	"context"
	"encoding/json"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/sophos"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ObjectListInput is the input schema for object_list.
type ObjectListInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required" jsonschema_description:"Catalog tag or alias (e.g. IPHost, FQDNHost, FirewallRule)"`
	Filter  string `json:"filter,omitempty" jsonschema_description:"Sophos filter in Field:Criteria:Value form (e.g. Name:like:LAN)"`
}

// ObjectGetInput is the input schema for object_get.
type ObjectGetInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required" jsonschema_description:"Catalog tag or alias"`
	Name    string `json:"name" jsonschema:"required" jsonschema_description:"Object name"`
}

// ObjectSearchInput is the input schema for object_search.
type ObjectSearchInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required" jsonschema_description:"Catalog tag or alias"`
	Query   string `json:"query" jsonschema:"required" jsonschema_description:"Substring to match against the Name field of records (case-insensitive)"`
}

// ObjectUsageInput is the input schema for object_usage.
type ObjectUsageInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
	Tag     string `json:"tag" jsonschema:"required" jsonschema_description:"Catalog tag or alias"`
	Name    string `json:"name" jsonschema:"required" jsonschema_description:"Object name"`
}

func (s *Server) registerObject() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_list",
		Description: "Generic catalog list. Returns sophosfw.v1.objectList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List objects (generic)"},
	}, s.handleObjectList)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_get",
		Description: "Generic catalog get-by-name. Returns sophosfw.v1.object envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get object (generic)"},
	}, s.handleObjectGet)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_search",
		Description: "Generic catalog Name-substring search. Pulls all records of the tag and filters client-side. Returns sophosfw.v1.objectList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Search objects by Name"},
	}, s.handleObjectSearch)

	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "object_usage",
		Description: "Generic catalog usage query (object's *Statistics tag). Returns sophosfw.v1.objectUsage envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Object usage (generic)"},
	}, s.handleObjectUsage)
}

func (s *Server) objectSvc() *svc.ObjectSvc {
	return &svc.ObjectSvc{
		Config: s.deps.Config, Creds: s.deps.Creds, Catalog: s.deps.Catalog, NewClient: s.deps.NewClient,
	}
}

func (s *Server) handleObjectList(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	var filter *sophos.FilterClause
	if in.Filter != "" {
		f, err := sophos.ParseFilterFlag(in.Filter)
		if err != nil {
			return s.errorEnvelopeResult(err, profile)
		}
		filter = &f
	}
	out, err := s.objectSvc().List(ctx, profile, in.Tag, filter)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectListEnvelope(out)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleObjectGet(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectGetInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	obj, err := s.objectSvc().Get(ctx, profile, in.Tag, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectEnvelope(obj)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleObjectSearch(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectSearchInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	all, err := s.objectSvc().List(ctx, profile, in.Tag, nil)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	q := strings.ToLower(in.Query)
	filtered := &svc.ObjectList{Profile: all.Profile, Tag: all.Tag, Filter: nil}
	for _, item := range all.Items {
		// Each item is either a typed struct or map[string]any. Get a Name string.
		name := nameOf(item)
		if name != "" && strings.Contains(strings.ToLower(name), q) {
			filtered.Items = append(filtered.Items, item)
		}
	}
	filtered.Count = len(filtered.Items)
	if filtered.Items == nil {
		filtered.Items = []any{}
	}
	body, err := render.ObjectListEnvelope(filtered)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

// nameOf extracts the "Name" field from a catalog item. Items can be typed
// structs (e.g. catalog.IPHost) or generic map[string]any. The JSON approach
// avoids reflection and works for both shapes.
func nameOf(item any) string {
	if m, ok := item.(map[string]any); ok {
		if n, ok := m["Name"].(string); ok {
			return n
		}
		return ""
	}
	b, err := json.Marshal(item)
	if err != nil {
		return ""
	}
	var n struct{ Name string }
	if err := json.Unmarshal(b, &n); err != nil {
		return ""
	}
	return n.Name
}

func (s *Server) handleObjectUsage(ctx context.Context, _ *sdkmcp.CallToolRequest, in ObjectUsageInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	u, err := s.objectSvc().Usage(ctx, profile, in.Tag, in.Name)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.ObjectUsageEnvelope(u)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}
