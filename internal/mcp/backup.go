// Package mcp backup.go: MCP tools for backup_create, backup_list,
// drift_check.
//
// All three are tagged ReadOnlyHint:true. The firewall is never mutated
// by these tools; backup_create writes a per-record YAML tree to local
// disk but does not change firewall state. backup_rotate is intentionally
// CLI-only — exposing destructive filesystem ops to agents widens the
// surface for low value.
package mcp

import (
	"context"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/render"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// BackupCreateInput is the input schema for backup_create.
type BackupCreateInput struct {
	Profile    string   `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
	ProfileSet string   `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, snapshots are produced for every profile in the set; result is a sophosfw.v1.fanoutResult envelope."`
	Out        string   `json:"out,omitempty" jsonschema_description:"snapshot directory; default: <baseDir>/profiles/<profile>/backups/<utc>"`
	Types      []string `json:"types,omitempty" jsonschema_description:"catalog tags to include (default: all). Mutually exclusive with exclude."`
	Exclude    []string `json:"exclude,omitempty" jsonschema_description:"catalog tags to skip. Mutually exclusive with types."`
}

// BackupListInput is the input schema for backup_list.
type BackupListInput struct {
	Profile string `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
}

// DriftCheckInput is the input schema for drift_check.
type DriftCheckInput struct {
	Profile    string   `json:"profile,omitempty" jsonschema_description:"Profile name; defaults to server default"`
	ProfileSet string   `json:"profileSet,omitempty" jsonschema_description:"named profile group OR comma-separated profile list; mutually exclusive with profile. When set, drift is checked for every profile in the set; result is a sophosfw.v1.fanoutResult envelope."`
	Snapshot   string   `json:"snapshot,omitempty" jsonschema_description:"snapshot directory path; mutually exclusive with latest"`
	Latest     bool     `json:"latest,omitempty" jsonschema_description:"use most recent snapshot under default location"`
	Types      []string `json:"types,omitempty" jsonschema_description:"catalog tags to check (default: all in snapshot)"`
	Force      bool     `json:"force,omitempty" jsonschema_description:"override profile-mismatch refusal"`
}

func (s *Server) registerBackup() {
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "backup_create",
		Description: "Snapshot the firewall config to a per-record YAML tree. Read-only against the firewall; produces files locally. Returns sophosfw.v1.backupCreate envelope (path, profile, createdAt, recordCounts).",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Create backup"},
	}, s.handleBackupCreate)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "backup_list",
		Description: "List existing backup snapshots for the profile, newest-first. Returns sophosfw.v1.backupList envelope.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "List backups"},
	}, s.handleBackupList)
	sdkmcp.AddTool(s.impl, &sdkmcp.Tool{
		Name:        "drift_check",
		Description: "Compare a backup snapshot to current firewall state. Returns sophosfw.v1.drift envelope with added/modified/removed/unchanged counts plus per-record diffs. Read-only.",
		Annotations: &sdkmcp.ToolAnnotations{ReadOnlyHint: true, Title: "Drift check"},
	}, s.handleDriftCheck)
}

// backupSvc resolves a BackupSvc from server Deps. Catalog comes from
// Deps (already plumbed by the cli `mcp serve` factory); BaseDir is the
// on-disk root for snapshot writes; Version is recorded in _meta.yaml so
// snapshots carry the producing build.
func (s *Server) backupSvc() *svc.BackupSvc {
	return &svc.BackupSvc{
		Inner:   s.objectSvc(),
		Catalog: s.deps.Catalog,
		BaseDir: s.deps.BaseDir,
		Now:     time.Now,
		Version: s.version,
	}
}

func (s *Server) handleBackupCreate(ctx context.Context, _ *sdkmcp.CallToolRequest, in BackupCreateInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	opts := svc.BackupCreateOptions{
		OutDir:  in.Out,
		Types:   in.Types,
		Exclude: in.Exclude,
	}
	if len(profiles) == 1 {
		result, err := s.backupSvc().Create(ctx, profiles[0], opts)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := render.BackupCreateEnvelope(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	// Fan-out: backup is a read-side op (no real "preflight" — snapshotting
	// is itself the operation). Pre-flight phase is a cheap no-op so all
	// per-profile work happens in the apply phase, sequentially with
	// fail-fast.
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		if preflight {
			return nil, nil
		}
		return s.backupSvc().Create(ctx, profile, opts)
	}
	fr := svc.Run(ctx, "backup_create", profiles, op, false)
	return s.renderFanoutResult(fr)
}

func (s *Server) handleBackupList(_ context.Context, _ *sdkmcp.CallToolRequest, in BackupListInput) (*sdkmcp.CallToolResult, any, error) {
	profile := s.resolveProfile(in.Profile)
	entries, err := s.backupSvc().List(profile)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	body, err := render.BackupListEnvelope(profile, entries)
	if err != nil {
		return s.errorEnvelopeResult(err, profile)
	}
	return jsonResult(body)
}

func (s *Server) handleDriftCheck(ctx context.Context, _ *sdkmcp.CallToolRequest, in DriftCheckInput) (*sdkmcp.CallToolResult, any, error) {
	profiles, err := s.resolveTargetProfilesMcp(in.Profile, in.ProfileSet)
	if err != nil {
		return s.errorEnvelopeResult(err, "")
	}
	opts := svc.DriftOptions{
		SnapshotPath: in.Snapshot,
		Latest:       in.Latest,
		Types:        in.Types,
		Force:        in.Force,
	}
	if len(profiles) == 1 {
		result, err := s.backupSvc().Drift(ctx, profiles[0], opts)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		body, err := render.DriftEnvelope(result)
		if err != nil {
			return s.errorEnvelopeResult(err, profiles[0])
		}
		return jsonResult(body)
	}
	// Fan-out: drift is a read-side op. Pre-flight is a no-op; the apply
	// phase per profile runs the actual comparison and captures the
	// summary in ApplyResult.
	op := func(ctx context.Context, profile string, preflight bool) (any, error) {
		if preflight {
			return nil, nil
		}
		return s.backupSvc().Drift(ctx, profile, opts)
	}
	fr := svc.Run(ctx, "drift_check", profiles, op, false)
	return s.renderFanoutResult(fr)
}
