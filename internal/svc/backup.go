package svc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/draft"
	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// MetaSchemaName is the schema string written into _meta.yaml at the root
// of every snapshot. Drift readers MUST refuse to interpret a directory as
// a snapshot unless this exact string is present.
const MetaSchemaName = "sophosfw.v1.backupMeta"

// BackupSvc orchestrates `sophosfw backup` and `sophosfw drift`.
//
// Inner provides the per-type list/get plumbing (config, creds, catalog,
// client factory). Catalog is duplicated on the struct so resolveTypes
// can iterate the full tag list without dipping into ObjectSvc internals.
// BaseDir is the root of the on-disk store (typically ~/.config/sophosfw).
// Now is overrideable for deterministic tests. Version is the sophosfw
// build version baked into _meta.yaml; injected by the caller (CLI/MCP
// factories pass RootDeps.Version).
type BackupSvc struct {
	Inner   *ObjectSvc
	Catalog *catalog.Catalog
	BaseDir string
	Now     func() time.Time
	Version string
}

func (s *BackupSvc) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// BackupCreateOptions controls Create. OutDir overrides the default
// timestamped location under <BaseDir>/profiles/<name>/backups/. Types and
// Exclude are mutually exclusive: Types restricts to a subset, Exclude
// trims from the full catalog.
type BackupCreateOptions struct {
	OutDir  string
	Types   []string
	Exclude []string
}

// BackupCreateResult is the render-friendly summary returned by Create.
type BackupCreateResult struct {
	Profile       string
	Path          string
	CreatedAt     time.Time
	TypesIncluded []string
	RecordCounts  map[string]int
	TotalRecords  int
}

// backupMeta is serialized as _meta.yaml at the root of every snapshot.
// The leading `schema` field is the discriminator; CatalogVersion is a
// placeholder for future schema evolution.
type backupMeta struct {
	Schema          string         `yaml:"schema"`
	Profile         string         `yaml:"profile"`
	URL             string         `yaml:"url"`
	SophosfwVersion string         `yaml:"sophosfwVersion"`
	CreatedAt       string         `yaml:"createdAt"`
	CatalogVersion  string         `yaml:"catalogVersion"`
	TypesIncluded   []string       `yaml:"typesIncluded"`
	RecordCounts    map[string]int `yaml:"recordCounts"`
	TotalRecords    int            `yaml:"totalRecords"`
}

// Create writes a per-record YAML snapshot tree under <OutDir or default>.
//
// Atomicity: the snapshot is built under "<targetDir>.partial" and
// os.Renamed to "<targetDir>" only after every type has been written.
// On any error, the .partial directory is deliberately left in place for
// inspection; the caller (or an operator) can decide whether to retry or
// to investigate the partial result.
//
// Stub records (where Name is empty) are dropped. _diffHash is injected
// per record before writing so a later drift pass can short-circuit on
// hash equality without re-marshalling.
func (s *BackupSvc) Create(ctx context.Context, profileName string, opts BackupCreateOptions) (*BackupCreateResult, error) {
	profile, name, err := s.Inner.Config.ActiveProfile(profileName)
	if err != nil {
		return nil, err
	}

	if len(opts.Types) > 0 && len(opts.Exclude) > 0 {
		return nil, fmt.Errorf("%w: --types and --exclude are mutually exclusive", sophos.ErrInvalidRequest)
	}

	types, err := s.resolveTypes(opts.Types, opts.Exclude)
	if err != nil {
		return nil, err
	}

	now := s.now()
	targetDir := opts.OutDir
	if targetDir == "" {
		targetDir, err = draft.BackupSnapshotDir(s.BaseDir, name, now)
		if err != nil {
			return nil, err
		}
	}

	if _, statErr := os.Stat(targetDir); statErr == nil {
		return nil, fmt.Errorf("%w: snapshot dir already exists at %s", sophos.ErrInvalidRequest, targetDir)
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	partialDir := targetDir + ".partial"
	// Clear any leftover .partial from a prior failed run before starting.
	// On-error retention applies to *this* run's failure, not stale state.
	if err := os.RemoveAll(partialDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(partialDir, 0o755); err != nil {
		return nil, err
	}

	counts := map[string]int{}
	total := 0

	for _, tag := range types {
		list, err := s.Inner.List(ctx, profileName, tag, nil)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", tag, err)
		}
		if list == nil || len(list.Items) == 0 {
			continue
		}
		typeDir := filepath.Join(partialDir, tag)
		if err := os.MkdirAll(typeDir, 0o755); err != nil {
			return nil, err
		}
		for _, item := range list.Items {
			record, mErr := toMap(item)
			if mErr != nil {
				return nil, fmt.Errorf("coerce %s record: %w", tag, mErr)
			}
			if record == nil {
				continue
			}
			recName, _ := record["Name"].(string)
			if recName == "" {
				// Defense in depth: ObjectSvc.List already drops stubs,
				// but if anything slips through we skip it here too.
				continue
			}
			// Inject diff hash for fast drift comparison later. DiffHash
			// strips _diffHash internally, so re-hashing is idempotent.
			if hash, herr := DiffHash(record); herr == nil {
				record["_diffHash"] = hash
			}
			slug := draft.Slug(recName)
			yamlBytes, merr := marshalCanonicalYAML(record)
			if merr != nil {
				return nil, fmt.Errorf("marshal %s/%s: %w", tag, recName, merr)
			}
			if err := os.WriteFile(filepath.Join(typeDir, slug+".yaml"), yamlBytes, 0o644); err != nil {
				return nil, err
			}
			counts[tag]++
			total++
		}
	}

	meta := backupMeta{
		Schema:          MetaSchemaName,
		Profile:         name,
		URL:             profile.URL,
		SophosfwVersion: s.Version,
		CreatedAt:       now.Format(time.RFC3339),
		CatalogVersion:  "1",
		TypesIncluded:   types,
		RecordCounts:    counts,
		TotalRecords:    total,
	}
	metaBytes, err := yaml.Marshal(meta)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(partialDir, "_meta.yaml"), metaBytes, 0o644); err != nil {
		return nil, err
	}

	// Ensure the parent of targetDir exists before rename. (BackupSnapshotDir
	// returns a nested path; default location's parent is typically already
	// created by MkdirAll above on partialDir, but custom OutDir may not be.)
	if err := os.MkdirAll(filepath.Dir(targetDir), 0o755); err != nil {
		return nil, err
	}
	if err := os.Rename(partialDir, targetDir); err != nil {
		return nil, err
	}

	return &BackupCreateResult{
		Profile:       name,
		Path:          targetDir,
		CreatedAt:     now,
		TypesIncluded: types,
		RecordCounts:  counts,
		TotalRecords:  total,
	}, nil
}

// resolveTypes returns the alphabetically-sorted list of catalog tags to
// include. want and exclude are mutually exclusive (the caller checks).
// All inputs are validated against the catalog; an unknown tag is an
// invalid-request error.
func (s *BackupSvc) resolveTypes(want, exclude []string) ([]string, error) {
	all := append([]string(nil), s.Catalog.Tags()...)
	sort.Strings(all)

	if len(want) == 0 && len(exclude) == 0 {
		return all, nil
	}

	if len(want) > 0 {
		out := make([]string, 0, len(want))
		for _, t := range want {
			entry, ok := s.Catalog.Resolve(t)
			if !ok {
				return nil, fmt.Errorf("%w: unknown type %q", sophos.ErrInvalidRequest, t)
			}
			out = append(out, entry.Tag)
		}
		sort.Strings(out)
		return out, nil
	}

	excludeSet := map[string]bool{}
	for _, t := range exclude {
		entry, ok := s.Catalog.Resolve(t)
		if !ok {
			return nil, fmt.Errorf("%w: unknown type %q (in --exclude)", sophos.ErrInvalidRequest, t)
		}
		excludeSet[entry.Tag] = true
	}
	out := make([]string, 0, len(all))
	for _, t := range all {
		if !excludeSet[t] {
			out = append(out, t)
		}
	}
	return out, nil
}
