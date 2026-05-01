// Package svc holds application services. Both CLI commands and (Phase-4) MCP
// tools call into svc, never directly into sophos/catalog/config. svc owns
// read-only enforcement (per-command layer) and dry-run gating.
package svc

import (
	"errors"
	"fmt"
	"sort"

	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
)

// ProfileSvc owns profile add/remove/use/list and the corresponding config
// + credential persistence.
type ProfileSvc struct {
	Config  *config.Config
	Creds   creds.Store
	BaseDir string
}

// ProfileInfo is a render-friendly summary returned by List.
type ProfileInfo struct {
	Name     string
	URL      string
	ReadOnly bool
	Current  bool
}

// Add registers a new profile. Fails on duplicate name or empty URL. The
// first profile becomes current automatically.
func (s *ProfileSvc) Add(name, url string, readOnly bool) error {
	if url == "" {
		return errors.New("profile: --url is required")
	}
	if _, dup := s.Config.Profiles[name]; dup {
		return fmt.Errorf("profile %q already exists", name)
	}
	s.Config.AddProfile(name, config.Profile{
		URL:                url,
		Timeout:            s.Config.Defaults.Timeout,
		ReadOnly:           readOnly,
		CredentialsBackend: s.Creds.Backend(),
	})
	return s.Config.Save(s.BaseDir)
}

// Remove deletes a profile and its stored credentials.
func (s *ProfileSvc) Remove(name string) error {
	if err := s.Config.RemoveProfile(name); err != nil {
		return err
	}
	if err := s.Creds.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
		return err
	}
	return s.Config.Save(s.BaseDir)
}

// Use switches the current profile.
func (s *ProfileSvc) Use(name string) error {
	if err := s.Config.UseProfile(name); err != nil {
		return err
	}
	return s.Config.Save(s.BaseDir)
}

// List returns all profiles sorted by name.
func (s *ProfileSvc) List() []ProfileInfo {
	out := make([]ProfileInfo, 0, len(s.Config.Profiles))
	for name, p := range s.Config.Profiles {
		out = append(out, ProfileInfo{
			Name:     name,
			URL:      p.URL,
			ReadOnly: p.ReadOnly,
			Current:  s.Config.CurrentProfile == name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
