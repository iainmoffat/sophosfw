// Package config models ~/.config/sophosfw/config.yaml: the global defaults
// and the registry of named firewall profiles.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

const (
	configFileName     = "config.yaml"
	profilesDirName    = "profiles"
	defaultOutput      = "table"
	defaultTimeout     = 30 * time.Second
	defaultBackendName = "keychain" // overridden on non-darwin
)

// Defaults are global settings that apply when a per-profile or per-flag
// override isn't supplied.
type Defaults struct {
	Output             string        `yaml:"output"`
	Timeout            time.Duration `yaml:"timeout"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
	AuditLog           *bool         `yaml:"auditLog,omitempty"` // pointer: nil = default-on
}

// Profile is a single named firewall configuration.
type Profile struct {
	URL                string        `yaml:"url"`
	Timeout            time.Duration `yaml:"timeout"`
	InsecureSkipVerify bool          `yaml:"insecureSkipVerify"`
	ReadOnly           bool          `yaml:"readOnly"`
	APIVersion         string        `yaml:"apiVersion,omitempty"`
	Notes              string        `yaml:"notes,omitempty"`
	CredentialsBackend string        `yaml:"credentialsBackend"`
}

// Config is the top-level config.yaml shape.
type Config struct {
	Version        int                 `yaml:"version"`
	CurrentProfile string              `yaml:"currentProfile,omitempty"`
	Defaults       Defaults            `yaml:"defaults"`
	Profiles       map[string]Profile  `yaml:"profiles"`
	ProfileSets    map[string][]string `yaml:"profileSets,omitempty"`
}

// profileNameRE matches the allowlist for profile and profile-set names:
// non-empty A-Za-z0-9_- (same as internal/draft/paths.go).
var profileNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validProfileSetName reports whether name matches the profile-name allowlist.
func validProfileSetName(name string) bool {
	return profileNameRE.MatchString(name)
}

// New returns a Config populated with defaults.
func New() *Config {
	return &Config{
		Version: 1,
		Defaults: Defaults{
			Output:  defaultOutput,
			Timeout: defaultTimeout,
		},
		Profiles: map[string]Profile{},
	}
}

// Load reads the config file under baseDir (typically ~/.config/sophosfw).
// If the file is absent, defaults are returned.
func Load(baseDir string) (*Config, error) {
	path := filepath.Join(baseDir, configFileName)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	c := New()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	if c.Defaults.Output == "" {
		c.Defaults.Output = defaultOutput
	}
	if c.Defaults.Timeout == 0 {
		c.Defaults.Timeout = defaultTimeout
	}
	if c.Version == 0 {
		c.Version = 1
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", path, err)
	}
	return c, nil
}

// validate checks invariants that aren't enforceable by the YAML schema alone.
// Today: ProfileSets entries must satisfy the allowlist, must not collide with
// a profile name, and every member must reference an existing profile.
//
// All errors are wrapped with sophos.ErrInvalidRequest so callers can match
// with errors.Is.
func (c *Config) validate() error {
	for name, members := range c.ProfileSets {
		if !validProfileSetName(name) {
			return fmt.Errorf("%w: invalid profile set name %q (allowed: A-Za-z0-9_-)", sophos.ErrInvalidRequest, name)
		}
		if _, collides := c.Profiles[name]; collides {
			return fmt.Errorf("%w: profile set name %q collides with profile name", sophos.ErrInvalidRequest, name)
		}
		for _, m := range members {
			if _, ok := c.Profiles[m]; !ok {
				return fmt.Errorf("%w: profile %q referenced by set %q does not exist", sophos.ErrInvalidRequest, m, name)
			}
		}
	}
	return nil
}

// Save writes the config (atomic rename) and ensures the profile dir exists.
func (c *Config) Save(baseDir string) error {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", baseDir, err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, profilesDirName), 0o700); err != nil {
		return fmt.Errorf("config: mkdir profiles: %w", err)
	}

	path := filepath.Join(baseDir, configFileName)
	tmp := path + ".tmp"
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("config: write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

// AddProfile inserts a profile. If no profile is currently selected, the
// newly added one becomes current.
func (c *Config) AddProfile(name string, p Profile) {
	if c.Profiles == nil {
		c.Profiles = map[string]Profile{}
	}
	c.Profiles[name] = p
	if c.CurrentProfile == "" {
		c.CurrentProfile = name
	}
}

// UseProfile switches the current profile.
func (c *Config) UseProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	c.CurrentProfile = name
	return nil
}

// RemoveProfile deletes a profile. Clears CurrentProfile if it was that one.
func (c *Config) RemoveProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	delete(c.Profiles, name)
	if c.CurrentProfile == name {
		c.CurrentProfile = ""
	}
	return nil
}

// ActiveProfile resolves the active profile from an optional override
// (typically the --profile flag). Returns the profile, its name, and an error
// if neither a valid override nor a current profile exists.
func (c *Config) ActiveProfile(override string) (Profile, string, error) {
	name := override
	if name == "" {
		name = c.CurrentProfile
	}
	if name == "" {
		return Profile{}, "", errors.New("no profile selected (use --profile or `sophosfw auth profile use`)")
	}
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, "", fmt.Errorf("profile %q not found", name)
	}
	return p, name, nil
}

// AuditLogEnabled reports whether mutation audit logging should write to
// ~/.config/sophosfw/audit.log. Default: true. Set defaults.auditLog: false
// in config.yaml to disable.
func (c *Config) AuditLogEnabled() bool {
	if c == nil || c.Defaults.AuditLog == nil {
		return true
	}
	return *c.Defaults.AuditLog
}

// AddProfileSet inserts (or overwrites) a named profile group. The name must
// satisfy the profile-name allowlist, must not collide with an existing
// profile name, and every member must reference an existing profile. The
// supplied members slice is copied; the caller may mutate it after the call.
func (c *Config) AddProfileSet(name string, members []string) error {
	if !validProfileSetName(name) {
		return fmt.Errorf("%w: invalid profile set name %q (allowed: A-Za-z0-9_-)", sophos.ErrInvalidRequest, name)
	}
	if _, exists := c.Profiles[name]; exists {
		return fmt.Errorf("%w: profile set name %q collides with profile name", sophos.ErrInvalidRequest, name)
	}
	for _, m := range members {
		if _, ok := c.Profiles[m]; !ok {
			return fmt.Errorf("%w: profile %q referenced by set %q does not exist", sophos.ErrInvalidRequest, m, name)
		}
	}
	if c.ProfileSets == nil {
		c.ProfileSets = map[string][]string{}
	}
	c.ProfileSets[name] = append([]string(nil), members...)
	return nil
}

// RemoveProfileSet deletes a named profile group. Errors if no such group
// exists.
func (c *Config) RemoveProfileSet(name string) error {
	if _, ok := c.ProfileSets[name]; !ok {
		return fmt.Errorf("%w: profile set %q not found", sophos.ErrInvalidRequest, name)
	}
	delete(c.ProfileSets, name)
	return nil
}

// ResolveProfileSet maps a --profile-set flag value to an ordered list of
// profile names. Three forms are accepted:
//
//   - bare set name      → expand to set members (in stored order)
//   - bare profile name  → single-element slice
//   - CSV of profile names (NOT set names) → multi-element slice with
//     duplicates removed; sets-of-sets are explicitly rejected.
//
// All errors are wrapped with sophos.ErrInvalidRequest.
func (c *Config) ResolveProfileSet(value string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: empty profile-set value", sophos.ErrInvalidRequest)
	}
	parts := strings.Split(value, ",")
	if len(parts) == 1 {
		single := strings.TrimSpace(parts[0])
		if single == "" {
			return nil, fmt.Errorf("%w: empty profile-set value", sophos.ErrInvalidRequest)
		}
		if members, ok := c.ProfileSets[single]; ok {
			return append([]string(nil), members...), nil
		}
		if _, ok := c.Profiles[single]; ok {
			return []string{single}, nil
		}
		return nil, fmt.Errorf("%w: unknown profile or profile set %q", sophos.ErrInvalidRequest, single)
	}
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		n := strings.TrimSpace(p)
		if n == "" {
			return nil, fmt.Errorf("%w: empty entry in profile CSV", sophos.ErrInvalidRequest)
		}
		if _, isSet := c.ProfileSets[n]; isSet {
			return nil, fmt.Errorf("%w: CSV entry %q is a profile set; use the set name alone, not in a CSV", sophos.ErrInvalidRequest, n)
		}
		if _, ok := c.Profiles[n]; !ok {
			return nil, fmt.Errorf("%w: profile %q not found", sophos.ErrInvalidRequest, n)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// DefaultBaseDir returns the conventional config dir under $XDG_CONFIG_HOME
// or ~/.config.
func DefaultBaseDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "sophosfw"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sophosfw"), nil
}
