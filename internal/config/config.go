// Package config models ~/.config/sophosfw/config.yaml: the global defaults
// and the registry of named firewall profiles.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
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
	Version        int                `yaml:"version"`
	CurrentProfile string             `yaml:"currentProfile,omitempty"`
	Defaults       Defaults           `yaml:"defaults"`
	Profiles       map[string]Profile `yaml:"profiles"`
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
	return c, nil
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
