package creds

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ErrNotFound is returned when no credentials are stored for a given profile.
var ErrNotFound = errors.New("creds: not found")

// ErrInsecurePermissions is returned when the credentials file has perms
// looser than 0600.
var ErrInsecurePermissions = errors.New("creds: file permissions too permissive (must be 0600)")

const credsFileName = "credentials.yaml"

// FileStore persists credentials in <baseDir>/credentials.yaml at mode 0600.
type FileStore struct {
	baseDir string
}

// NewFileStore returns a Store that persists under baseDir.
func NewFileStore(baseDir string) *FileStore {
	return &FileStore{baseDir: baseDir}
}

func (f *FileStore) Backend() string { return BackendFile }

type fileFormat struct {
	Profiles map[string]Credentials `yaml:"profiles"`
}

func (f *FileStore) path() string { return filepath.Join(f.baseDir, credsFileName) }

func (f *FileStore) load() (*fileFormat, error) {
	path := f.path()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &fileFormat{Profiles: map[string]Credentials{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("creds: stat: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("creds: read: %w", err)
	}
	ff := &fileFormat{Profiles: map[string]Credentials{}}
	if err := yaml.Unmarshal(b, ff); err != nil {
		return nil, fmt.Errorf("creds: parse: %w", err)
	}
	if ff.Profiles == nil {
		ff.Profiles = map[string]Credentials{}
	}
	return ff, nil
}

func (f *FileStore) save(ff *fileFormat) error {
	if err := os.MkdirAll(f.baseDir, 0o700); err != nil {
		return fmt.Errorf("creds: mkdir: %w", err)
	}
	b, err := yaml.Marshal(ff)
	if err != nil {
		return fmt.Errorf("creds: marshal: %w", err)
	}
	tmp := f.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("creds: write tmp: %w", err)
	}
	return os.Rename(tmp, f.path())
}

// Load returns the credentials for the given profile.
func (f *FileStore) Load(profile string) (Credentials, error) {
	ff, err := f.load()
	if err != nil {
		return Credentials{}, err
	}
	c, ok := ff.Profiles[profile]
	if !ok {
		return Credentials{}, ErrNotFound
	}
	return c, nil
}

// Save persists credentials for the given profile.
func (f *FileStore) Save(profile string, c Credentials) error {
	ff, err := f.load()
	if err != nil && !errors.Is(err, ErrInsecurePermissions) {
		return err
	}
	if ff == nil {
		ff = &fileFormat{Profiles: map[string]Credentials{}}
	}
	ff.Profiles[profile] = c
	return f.save(ff)
}

// Delete removes credentials for the given profile.
func (f *FileStore) Delete(profile string) error {
	ff, err := f.load()
	if err != nil {
		return err
	}
	delete(ff.Profiles, profile)
	return f.save(ff)
}
