// Package creds abstracts credential persistence so the rest of the codebase
// never touches platform-specific keychains directly.
package creds

// Credentials is a username/password pair for a Sophos firewall profile.
type Credentials struct {
	Username string
	Password string
}

// Store persists Credentials per profile name. Implementations must scrub
// values from memory where the platform allows.
type Store interface {
	Load(profile string) (Credentials, error)
	Save(profile string, c Credentials) error
	Delete(profile string) error
	Backend() string // "keychain" | "file"
}

// Backend names returned by Store.Backend().
const (
	BackendKeychain = "keychain"
	BackendFile     = "file"
)
