//go:build darwin

package creds

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

const keychainService = "sophosfw"

// KeychainStore persists credentials in the macOS keychain.
type KeychainStore struct{}

// NewKeychainStore returns a Store backed by the macOS keychain.
func NewKeychainStore() *KeychainStore { return &KeychainStore{} }

func (*KeychainStore) Backend() string { return BackendKeychain }

// We pack username and password into a single secret as "username\npassword"
// so each profile is one keychain item.
func (*KeychainStore) Load(profile string) (Credentials, error) {
	v, err := keyring.Get(keychainService, profile)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return Credentials{}, ErrNotFound
		}
		return Credentials{}, fmt.Errorf("creds: keychain get: %w", err)
	}
	parts := strings.SplitN(v, "\n", 2)
	if len(parts) != 2 {
		return Credentials{}, fmt.Errorf("creds: malformed keychain entry for %q", profile)
	}
	return Credentials{Username: parts[0], Password: parts[1]}, nil
}

func (*KeychainStore) Save(profile string, c Credentials) error {
	if strings.Contains(c.Username, "\n") {
		return fmt.Errorf("creds: username must not contain newline")
	}
	return keyring.Set(keychainService, profile, c.Username+"\n"+c.Password)
}

func (*KeychainStore) Delete(profile string) error {
	err := keyring.Delete(keychainService, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
