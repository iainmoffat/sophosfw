//go:build !darwin

package creds

// KeychainStore is a stub on non-Darwin platforms. The factory does not
// instantiate it; this exists only so cross-platform code can reference the
// type name without build-tag noise.
type KeychainStore struct{}

func NewKeychainStore() *KeychainStore { return &KeychainStore{} }

func (*KeychainStore) Backend() string                          { return BackendKeychain }
func (*KeychainStore) Load(string) (Credentials, error)         { return Credentials{}, ErrNotFound }
func (*KeychainStore) Save(string, Credentials) error           { return ErrNotFound }
func (*KeychainStore) Delete(string) error                      { return nil }
