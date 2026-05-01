package creds

import "runtime"

// New returns the platform-default Store: keychain on darwin, file elsewhere.
// The fileBaseDir parameter is used by the file backend (typically
// ~/.config/sophosfw).
func New(fileBaseDir string) Store {
	if runtime.GOOS == "darwin" {
		return NewKeychainStore()
	}
	return NewFileStore(fileBaseDir)
}
