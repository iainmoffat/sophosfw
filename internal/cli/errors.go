package cli

import (
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ErrorKind classifies an error into a sophosfw.v1.error envelope kind.
func ErrorKind(err error) string {
	return svc.ErrorKind(err)
}

// ExitCodeFor maps an error kind to a process exit code.
func ExitCodeFor(kind string) int {
	switch kind {
	case "":
		return 0
	case "config_error":
		return 2
	case "auth_failed":
		return 3
	case "read_only_violation":
		return 4
	case "tls_error", "network_error":
		return 5
	case "unsupported_in_phase":
		return 6
	default:
		return 1
	}
}
