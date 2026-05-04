package cli

import (
	"errors"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ErrDriftDetected is a sentinel returned by `sophosfw drift` when one
// or more changes are observed between the snapshot and the live
// firewall state. It is mapped by HandleError to exit code 1 *without*
// printing an error envelope so cron/CI invocations can treat drift as
// a normal output mode (think `git diff --exit-code`): 0 = clean,
// 1 = drift detected, 2+ = actual error.
var ErrDriftDetected = errors.New("drift detected")

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
	case "diff_hash_mismatch":
		return 7
	default:
		return 1
	}
}
