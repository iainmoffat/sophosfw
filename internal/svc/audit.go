package svc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry is one append-only line in ~/.config/sophosfw/audit.log.
// Single line of compact JSON; line-oriented log for grep-ability.
type AuditEntry struct {
	Timestamp        string `json:"timestamp"`
	Profile          string `json:"profile"`
	Operation        string `json:"operation"`  // create | update | delete | raw_apply | raw_apply_mutating
	ObjectType       string `json:"objectType"` // IPHost | raw
	ObjectName       string `json:"objectName,omitempty"`
	ExpectedDiffHash string `json:"expectedDiffHash,omitempty"`
	RedactedXML      string `json:"redactedXml,omitempty"`
	Result           string `json:"result"` // ok | error:<kind>
	ErrorMessage     string `json:"errorMessage,omitempty"`
}

// AuditLog is a thread-safe append-only writer to <baseDir>/audit.log
// (mode 0600). Construct via NewAuditLog. When enabled=false, Write is a no-op
// and the file is never created.
type AuditLog struct {
	path    string
	enabled bool
	mu      sync.Mutex
}

func NewAuditLog(baseDir string, enabled bool) *AuditLog {
	return &AuditLog{
		path:    filepath.Join(baseDir, "audit.log"),
		enabled: enabled,
	}
}

// Dir returns the directory that contains the audit.log file.
func (a *AuditLog) Dir() string { return filepath.Dir(a.path) }

func (a *AuditLog) Write(entry AuditEntry) error {
	if a == nil || !a.enabled {
		return nil
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}
