package draft

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrDraftMissing is returned by ReadDraft when the file does not exist.
// ErrSnapshotMissing is used by callers (svc package) when a draft's
// matching snapshot file cannot be found.
var (
	ErrDraftMissing    = errors.New("firewall rule draft not found")
	ErrSnapshotMissing = errors.New("firewall rule snapshot not found for this draft")
)

// Draft holds the parsed shape of a YAML draft file: header metadata
// + the editable YAML body.
type Draft struct {
	Profile   string
	Rule      string
	Operation string // "create" | "update". Empty defaults to "update" on read.
	PulledAt  time.Time
	DiffHash  string
	Body      []byte
}

var hashRe = regexp.MustCompile(`^[a-f0-9]{64}$`)
var headerLine = regexp.MustCompile(`^# ([A-Za-z]+): (.*)$`)

// ReadDraft parses a draft file. Missing file returns ErrDraftMissing.
// Malformed header (missing required keys, bad timestamp, bad hash) →
// a descriptive error.
func ReadDraft(path string) (*Draft, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrDraftMissing, path)
		}
		return nil, err
	}
	// Normalize CRLF → LF so files edited on Windows or transferred via
	// tools that injected CRLF still parse. The body-split below uses LF
	// directly.
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	d := &Draft{}
	headerEnd := -1
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "---" {
			headerEnd = i
			break
		}
		// Skip the title line and the "DO NOT EDIT" advisory.
		if strings.HasPrefix(line, "# sophosfw firewall rule draft") ||
			strings.Contains(line, "DO NOT EDIT") {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			return nil, fmt.Errorf("draft header malformed at line %d: expected comment or `---`, got %q", i+1, line)
		}
		m := headerLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := strings.ToLower(m[1]), strings.TrimSpace(m[2])
		switch key {
		case "profile":
			d.Profile = val
		case "rule":
			d.Rule = val
		case "operation":
			d.Operation = val
		case "pulledat":
			t, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return nil, fmt.Errorf("draft header pulledAt invalid: %w", err)
			}
			d.PulledAt = t
		case "diffhash":
			// Empty diffHash is valid (for create operations), but if present,
			// it must be a valid 64-char hex hash.
			if val != "" && !hashRe.MatchString(val) {
				return nil, fmt.Errorf("draft header diffHash invalid: must be 64-char lowercase hex, got %q", val)
			}
			d.DiffHash = val
		}
	}
	if headerEnd < 0 {
		return nil, fmt.Errorf("draft missing `---` document marker")
	}
	if d.Profile == "" {
		return nil, fmt.Errorf("draft header missing profile")
	}
	if d.Rule == "" {
		return nil, fmt.Errorf("draft header missing rule")
	}
	if d.PulledAt.IsZero() {
		return nil, fmt.Errorf("draft header missing pulledAt")
	}
	// Operation defaults to "update" for backward compatibility with
	// Phase 7/8 drafts.
	if d.Operation == "" {
		d.Operation = "update"
	}
	if d.Operation != "create" && d.Operation != "update" {
		return nil, fmt.Errorf("draft header operation invalid: must be 'create' or 'update', got %q", d.Operation)
	}
	// Operation/diffHash consistency:
	if d.Operation == "create" && d.DiffHash != "" {
		return nil, fmt.Errorf("draft header inconsistency: operation=create requires empty diffHash")
	}
	if d.Operation == "update" && d.DiffHash == "" {
		return nil, fmt.Errorf("draft header missing diffHash (required for operation=update)")
	}
	parts := bytes.SplitN(b, []byte("\n---\n"), 2)
	if len(parts) != 2 {
		d.Body = nil
	} else {
		d.Body = parts[1]
	}
	return d, nil
}

// WriteDraft writes a draft to disk with mode 0600. Parent directories
// are created with mode 0700 if missing.
func WriteDraft(path string, d *Draft) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "# sophosfw firewall rule draft v1")
	fmt.Fprintf(&buf, "# profile: %s\n", d.Profile)
	fmt.Fprintf(&buf, "# rule: %s\n", d.Rule)
	op := d.Operation
	if op == "" {
		op = "update"
	}
	fmt.Fprintf(&buf, "# operation: %s\n", op)
	fmt.Fprintf(&buf, "# pulledAt: %s\n", d.PulledAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&buf, "# diffHash: %s\n", d.DiffHash)
	fmt.Fprintln(&buf, "# DO NOT EDIT ABOVE THIS LINE — push reads this header to verify drift")
	fmt.Fprintln(&buf, "---")
	buf.Write(d.Body)
	if !bytes.HasSuffix(d.Body, []byte("\n")) {
		buf.WriteByte('\n')
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}
