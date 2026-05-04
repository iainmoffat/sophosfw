package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// LoadBody resolves --body input into a map[string]any.
//
// Source forms:
//
//   - "@/path/to/file" → read file contents
//   - "-"              → read stdin
//   - other            → treat as inline JSON or YAML string
//
// Format auto-detection: try JSON first (cheaper to fail), then YAML.
// Returns ErrInvalidRequest on parse failure or empty input.
func LoadBody(source string) (map[string]any, error) {
	var raw []byte
	var err error
	switch {
	case source == "":
		return nil, fmt.Errorf("%w: --body is required", sophos.ErrInvalidRequest)
	case source == "-":
		raw, err = io.ReadAll(os.Stdin)
	case strings.HasPrefix(source, "@"):
		raw, err = os.ReadFile(source[1:])
	default:
		raw = []byte(source)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", sophos.ErrInvalidRequest, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: body is empty", sophos.ErrInvalidRequest)
	}
	var body map[string]any
	if jerr := json.Unmarshal(raw, &body); jerr == nil {
		return body, nil
	}
	if yerr := yaml.Unmarshal(raw, &body); yerr == nil {
		return body, nil
	}
	return nil, fmt.Errorf("%w: body is neither valid JSON nor YAML", sophos.ErrInvalidRequest)
}
