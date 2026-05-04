package svc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"

	"github.com/iainmoffat/sophosfw/internal/sophos"
)

// validXMLName is the allowlist regex for legal XML element names per
// the spec. Permits letter/underscore start, then letters, digits,
// underscore, period, hyphen.
var validXMLName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// validateXMLName checks if a string is a valid XML element name.
// Caller-controlled keys are validated through this gate to prevent
// XML injection.
func validateXMLName(name string) error {
	if !validXMLName.MatchString(name) {
		return fmt.Errorf("%w: invalid XML element name %q", sophos.ErrInvalidRequest, name)
	}
	return nil
}

// marshalObjectBody emits the Sophos inner XML element for a single
// object body. tag is the outer element name (e.g. "FirewallRule",
// "IPHostGroup"). body is the parsed YAML/JSON map. Map keys are
// validated via validateXMLName so caller-controlled keys cannot
// inject XML; tag is also validated for the same reason.
//
// Encoding rules (preserved from the per-type helpers this replaces):
//   - keys are emitted in sorted order for deterministic output;
//   - nil values are skipped;
//   - strings are XML-escaped via encoding/xml's EscapeText;
//   - booleans render as "true"/"false";
//   - integer and float scalars render via fmt %v;
//   - nested maps recurse;
//   - []any emits one <key>VAL</key> element per item (flat repetition,
//     not a wrapper); callers nest a parent map for grouped lists.
func marshalObjectBody(tag string, body map[string]any) ([]byte, error) {
	if err := validateXMLName(tag); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("<")
	buf.WriteString(tag)
	buf.WriteString(">")
	if err := writeMapChildren(&buf, body); err != nil {
		return nil, err
	}
	buf.WriteString("</")
	buf.WriteString(tag)
	buf.WriteString(">")
	return buf.Bytes(), nil
}

// writeMapChildren writes each key/value of m as an XML child element,
// keys in sorted order.
func writeMapChildren(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeKeyValue(buf, k, m[k]); err != nil {
			return err
		}
	}
	return nil
}

// writeKeyValue writes a single XML element <key>val</key>, recursing
// for maps and repeating for slices. See marshalObjectBody for the
// full encoding contract.
func writeKeyValue(buf *bytes.Buffer, key string, val any) error {
	if err := validateXMLName(key); err != nil {
		return err
	}
	switch v := val.(type) {
	case nil:
		return nil
	case string:
		writeOpen(buf, key)
		if err := xml.EscapeText(buf, []byte(v)); err != nil {
			return err
		}
		writeClose(buf, key)
	case bool:
		writeOpen(buf, key)
		fmt.Fprintf(buf, "%t", v)
		writeClose(buf, key)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		writeOpen(buf, key)
		fmt.Fprintf(buf, "%v", v)
		writeClose(buf, key)
	case map[string]any:
		writeOpen(buf, key)
		if err := writeMapChildren(buf, v); err != nil {
			return err
		}
		writeClose(buf, key)
	case []any:
		// Emit one <key>VAL</key> per item.
		for _, item := range v {
			if err := writeKeyValue(buf, key, item); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported value type for key %q: %T", key, val)
	}
	return nil
}

func writeOpen(buf *bytes.Buffer, key string) {
	buf.WriteString("<")
	buf.WriteString(key)
	buf.WriteString(">")
}

func writeClose(buf *bytes.Buffer, key string) {
	buf.WriteString("</")
	buf.WriteString(key)
	buf.WriteString(">")
}
