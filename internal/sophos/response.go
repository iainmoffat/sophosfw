package sophos

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// Response is the parsed shape of a Sophos `<Response>` envelope.
type Response struct {
	APIVersion  string
	LoginOK     bool
	LoginStatus string

	// Body is keyed by XML tag (e.g. "IPHost"). Each value is a slice of raw
	// per-record JSON fragments (we convert XML records to JSON for downstream
	// consumption). Unknown tags survive intact.
	Body map[string][]json.RawMessage

	// embeddedStatuses captures `<Tag><Status code="…">…</Status></Tag>`
	// blocks per tag so AsError can surface them.
	embeddedStatuses []embeddedStatus
}

type embeddedStatus struct {
	Tag     string
	Code    int
	Message string
}

// ParseResponse parses a Sophos XML response. Returns an error only for
// malformed XML — Sophos status codes inside the response are surfaced via
// Response.AsError() so callers can inspect the body even on failure.
func ParseResponse(b []byte) (*Response, error) {
	r := &Response{Body: map[string][]json.RawMessage{}}

	dec := xml.NewDecoder(bytes.NewReader(b))
	var (
		root    string
		current string
		buf     bytes.Buffer
		depth   int
		inLogin bool
		loginSb bytes.Buffer
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("sophos: parse: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if root == "" && t.Name.Local == "Response" {
				for _, a := range t.Attr {
					if a.Name.Local == "APIVersion" {
						r.APIVersion = a.Value
					}
				}
				root = "Response"
				continue
			}

			if depth == 2 && t.Name.Local == "Login" {
				inLogin = true
				loginSb.Reset()
				continue
			}

			if depth == 2 {
				current = t.Name.Local
				buf.Reset()
				if err := encodeStart(&buf, t); err != nil {
					return nil, err
				}
				continue
			}

			if current != "" {
				if err := encodeStart(&buf, t); err != nil {
					return nil, err
				}
			}

		case xml.EndElement:
			depth--

			if inLogin && t.Name.Local == "Login" {
				r.LoginStatus = strings.TrimSpace(loginSb.String())
				r.LoginOK = r.LoginStatus == "Authentication Successful"
				inLogin = false
				continue
			}

			if depth == 1 && current != "" {
				// Closing tag of a top-level child of Response.
				fmt.Fprintf(&buf, "</%s>", t.Name.Local)
				if err := r.absorbRecord(current, buf.Bytes()); err != nil {
					return nil, err
				}
				current = ""
				buf.Reset()
				continue
			}

			if current != "" {
				fmt.Fprintf(&buf, "</%s>", t.Name.Local)
			}

		case xml.CharData:
			if inLogin {
				loginSb.Write(t)
			} else if current != "" {
				if err := xml.EscapeText(&buf, t); err != nil {
					return nil, err
				}
			}
		}
	}

	return r, nil
}

func encodeStart(w *bytes.Buffer, s xml.StartElement) error {
	w.WriteString("<")
	w.WriteString(s.Name.Local)
	for _, a := range s.Attr {
		fmt.Fprintf(w, ` %s="`, a.Name.Local)
		if err := xml.EscapeText(w, []byte(a.Value)); err != nil {
			return err
		}
		w.WriteString(`"`)
	}
	w.WriteString(">")
	return nil
}

// absorbRecord converts the raw XML fragment for one top-level child element
// into a JSON map and appends it to Body[tag]. If the fragment carries an
// embedded `<Status code="…">…</Status>`, it's recorded for AsError.
func (r *Response) absorbRecord(tag string, raw []byte) error {
	// Detect embedded Status (e.g., empty-result tag carrying code 526).
	if code, msg, ok := extractEmbeddedStatus(raw); ok {
		r.embeddedStatuses = append(r.embeddedStatuses, embeddedStatus{Tag: tag, Code: code, Message: msg})
		return nil
	}

	m, err := xmlFragmentToMap(raw)
	if err != nil {
		return fmt.Errorf("sophos: convert %s: %w", tag, err)
	}
	jb, err := json.Marshal(m)
	if err != nil {
		return err
	}
	r.Body[tag] = append(r.Body[tag], json.RawMessage(jb))
	return nil
}

// AsError returns nil if the response is fully successful, or a typed error
// derived from the strongest signal in the response (login first, then
// embedded per-tag status codes).
func (r *Response) AsError() error {
	if !r.LoginOK {
		return &StatusError{Code: 534, Message: r.LoginStatus, Sentinel: ErrAuthFailed}
	}
	for _, s := range r.embeddedStatuses {
		if err := statusToError(s.Code, s.Message); err != nil {
			return err
		}
	}
	return nil
}

func extractEmbeddedStatus(raw []byte) (int, string, bool) {
	// Cheap pattern: look for <Status code="NNN">message</Status>
	const open = `<Status code="`
	idx := bytes.Index(raw, []byte(open))
	if idx < 0 {
		return 0, "", false
	}
	rest := raw[idx+len(open):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return 0, "", false
	}
	codeStr := string(rest[:end])
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return 0, "", false
	}
	rest = rest[end:]
	gt := bytes.IndexByte(rest, '>')
	if gt < 0 {
		return 0, "", false
	}
	rest = rest[gt+1:]
	closeIdx := bytes.Index(rest, []byte("</Status>"))
	if closeIdx < 0 {
		return code, "", true
	}
	return code, string(rest[:closeIdx]), true
}

// xmlFragmentToMap converts an XML element (with its outer tag) to a
// map[string]any with child element names as keys. Lossy for attributes and
// mixed content, which is acceptable for Sophos response shapes.
func xmlFragmentToMap(raw []byte) (map[string]any, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	stack := []map[string]any{}
	var current map[string]any
	var charBuf bytes.Buffer

	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			next := map[string]any{}
			if current == nil {
				current = next
				stack = append(stack, current)
				continue
			}
			stack = append(stack, next)
			// Will assign on EndElement.
			charBuf.Reset()

		case xml.CharData:
			charBuf.Write(t)

		case xml.EndElement:
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			text := bytesTrim(charBuf.Bytes())
			charBuf.Reset()

			var value any
			if len(top) > 0 {
				value = top
			} else {
				value = string(text)
			}

			if len(stack) == 0 {
				return current, nil
			}
			parent := stack[len(stack)-1]
			parent[t.Name.Local] = value
		}
	}
	return current, nil
}

func bytesTrim(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\t' || b[start] == '\r') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\t' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}
