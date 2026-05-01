// Package sophos implements the Sophos Firewall XML API client: request
// envelope construction, response parsing, status normalization, and HTTP
// transport. Login credentials are owned by this package and injected at
// send time so service-layer code never touches them.
package sophos

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

// Op is implemented by all envelope operations (GetOp, StatisticsOp, …).
type Op interface{ isOp() }

// GetOp models a `<Get><Tag>…</Tag></Get>` envelope. If Name is set it is
// converted to a Name=Value filter. If Filter is set it is used directly.
type GetOp struct {
	XMLTag string
	Name   string
	Filter *FilterClause
}

func (GetOp) isOp() {}

// StatisticsOp models a `<TagStatistics>…</TagStatistics>` envelope with an
// optional rich-criteria filter.
type StatisticsOp struct {
	XMLTag string // e.g. "IPHostStatistics"
	Filter *FilterClause
}

func (StatisticsOp) isOp() {}

// FilterClause is a single field/criteria/value tuple. Validation against the
// allowed criteria set lives in filter.go.
type FilterClause struct {
	Field    string
	Criteria string
	Value    string
}

// Envelope is the user-facing description of an outbound request. The client
// injects credentials and serializes to XML at send time.
type Envelope struct {
	Operations []Op
	TxnID      string
}

// BuildEnvelope serializes an Envelope into a Sophos `<Request>` XML body
// with Login injected.
func BuildEnvelope(env Envelope, username, password string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<Request>")

	if env.TxnID != "" {
		buf.WriteString("<transactionid>")
		if err := xml.EscapeText(&buf, []byte(env.TxnID)); err != nil {
			return nil, err
		}
		buf.WriteString("</transactionid>")
	}

	if err := writeLogin(&buf, username, password); err != nil {
		return nil, err
	}

	for _, op := range env.Operations {
		switch o := op.(type) {
		case GetOp:
			if err := writeGetOp(&buf, o); err != nil {
				return nil, err
			}
		case StatisticsOp:
			if err := writeStatisticsOp(&buf, o); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("sophos: unknown operation type %T", op)
		}
	}

	buf.WriteString("</Request>")
	return buf.Bytes(), nil
}

// BuildRawEnvelope wraps a user-supplied operation body in a `<Request>` with
// Login injected. The raw bytes may be a complete `<Request>…</Request>` (in
// which case we splice Login in after `<Request>`) or just the operation
// body.
func BuildRawEnvelope(raw []byte, username, password string) ([]byte, error) {
	var login bytes.Buffer
	if err := writeLogin(&login, username, password); err != nil {
		return nil, err
	}

	if bytes.Contains(raw, []byte("<Request>")) {
		// Splice Login in immediately after the opening Request tag.
		out := bytes.Replace(raw, []byte("<Request>"), append([]byte("<Request>"), login.Bytes()...), 1)
		return out, nil
	}
	// Wrap.
	var out bytes.Buffer
	out.WriteString("<Request>")
	out.Write(login.Bytes())
	out.Write(raw)
	out.WriteString("</Request>")
	return out.Bytes(), nil
}

// BuildSetEnvelope wraps inner XML in a <Set operation="add|update"> within
// the standard Sophos <Request><Login>...</Login>...</Request> envelope.
// `operation` must be "add" or "update". `inner` is the body that goes
// inside <Set>...</Set>, e.g. `<IPHost>...</IPHost>`.
func BuildSetEnvelope(operation string, inner []byte, username, password string) ([]byte, error) {
	if operation != "add" && operation != "update" {
		return nil, fmt.Errorf("BuildSetEnvelope: operation must be \"add\" or \"update\", got %q", operation)
	}
	var buf bytes.Buffer
	buf.WriteString("<Request>")
	if err := writeLogin(&buf, username, password); err != nil {
		return nil, err
	}
	buf.WriteString(`<Set operation="`)
	buf.WriteString(operation)
	buf.WriteString(`">`)
	buf.Write(inner)
	buf.WriteString("</Set>")
	buf.WriteString("</Request>")
	return buf.Bytes(), nil
}

// BuildRemoveEnvelope wraps inner XML in a <Remove>...</Remove>.
func BuildRemoveEnvelope(inner []byte, username, password string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("<Request>")
	if err := writeLogin(&buf, username, password); err != nil {
		return nil, err
	}
	buf.WriteString("<Remove>")
	buf.Write(inner)
	buf.WriteString("</Remove>")
	buf.WriteString("</Request>")
	return buf.Bytes(), nil
}

func writeLogin(buf *bytes.Buffer, username, password string) error {
	buf.WriteString("<Login>")
	buf.WriteString("<Username>")
	if err := xml.EscapeText(buf, []byte(username)); err != nil {
		return err
	}
	buf.WriteString("</Username>")
	buf.WriteString("<Password>")
	if err := xml.EscapeText(buf, []byte(password)); err != nil {
		return err
	}
	buf.WriteString("</Password>")
	buf.WriteString("</Login>")
	return nil
}

func writeGetOp(buf *bytes.Buffer, o GetOp) error {
	if o.XMLTag == "" {
		return fmt.Errorf("sophos: GetOp requires XMLTag")
	}
	buf.WriteString("<Get>")
	buf.WriteString("<")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")

	switch {
	case o.Filter != nil:
		if err := writeFilter(buf, *o.Filter); err != nil {
			return err
		}
	case o.Name != "":
		if err := writeFilter(buf, FilterClause{Field: "Name", Criteria: "=", Value: o.Name}); err != nil {
			return err
		}
	}

	buf.WriteString("</")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")
	buf.WriteString("</Get>")
	return nil
}

func writeStatisticsOp(buf *bytes.Buffer, o StatisticsOp) error {
	if o.XMLTag == "" {
		return fmt.Errorf("sophos: StatisticsOp requires XMLTag")
	}
	buf.WriteString("<")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")

	if o.Filter != nil {
		if err := writeFilter(buf, *o.Filter); err != nil {
			return err
		}
	}

	buf.WriteString("</")
	buf.WriteString(o.XMLTag)
	buf.WriteString(">")
	return nil
}

func writeFilter(buf *bytes.Buffer, f FilterClause) error {
	buf.WriteString("<Filter>")
	buf.WriteString(`<key name="`)
	if err := xml.EscapeText(buf, []byte(f.Field)); err != nil {
		return err
	}
	buf.WriteString(`" criteria="`)
	if err := xml.EscapeText(buf, []byte(f.Criteria)); err != nil {
		return err
	}
	buf.WriteString(`">`)
	if err := xml.EscapeText(buf, []byte(f.Value)); err != nil {
		return err
	}
	buf.WriteString("</key>")
	buf.WriteString("</Filter>")
	return nil
}
