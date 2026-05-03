package sophos

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/iainmoffat/sophosfw/internal/safety"
)

// ClientConfig configures a sophos.Client.
type ClientConfig struct {
	BaseURL            string // e.g. https://fw.example.com:4444
	Username           string
	Password           string
	Timeout            time.Duration
	InsecureSkipVerify bool
	ReadOnly           bool
}

// Client speaks the Sophos XML API over HTTP. Credentials are owned by the
// client and injected into every envelope at send time.
type Client struct {
	BaseURL            string
	Username           string
	Password           string
	Timeout            time.Duration
	InsecureSkipVerify bool
	ReadOnly           bool

	HTTPClient *http.Client
	Stderr     io.Writer // for the per-call --insecure-skip-verify warning
}

// NewClient constructs a Client from the given config.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec
	}
	return &Client{
		BaseURL:            strings.TrimRight(cfg.BaseURL, "/"),
		Username:           cfg.Username,
		Password:           cfg.Password,
		Timeout:            cfg.Timeout,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ReadOnly:           cfg.ReadOnly,
		HTTPClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		// Stderr defaults to os.Stderr; tests can swap it.
		Stderr: stderr(),
	}
}

// stderr is a package-level indirection so tests can capture warnings.
var stderr = func() io.Writer { return os.Stderr }

// Do builds an envelope from `env`, sends it, and returns the parsed response.
func (c *Client) Do(ctx context.Context, env Envelope) (*Response, error) {
	xmlBody, err := BuildEnvelope(env, c.Username, c.Password)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, xmlBody)
}

// DoRaw sends a user-supplied XML envelope. Login is injected if not present.
func (c *Client) DoRaw(ctx context.Context, raw []byte) (*Response, error) {
	body, err := BuildRawEnvelope(raw, c.Username, c.Password)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, body)
}

func (c *Client) send(ctx context.Context, xmlBody []byte) (*Response, error) {
	if c.ReadOnly {
		if mutating, verbs := safety.IsMutating(xmlBody); mutating {
			return nil, fmt.Errorf("%w: %s", ErrReadOnlyViolation, strings.Join(verbs, ","))
		}
	}

	if c.InsecureSkipVerify && c.Stderr != nil {
		_, _ = fmt.Fprintln(c.Stderr, "warning: TLS verification disabled for this request (--insecure-skip-verify)")
	}

	form := url.Values{}
	form.Set("reqxml", string(xmlBody))

	endpoint := c.BaseURL + "/webconsole/APIController"
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sophos: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sophos: read response: %w", err)
	}

	parsed, err := ParseResponse(respBody)
	if err != nil {
		return nil, err
	}
	if err := parsed.AsError(); err != nil {
		return parsed, err
	}
	return parsed, nil
}
