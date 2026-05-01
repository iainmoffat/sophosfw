package sophos

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestClient_Do_PostsReqxmlForm(t *testing.T) {
	var receivedBody string
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "/webconsole/APIController", r.URL.Path)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		require.NoError(t, r.ParseForm())
		receivedBody = r.Form.Get("reqxml")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login></Response>`)
	})

	c := newClientWithRoots(t, srv.URL, pool)
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(receivedBody, "<Request>"))
	require.Contains(t, receivedBody, "<Username>u</Username>")
	require.Contains(t, receivedBody, "<Get><IPHost></IPHost></Get>")
}

func TestClient_Do_RejectsMutatingWhenReadOnly(t *testing.T) {
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server must not be reached for read-only violation")
	})
	c := newClientWithRoots(t, srv.URL, pool)
	c.ReadOnly = true

	raw := []byte(`<Set operation="add"><IPHost><Name>x</Name></IPHost></Set>`)
	_, err := c.DoRaw(context.Background(), raw)
	require.ErrorIs(t, err, ErrReadOnlyViolation)
}

func TestClient_Do_AuthFailureSurfacesAsError(t *testing.T) {
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<Response APIVersion="2200.1"><Login><status>Authentication Failure</status></Login></Response>`)
	})
	c := newClientWithRoots(t, srv.URL, pool)
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.ErrorIs(t, err, ErrAuthFailed)
}

func TestClient_Do_TimeoutHonored(t *testing.T) {
	srv, pool := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	})
	c := newClientWithRoots(t, srv.URL, pool)
	c.Timeout = 10 * time.Millisecond
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.Error(t, err)
}

func TestClient_Do_WarnsOnInsecureSkipVerify(t *testing.T) {
	srv, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<Response><Login><status>Authentication Successful</status></Login></Response>`)
	})
	c := NewClient(ClientConfig{
		BaseURL:            srv.URL,
		Username:           "u",
		Password:           "p",
		InsecureSkipVerify: true,
	})
	stderrBuf := &bytes.Buffer{}
	c.Stderr = stderrBuf
	_, err := c.Do(context.Background(), Envelope{Operations: []Op{GetOp{XMLTag: "IPHost"}}})
	require.NoError(t, err)
	require.Contains(t, stderrBuf.String(), "TLS verification disabled")
}

// newClientWithRoots builds a client trusting a single test cert. Tests do
// NOT use InsecureSkipVerify so that the trust path itself is exercised.
func newClientWithRoots(t *testing.T, base string, pool *x509.CertPool) *Client {
	t.Helper()
	u, err := url.Parse(base)
	require.NoError(t, err)
	c := NewClient(ClientConfig{
		BaseURL:  u.String(),
		Username: "u",
		Password: "p",
		Timeout:  5 * time.Second,
	})
	c.HTTPClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	return c
}
