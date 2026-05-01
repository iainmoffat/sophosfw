// Package mcp wraps the modelcontextprotocol/go-sdk SDK to expose sophosfw's
// read-only surface as MCP tools. Tool handlers are thin adapters over the
// existing svc package; output bodies are sophosfw.v1.* JSON envelopes
// matching the cli --json output.
package mcp

import (
	"context"
	"io"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
	"github.com/iainmoffat/sophosfw/internal/svc"
)

// Deps are the dependencies the MCP server needs from main.
type Deps struct {
	Config         *config.Config
	Creds          creds.Store
	Catalog        *catalog.Catalog
	NewClient      svc.ClientFactory
	DefaultProfile string // from --profile flag at server startup; "" = use config currentProfile
}

// Server wraps an sdk-mcp Server and the project Deps.
type Server struct {
	deps Deps
	impl *sdkmcp.Server
}

// NewServer constructs the MCP server with all read-only tools registered.
// version becomes the Server.Version field reported during the MCP handshake.
func NewServer(version string, d Deps) *Server {
	impl := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "sophosfw",
		Version: version,
	}, nil)
	s := &Server{deps: d, impl: impl}
	s.registerAll()
	return s
}

// Impl returns the underlying SDK server for testing purposes.
func (s *Server) Impl() *sdkmcp.Server {
	return s.impl
}

// Serve runs the MCP server on the supplied transport until the transport
// closes or the context is canceled.
func (s *Server) Serve(ctx context.Context, transport sdkmcp.Transport) error {
	return s.impl.Run(ctx, transport)
}

// ServeStdio is a convenience for the cli `mcp serve` command. It uses the
// SDK's StdioTransport bound to os.Stdin/os.Stdout.
//
// The unused `w` parameter exists only so existing call sites built for the
// foundation stub (which took io.Writer) can compile during the transition;
// it is ignored.
func (s *Server) ServeStdio(ctx context.Context, _ io.Writer) error {
	return s.Serve(ctx, &sdkmcp.StdioTransport{})
}

// registerAll wires every per-group tool registration. Each registerXxx
// function lives in its own per-group file (auth.go, object.go, etc.) and
// is added to the Server. T3 leaves this empty; T4-T10 add the real groups.
func (s *Server) registerAll() {
	s.registerAuth()
	s.registerObject()
	s.registerRaw()
	s.registerHostIP()
	s.registerService()
	s.registerFirewallRule()
	s.registerNATRule()
}
