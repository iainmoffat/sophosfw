// Package mcp is the foundation-phase MCP server scaffold. It registers zero
// tools but exists to prove the seam: the catalog and svc packages must be
// usable from a non-Cobra consumer. Phase 4 will add the real tool surface.
package mcp

import (
	"context"
	"fmt"
	"io"

	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/iainmoffat/sophosfw/internal/config"
	"github.com/iainmoffat/sophosfw/internal/creds"
)

// Deps are the dependencies the MCP server needs from main.
type Deps struct {
	Config  *config.Config
	Creds   creds.Store
	Catalog *catalog.Catalog
}

// Server is the MCP server stub.
type Server struct {
	deps Deps
}

// NewServer constructs a stub server.
func NewServer(d Deps) *Server { return &Server{deps: d} }

// StartupReport returns the line printed by `mcp serve` at startup. It also
// exercises the seam by calling into the catalog so a future Phase-4 plug-in
// can rely on Catalog being non-nil and loadable.
func (s *Server) StartupReport(ctx context.Context) (string, error) {
	tags := s.deps.Catalog.Tags()
	return fmt.Sprintf(
		"sophosfw MCP server: 0 tools registered (foundation phase scaffold; Phase 4 will add tools). Catalog has %d tags loaded.",
		len(tags),
	), nil
}

// Serve is the entrypoint for `mcp serve`. In foundation phase it simply
// prints the startup report and blocks on ctx.Done(). Phase 4 will replace
// this with the real MCP transport (stdio JSON-RPC) and tool registration.
func (s *Server) Serve(ctx context.Context, w io.Writer) error {
	msg, err := s.StartupReport(ctx)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, msg); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
