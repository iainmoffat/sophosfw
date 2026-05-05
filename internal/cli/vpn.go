package cli

import (
	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/spf13/cobra"
)

// newVPNCmd is the top-level `vpn` parent command. Sub-trees:
//   - `vpn ipsec ...`       — site-to-site IPsec tunnels (T6)
//   - `vpn ike-profile ...` — IKE / VPN profiles (T7)
func newVPNCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "vpn", Short: "VPN commands"}
	cmd.AddCommand(newVPNIPsecCmd(d, cat))
	// Note: IPsecPolicy CLI registration deferred — Sophos 22.x XML API
	// does not recognize "IPsecPolicy" as a valid tag (probe returned
	// "Input request module is Invalid"). The svc/CLI/MCP code is
	// retained for future re-wiring once the correct tag name is
	// discovered. See Phase 15.x roadmap follow-up.
	cmd.AddCommand(newVPNProfileCmd(d, cat))
	return cmd
}
