package cli

import (
	"github.com/iainmoffat/sophosfw/internal/catalog"
	"github.com/spf13/cobra"
)

// newVPNCmd is the top-level `vpn` parent command. Sub-trees:
//   - `vpn ipsec ...`       — site-to-site IPsec tunnels (T6)
//   - `vpn policy ...`      — IPsec (Phase 2) policies (T7)
//   - `vpn ike-profile ...` — IKE / VPN profiles (T7)
func newVPNCmd(d RootDeps, cat *catalog.Catalog) *cobra.Command {
	cmd := &cobra.Command{Use: "vpn", Short: "VPN commands"}
	cmd.AddCommand(newVPNIPsecCmd(d, cat))
	cmd.AddCommand(newIPsecPolicyCmd(d, cat))
	cmd.AddCommand(newVPNProfileCmd(d, cat))
	return cmd
}
