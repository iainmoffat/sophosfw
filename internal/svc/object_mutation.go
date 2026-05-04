package svc

// ObjectMutationResult is the shared result type for the body-as-map
// mutating workflows added in Phase 12 (IPHostGroup, FQDNHost,
// FQDNHostGroup, MACHost, Services, ServiceGroup). Structurally identical
// to FirewallRulePushResult but kept separate to avoid churning the
// existing firewall_rule/nat_rule code paths.
type ObjectMutationResult struct {
	Profile     string
	ObjectType  string
	Name        string
	Operation   string // "create" | "update" | "delete"
	DryRun      bool
	Preview     *Preview
	NewDiffHash string
	Item        map[string]any
}
