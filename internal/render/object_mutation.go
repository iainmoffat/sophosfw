package render

import (
	"encoding/json"

	"github.com/iainmoffat/sophosfw/internal/svc"
)

// ObjectMutationEnvelope is the JSON envelope shape for the Phase 12
// mutating workflows. Schema name is per-type to give grep-friendly
// uniqueness — e.g. "sophosfw.v1.ipHostGroupMutation".
func ObjectMutationEnvelope(r *svc.ObjectMutationResult) ([]byte, error) {
	schema := schemaForObjectType(r.ObjectType)
	env := map[string]any{
		"schema":     schema,
		"profile":    r.Profile,
		"objectType": r.ObjectType,
		"name":       r.Name,
		"operation":  r.Operation,
		"applied":    !r.DryRun,
	}
	if r.DryRun && r.Preview != nil {
		env["preview"] = r.Preview
	}
	if !r.DryRun {
		if r.Item != nil {
			env["item"] = r.Item
		}
		if r.NewDiffHash != "" {
			env["newDiffHash"] = r.NewDiffHash
		}
	}
	return json.MarshalIndent(env, "", "  ")
}

// schemaForObjectType returns the per-type envelope schema name.
// Maps XML tag → camelCase short name.
func schemaForObjectType(t string) string {
	switch t {
	case "IPHostGroup":
		return "sophosfw.v1.ipHostGroupMutation"
	case "FQDNHost":
		return "sophosfw.v1.fqdnHostMutation"
	case "FQDNHostGroup":
		return "sophosfw.v1.fqdnHostGroupMutation"
	case "MACHost":
		return "sophosfw.v1.macHostMutation"
	case "Services":
		return "sophosfw.v1.servicesMutation"
	case "ServiceGroup":
		return "sophosfw.v1.serviceGroupMutation"
	case "VPNIPsecConnection":
		return "sophosfw.v1.vpnIpsecMutation"
	case "IPsecPolicy":
		return "sophosfw.v1.ipsecPolicyMutation"
	case "VPNProfile":
		return "sophosfw.v1.vpnProfileMutation"
	}
	return "sophosfw.v1.objectMutation"
}
