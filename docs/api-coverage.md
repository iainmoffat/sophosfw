# API coverage

**MCP tools (Phase 4):** in addition to the per-tag mappings below, the
server registers `auth_status`, `auth_test`, `auth_profile_list`,
`auth_profile_current`, and `raw_get` (the latter exposes any catalog tag
including ones not listed above).

| Area | XML Tag | CLI Command | MCP Tool | Get | Add | Update | Remove | Usage | Status |
|---|---|---|---|---|---|---|---|---|---|
| Host | IPHost | object list/get IPHost; host ip list/show/search/usage | host_ip_list/show/search/usage; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
| Host | IPHostGroup | object list/get IPHostGroup | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | FQDNHost | object list/get FQDNHost (typed Phase 3) | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Host | FQDNHostGroup | object list/get FQDNHostGroup | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | MACHost | object list/get MACHost (typed Phase 3) | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Service | Services | object list/get Services; service list/show/search/usage | service_list/show/search/usage; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
| Service | ServiceGroup | object list/get ServiceGroup | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Zone | object list/get Zone (typed Phase 3) | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Network | Interface | object list/get Interface | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Gateway | object list/get Gateway | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show | firewall_rule_list/show; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |
| Firewall | NATRule | object list/get NATRule; nat rule list/show | nat_rule_list/show; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |

Source references: Sophos 22.0 API docs, Sophos Postman collection, Sophos Python SDK behavior.
