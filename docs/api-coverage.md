# API coverage

**MCP tools (Phase 4):** in addition to the per-tag mappings below, the
server registers `auth_status`, `auth_test`, `auth_profile_list`,
`auth_profile_current`, and `raw_get` (the latter exposes any catalog tag
including ones not listed above).

| Area | XML Tag | CLI Command | MCP Tool | Get | Add | Update | Remove | Usage | Status |
|---|---|---|---|---|---|---|---|---|---|
| Host | IPHost | object list/get IPHost; host ip list/show/search/usage/create/update/delete | host_ip_list/show/search/usage/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host ip create; host_ip_create) | yes (sophosfw host ip update; host_ip_update) | yes (sophosfw host ip delete; host_ip_delete) | yes (with --with-references) | Phase 6 |
| Host | IPHostGroup | object list/get IPHostGroup | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | FQDNHost | object list/get FQDNHost (typed Phase 3) | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Host | FQDNHostGroup | object list/get FQDNHostGroup | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | MACHost | object list/get MACHost (typed Phase 3) | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Service | Services | object list/get Services; service list/show/search/usage | service_list/show/search/usage; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
| Service | ServiceGroup | object list/get ServiceGroup | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Zone | object list/get Zone (typed Phase 3) | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Network | Interface | object list/get Interface | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | GatewayConfiguration | object list/get GatewayConfiguration (alias: gateway) | object_list/get/search/usage | yes | Phase 8 | Phase 8 | Phase 8 | yes | partial |
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show/pull/diff/push/delete | firewall_rule_list/show; object_list/get/search/usage | yes | Phase 8 | yes (sophosfw firewall rule push) | yes (sophosfw firewall rule delete) | n/a | Phase 7 |
| Firewall | NATRule | object list/get NATRule; nat rule list/show | nat_rule_list/show; object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |

Source references: Sophos 22.0 API docs, Sophos Postman collection, Sophos Python SDK behavior.
