# API coverage

**MCP tools (Phase 4):** in addition to the per-tag mappings below, the
server registers `auth_status`, `auth_test`, `auth_profile_list`,
`auth_profile_current`, and `raw_get` (the latter exposes any catalog tag
including ones not listed above).

| Area | XML Tag | CLI Command | MCP Tool | Get | Add | Update | Remove | Usage | Status |
|---|---|---|---|---|---|---|---|---|---|
| Host | IPHost | object list/get IPHost; host ip list/show/search/usage/create/update/delete | host_ip_list/show/search/usage/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host ip create; host_ip_create) | yes (sophosfw host ip update; host_ip_update) | yes (sophosfw host ip delete; host_ip_delete) | yes (with --with-references) | Phase 6 |
| Host | IPHostGroup | object list/get IPHostGroup; host group create/update/delete | host_group_create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host group create; host_group_create) | yes (sophosfw host group update; host_group_update) | yes (sophosfw host group delete; host_group_delete) | yes | Phase 12 |
| Host | FQDNHost | object list/get FQDNHost (typed Phase 3); host fqdn create/update/delete | host_fqdn_create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host fqdn create; host_fqdn_create) | yes (sophosfw host fqdn update; host_fqdn_update) | yes (sophosfw host fqdn delete; host_fqdn_delete) | yes | Phase 12 |
| Host | FQDNHostGroup | object list/get FQDNHostGroup; host fqdn-group create/update/delete | host_fqdn_group_create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host fqdn-group create; host_fqdn_group_create) | yes (sophosfw host fqdn-group update; host_fqdn_group_update) | yes (sophosfw host fqdn-group delete; host_fqdn_group_delete) | yes | Phase 12 |
| Host | MACHost | object list/get MACHost (typed Phase 3); host mac create/update/delete | host_mac_create/update/delete; object_list/get/search/usage | yes | yes (sophosfw host mac create; host_mac_create) | yes (sophosfw host mac update; host_mac_update) | yes (sophosfw host mac delete; host_mac_delete) | yes | Phase 12 |
| Service | Services | object list/get Services; service list/show/search/usage; service create/update/delete | service_create/update/delete; service_list/show/search/usage; object_list/get/search/usage | yes | yes (sophosfw service create; service_create) | yes (sophosfw service update; service_update) | yes (sophosfw service delete; service_delete) | yes (with --with-references) | Phase 12 |
| Service | ServiceGroup | object list/get ServiceGroup; service group create/update/delete | service_group_create/update/delete; object_list/get/search/usage | yes | yes (sophosfw service group create; service_group_create) | yes (sophosfw service group update; service_group_update) | yes (sophosfw service group delete; service_group_delete) | yes | Phase 12 |
| Network | Zone | object list/get Zone (typed Phase 3) | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Network | Interface | object list/get Interface | object_list/get/search/usage | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | GatewayConfiguration | object list/get GatewayConfiguration (alias: gateway) | object_list/get/search/usage | yes | Phase 8 | Phase 8 | Phase 8 | yes | partial |
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show/new/pull/diff/push/delete | firewall_rule_list/show/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw firewall rule new; firewall_rule_create) | yes (sophosfw firewall rule push; firewall_rule_update) | yes (sophosfw firewall rule delete; firewall_rule_delete) | n/a | Phase 10 |
| Firewall | NATRule | object list/get NATRule; nat rule list/show/new/pull/diff/push/delete | nat_rule_list/show/create/update/delete; object_list/get/search/usage | yes | yes (sophosfw nat rule new; nat_rule_create) | yes (sophosfw nat rule push; nat_rule_update) | yes (sophosfw nat rule delete; nat_rule_delete) | n/a | Phase 10 |

Source references: Sophos 22.0 API docs, Sophos Postman collection, Sophos Python SDK behavior.
