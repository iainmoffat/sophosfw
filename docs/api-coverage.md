# API coverage

| Area | XML Tag | CLI Command | MCP Tool | Get | Add | Update | Remove | Usage | Status |
|---|---|---|---|---|---|---|---|---|---|
| Host | IPHost | object list/get IPHost; host ip list/show/search/usage | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
| Host | IPHostGroup | object list/get IPHostGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | FQDNHost | object list/get FQDNHost (typed Phase 3) | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Host | FQDNHostGroup | object list/get FQDNHostGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Host | MACHost | object list/get MACHost (typed Phase 3) | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Service | Services | object list/get Services; service list/show/search/usage | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes (with --with-references) | Phase 3 |
| Service | ServiceGroup | object list/get ServiceGroup | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Zone | object list/get Zone (typed Phase 3) | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | Phase 3 |
| Network | Interface | object list/get Interface | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Network | Gateway | object list/get Gateway | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | yes | partial |
| Firewall | FirewallRule | object list/get FirewallRule; firewall rule list/show | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |
| Firewall | NATRule | object list/get NATRule; nat rule list/show | (Phase 4) | yes | Phase 6 | Phase 6 | Phase 6 | n/a | Phase 3 |

Source references: Sophos 22.0 API docs, Sophos Postman collection, Sophos Python SDK behavior.
