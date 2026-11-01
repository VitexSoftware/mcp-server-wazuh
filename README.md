# mcp-server-wazuh

stdio MCP server for **Wazuh 5**. It reads the manager API on port 55000 (agents, groups, cluster, MITRE) and the indexer on port 9200 (events, findings, vulnerability state).

Wazuh 5 removed the 4.x manager paths `/manager`, `/rules`, `/syscheck`, `/sca` and `/vulnerability`. Existing public servers such as `gbrigandi/mcp-server-wazuh` still call those paths, so this package talks to the 5.0 API instead of forking them. Rule matches are **findings** in `wazuh-findings-v5*`, not `wazuh-alerts-*`.

## Install

    apt install mcp-server-wazuh
    apt install mcprack-mcp-server-wazuh

## Environment

| Variable | Secret | Default | Meaning |
|---|---|---|---|
| `WAZUH_API_URL` | no | `https://127.0.0.1:55000` | Manager API base URL |
| `WAZUH_API_USER` | yes | – | API user. Used once to obtain a JWT |
| `WAZUH_API_PASSWORD` | yes | – | API password |
| `WAZUH_INDEXER_URL` | no | `https://127.0.0.1:9200` | Indexer base URL |
| `WAZUH_INDEXER_USER` | yes | – | Indexer user |
| `WAZUH_INDEXER_PASSWORD` | yes | – | Indexer password |
| `WAZUH_READ_ONLY` | no | `true` | Hide `restart_agents` |
| `WAZUH_VERIFY_TLS` | no | `true` | Verify manager and indexer certificates |
| `WAZUH_TIMEOUT` | no | `30` | Seconds per request |
| `WAZUH_MAX_CHARS` | no | `100000` | Truncate larger tool output |
| `WAZUH_EVENTS_INDEX` | no | `wazuh-events-v5*` | Events data stream |
| `WAZUH_FINDINGS_INDEX` | no | `wazuh-findings-v5*` | Findings data stream |
| `WAZUH_VULN_INDEX` | no | `wazuh-states-vulnerabilities` | Vulnerability state index |

The JWT is refreshed in-process and is never printed. A 401 fetches a new token once.

## Tools

| Tool | Title | Annotation | Backend |
|---|---|---|---|
| `get_api_info` | API Info | read-only | manager `GET /` |
| `list_agents` | List Agents | read-only | manager `GET /agents` |
| `get_agent` | Get Agent | read-only | manager `GET /agents/{id}` |
| `get_agents_summary` | Agents Summary | read-only | manager `GET /agents/summary` |
| `list_groups` | List Groups | read-only | manager `GET /groups` |
| `get_cluster_status` | Cluster Status | read-only | manager `GET /cluster/status` |
| `list_cluster_nodes` | List Cluster Nodes | read-only | manager `GET /cluster/nodes` |
| `search_mitre` | Search MITRE | read-only | manager `GET /mitre/techniques` |
| `search_events` | Search Events | read-only | indexer |
| `search_findings` | Search Findings | read-only | indexer |
| `search_vulnerabilities` | Search Vulnerabilities | read-only | indexer |
| `restart_agents` | Restart Agents | destructive | manager, only when `WAZUH_READ_ONLY=false` |

`restart_agents` interrupts agents. Ask before calling it. Wazuh 5 may reject the restart endpoint.

## Development

    PYTHONPATH=src python3 -m pytest
