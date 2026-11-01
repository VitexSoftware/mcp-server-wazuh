---
name: wazuh-mcp
description: Inspect a Wazuh 5 deployment through mcp-server-wazuh. Use for agents, cluster status, events, findings and vulnerabilities.
---

This server talks to Wazuh 5, not 4.x. Findings are rule matches (`search_findings`); raw logs are `search_events`. Do not look for `wazuh-alerts-*` or `/manager` paths. `restart_agents` is hidden while `WAZUH_READ_ONLY=true`; ask the user before turning that off. Keep searches narrow (query, agent id, limit at most 100).
