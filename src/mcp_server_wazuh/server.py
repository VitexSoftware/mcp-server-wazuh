"""Wazuh 5 MCP tools.

Public Wazuh MCP servers (gbrigandi/mcp-server-wazuh, RayaSatriatama/wazuh-mcp-server,
socfortress/wazuh-mcp-server) call Wazuh 4 manager paths that 5.0 removed
(/manager, /rules, /syscheck, /vulnerability, /sca). This server uses the
5.0 manager API plus indexer data streams.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from .annotations import MUTATE_ANNOTATIONS, READ_ONLY_ANNOTATIONS
from .client import WazuhClient
from .config import Config

_AGENT = r"^[A-Za-z0-9_.:-]{1,64}$"


def _limit(value: int) -> int:
    if not 1 <= value <= 100:
        raise ValueError("Limit must be between 1 and 100")
    return value


def _offset(value: int) -> int:
    if not 0 <= value <= 10000:
        raise ValueError("Offset must be between 0 and 10000")
    return value


def _query(value: str) -> str:
    if len(value) > 2000:
        raise ValueError("Query must be at most 2000 characters")
    return value


def _agent_id(value: str) -> str:
    import re

    if not re.fullmatch(_AGENT, value):
        raise ValueError("Agent id contains unsupported characters")
    return value


# Wazuh 5 data streams keep the agent under wazuh.agent; the 4.x-style state
# indices use agent. Match either so one filter works on every index.
_AGENT_FIELDS = ("wazuh.agent.id", "agent.id")


def _agent_filter(agent_id: str) -> dict[str, Any]:
    value = _agent_id(agent_id)
    return {
        "bool": {
            "should": [{"term": {field: value}} for field in _AGENT_FIELDS],
            "minimum_should_match": 1,
        }
    }


def _search_body(
    query: str,
    limit: int,
    offset: int,
    agent_id: str | None,
    sort_field: str = "@timestamp",
) -> dict[str, Any]:
    must: list[dict[str, Any]] = []
    if query.strip():
        must.append({"query_string": {"query": query}})
    else:
        must.append({"match_all": {}})
    if agent_id:
        must.append(_agent_filter(agent_id))
    return {
        "size": _limit(limit),
        "from": _offset(offset),
        # unmapped_type keeps the query working on an index (or a fresh, empty
        # one) that lacks the sort field, instead of failing the whole search.
        "sort": [{sort_field: {"order": "desc", "unmapped_type": "date"}}],
        "query": {"bool": {"must": must}},
    }


def build_server(client: WazuhClient) -> FastMCP:
    config = client.config
    mcp = FastMCP("mcp-server-wazuh", instructions="Read Wazuh 5 agents, cluster data, events, findings and vulnerabilities.")

    @mcp.tool(name="get_api_info", title="API Info", annotations=READ_ONLY_ANNOTATIONS)
    def get_api_info() -> str:
        """Read the Wazuh manager API root. Confirms the host and the running build."""
        return client.manager("GET", "/")

    @mcp.tool(name="list_agents", title="List Agents", annotations=READ_ONLY_ANNOTATIONS)
    def list_agents(
        limit: Annotated[int, Field(description="Page size, from 1 to 100")] = 25,
        offset: Annotated[int, Field(description="Result offset, from 0 to 10000")] = 0,
        status: Annotated[str | None, Field(description="Optional agent status: active, disconnected, pending, or never_connected")] = None,
        search: Annotated[str | None, Field(description="Optional manager search string, at most 200 characters")] = None,
    ) -> str:
        """List agents from the Wazuh 5 manager API."""
        params: dict[str, Any] = {"limit": _limit(limit), "offset": _offset(offset)}
        if status is not None:
            if status not in {"active", "disconnected", "pending", "never_connected"}:
                raise ValueError("Status must be active, disconnected, pending, or never_connected")
            params["status"] = status
        if search is not None:
            if len(search) > 200:
                raise ValueError("Search must be at most 200 characters")
            params["search"] = search
        return client.manager("GET", "/agents", params)

    @mcp.tool(name="get_agent", title="Get Agent", annotations=READ_ONLY_ANNOTATIONS)
    def get_agent(
        agent_id: Annotated[str, Field(description="Agent id, such as 001")],
    ) -> str:
        """Read one agent from the manager API."""
        return client.manager("GET", f"/agents/{_agent_id(agent_id)}")

    @mcp.tool(name="get_agents_summary", title="Agents Summary", annotations=READ_ONLY_ANNOTATIONS)
    def get_agents_summary() -> str:
        """Read agent counts grouped by status."""
        return client.manager("GET", "/agents/summary")

    @mcp.tool(name="list_groups", title="List Groups", annotations=READ_ONLY_ANNOTATIONS)
    def list_groups(
        limit: Annotated[int, Field(description="Page size, from 1 to 100")] = 25,
        offset: Annotated[int, Field(description="Result offset, from 0 to 10000")] = 0,
    ) -> str:
        """List agent groups."""
        return client.manager("GET", "/groups", {"limit": _limit(limit), "offset": _offset(offset)})

    @mcp.tool(name="get_cluster_status", title="Cluster Status", annotations=READ_ONLY_ANNOTATIONS)
    def get_cluster_status() -> str:
        """Read whether the manager cluster is enabled and healthy."""
        return client.manager("GET", "/cluster/status")

    @mcp.tool(name="list_cluster_nodes", title="List Cluster Nodes", annotations=READ_ONLY_ANNOTATIONS)
    def list_cluster_nodes() -> str:
        """List Wazuh cluster nodes."""
        return client.manager("GET", "/cluster/nodes")

    @mcp.tool(name="search_mitre", title="Search MITRE", annotations=READ_ONLY_ANNOTATIONS)
    def search_mitre(
        limit: Annotated[int, Field(description="Page size, from 1 to 100")] = 25,
        offset: Annotated[int, Field(description="Result offset, from 0 to 10000")] = 0,
    ) -> str:
        """List MITRE techniques known to the manager."""
        return client.manager("GET", "/mitre/techniques", {"limit": _limit(limit), "offset": _offset(offset)})

    @mcp.tool(name="search_events", title="Search Events", annotations=READ_ONLY_ANNOTATIONS)
    def search_events(
        query: Annotated[str, Field(description="OpenSearch query_string. Empty matches all events.")] = "",
        limit: Annotated[int, Field(description="Page size, from 1 to 100")] = 25,
        offset: Annotated[int, Field(description="Result offset, from 0 to 10000")] = 0,
        agent_id: Annotated[str | None, Field(description="Optional agent id filter")] = None,
    ) -> str:
        """Search the wazuh-events-v5 data stream on the indexer."""
        return client.indexer(config.events_index, _search_body(_query(query), limit, offset, agent_id))

    @mcp.tool(name="search_findings", title="Search Findings", annotations=READ_ONLY_ANNOTATIONS)
    def search_findings(
        query: Annotated[str, Field(description="OpenSearch query_string. Empty matches all findings.")] = "",
        limit: Annotated[int, Field(description="Page size, from 1 to 100")] = 25,
        offset: Annotated[int, Field(description="Result offset, from 0 to 10000")] = 0,
        agent_id: Annotated[str | None, Field(description="Optional agent id filter")] = None,
    ) -> str:
        """Search rule matches in the wazuh-findings-v5 data stream. Wazuh 5 calls these findings, not alerts."""
        return client.indexer(config.findings_index, _search_body(_query(query), limit, offset, agent_id))

    @mcp.tool(name="search_vulnerabilities", title="Search Vulnerabilities", annotations=READ_ONLY_ANNOTATIONS)
    def search_vulnerabilities(
        query: Annotated[str, Field(description="OpenSearch query_string. Empty matches the vulnerability state index.")] = "",
        limit: Annotated[int, Field(description="Page size, from 1 to 100")] = 25,
        offset: Annotated[int, Field(description="Result offset, from 0 to 10000")] = 0,
        agent_id: Annotated[str | None, Field(description="Optional agent id filter")] = None,
    ) -> str:
        """Search the wazuh-states-vulnerabilities index, newest detections first. Example query: vulnerability.severity:Critical"""
        return client.indexer(
            config.vuln_index,
            _search_body(_query(query), limit, offset, agent_id, sort_field="vulnerability.detected_at"),
        )

    if not config.read_only:

        @mcp.tool(name="restart_agents", title="Restart Agents", annotations=MUTATE_ANNOTATIONS)
        def restart_agents(
            agent_ids: Annotated[str, Field(description="Comma-separated agent ids, or 'all'. Restarts the Wazuh agent process. Ask the user before calling.")],
        ) -> str:
            """Restart selected Wazuh agents. This interrupts the agent. Wazuh 5 may reject the call if the endpoint is unavailable. Ask the user before calling."""
            ids = [part.strip() for part in agent_ids.split(",") if part.strip()]
            if not ids or len(ids) > 100:
                raise ValueError("Provide 1 to 100 agent ids, or 'all'")
            if ids != ["all"]:
                ids = [_agent_id(part) for part in ids]
            return client.manager("PUT", "/agents/restart", {"agents_list": ",".join(ids)})

    return mcp


def main() -> None:
    build_server(WazuhClient(Config.from_env())).run(transport="stdio")
