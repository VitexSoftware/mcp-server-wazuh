import json
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_server_wazuh.client import WazuhClient
from mcp_server_wazuh.config import Config
from mcp_server_wazuh.server import build_server


def _config(**overrides) -> Config:
    data = dict(
        api_url="https://wazuh.example:55000",
        api_user="user",
        api_password="SECRET",
        indexer_url="https://indexer.example:9200",
        indexer_user="admin",
        indexer_password="INDEXSECRET",
        read_only=True,
        max_chars=5000,
    )
    data.update(overrides)
    return Config(**data)


class FakeClient(WazuhClient):
    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.calls: list[tuple] = []

    def manager(self, method, path, params=None, body=None):  # noqa: ANN001
        self.calls.append(("manager", method, path, params, body))
        return json.dumps({"data": {"token": "should-not-leak", "affected_items": []}})

    def indexer(self, index, body):  # noqa: ANN001
        self.calls.append(("indexer", index, body))
        return json.dumps({"hits": {"hits": []}, "password": "nope"})


def _tools(read_only: bool):
    client = FakeClient(_config(read_only=read_only))
    return client, build_server(client)


async def test_annotations_and_read_only_hides_restart():
    _, server = _tools(True)
    async with Client(server) as mcp:
        tools = await mcp.list_tools()
    names = {tool.name for tool in tools}
    assert "restart_agents" not in names
    assert "search_findings" in names
    assert "list_agents" in names
    for tool in tools:
        assert tool.title and tool.title != tool.name
        ann = tool.annotations
        assert None not in (ann.read_only_hint, ann.destructive_hint, ann.idempotent_hint, ann.open_world_hint)
        assert ann.read_only_hint is True
        assert not (ann.read_only_hint and ann.destructive_hint)
        if tool.name.startswith(("get_", "list_", "search_")):
            assert ann.read_only_hint is True


async def test_restart_registered_only_when_writes_enabled():
    _, server = _tools(False)
    async with Client(server) as mcp:
        tools = await mcp.list_tools()
    restart = next(tool for tool in tools if tool.name == "restart_agents")
    assert restart.annotations.destructive_hint is True
    assert restart.annotations.read_only_hint is False


async def test_list_agents_and_findings(monkeypatch):
    client, server = _tools(True)
    async with Client(server) as mcp:
        await mcp.call_tool("list_agents", {"status": "active", "limit": 2})
        await mcp.call_tool("search_findings", {"query": "rule.level:high", "agent_id": "001"})
    assert client.calls[0][1:] == ("GET", "/agents", {"limit": 2, "offset": 0, "status": "active"}, None)
    kind, index, body = client.calls[1]
    assert kind == "indexer"
    assert index == "wazuh-findings-v5*"
    assert body["query"]["bool"]["must"][1] == {"term": {"agent.id": "001"}}


async def test_invalid_agent_does_not_call():
    client, server = _tools(True)
    async with Client(server) as mcp:
        with pytest.raises(ToolError):
            await mcp.call_tool("get_agent", {"agent_id": "../etc"})
    assert client.calls == []


def test_auth_error_hides_password(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("password=SECRET Authorization: Basic abc")

    monkeypatch.setattr("mcp_server_wazuh.client.request_json", boom)
    client = WazuhClient(_config())
    with pytest.raises(RuntimeError) as exc:
        client.manager("GET", "/")
    assert "SECRET" not in str(exc.value)


def test_readme_lists_server_json_env():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text()
    manifest = json.loads((root / "debian" / "server.json").read_text())
    for item in manifest["environmentVariables"]:
        assert item["name"] in readme
