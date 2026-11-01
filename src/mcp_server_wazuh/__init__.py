"""MCP server for Wazuh 5 manager and indexer."""

try:
    from importlib.metadata import version

    __version__ = version("mcp-server-wazuh")
except Exception:  # pragma: no cover
    __version__ = "0.0.0+unknown"
