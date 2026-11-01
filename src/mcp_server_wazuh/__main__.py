import argparse

from . import __version__
from .server import main as run


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-server-wazuh",
        description="stdio MCP server for Wazuh 5. Reads the manager API (agents, groups, "
        "cluster, MITRE) and the indexer (events, findings, vulnerabilities). "
        "WAZUH_READ_ONLY defaults to true and hides restart_agents. "
        "Secrets: WAZUH_API_USER, WAZUH_API_PASSWORD, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args()
    run()


if __name__ == "__main__":
    main()
