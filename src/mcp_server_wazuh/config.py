"""Configuration from WAZUH_* environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

_TRUE = {"1", "true", "yes", "on"}


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in _TRUE


def _url(name: str, default: str) -> str:
    return os.environ.get(name, default).rstrip("/")


@dataclass(frozen=True)
class Config:
    api_url: str = "https://127.0.0.1:55000"
    api_user: str = field(default="", repr=False)
    api_password: str = field(default="", repr=False)
    indexer_url: str = "https://127.0.0.1:9200"
    indexer_user: str = field(default="", repr=False)
    indexer_password: str = field(default="", repr=False)
    timeout: float = 30.0
    verify_tls: bool = True
    read_only: bool = True
    max_chars: int = 100_000
    events_index: str = "wazuh-events-v5*"
    findings_index: str = "wazuh-findings-v5*"
    vuln_index: str = "wazuh-states-vulnerabilities"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            api_url=_url("WAZUH_API_URL", cls.api_url),
            api_user=os.environ.get("WAZUH_API_USER", ""),
            api_password=os.environ.get("WAZUH_API_PASSWORD", ""),
            indexer_url=_url("WAZUH_INDEXER_URL", cls.indexer_url),
            indexer_user=os.environ.get("WAZUH_INDEXER_USER", ""),
            indexer_password=os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
            timeout=float(os.environ.get("WAZUH_TIMEOUT", "30")),
            verify_tls=_flag("WAZUH_VERIFY_TLS", True),
            read_only=_flag("WAZUH_READ_ONLY", True),
            max_chars=int(os.environ.get("WAZUH_MAX_CHARS", "100000")),
            events_index=os.environ.get("WAZUH_EVENTS_INDEX", cls.events_index),
            findings_index=os.environ.get("WAZUH_FINDINGS_INDEX", cls.findings_index),
            vuln_index=os.environ.get("WAZUH_VULN_INDEX", cls.vuln_index),
        )
