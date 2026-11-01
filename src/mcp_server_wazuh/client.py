"""Wazuh 5 manager (JWT) and indexer (basic auth) clients."""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib.parse import quote, urlencode

from .config import Config
from .httputil import HttpError, redact, request_json

_INDEX_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.*-")


class WazuhClient:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._token = ""
        self._token_at = 0.0

    def manager(self, method: str, path: str, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None) -> str:
        self._check_base(self.config.api_url, "WAZUH_API_URL")
        if not self.config.api_user or not self.config.api_password:
            raise RuntimeError("WAZUH_API_USER and WAZUH_API_PASSWORD are required")
        url = self.config.api_url + path
        if params:
            url += "?" + urlencode(params)
        payload = self._manager_request(method, url, body, retry=True)
        return self._dump(payload)

    def indexer(self, index: str, body: dict[str, Any]) -> str:
        self._check_base(self.config.indexer_url, "WAZUH_INDEXER_URL")
        if not self.config.indexer_user or not self.config.indexer_password:
            raise RuntimeError("WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD are required")
        if not index or any(char not in _INDEX_OK for char in index):
            raise ValueError("Index name contains unsupported characters")
        url = f"{self.config.indexer_url}/{quote(index, safe='*')}/_search"
        token = base64.b64encode(f"{self.config.indexer_user}:{self.config.indexer_password}".encode()).decode()
        payload = request_json(
            "POST",
            url,
            headers={"Authorization": f"Basic {token}", "Accept": "application/json", "Content-Type": "application/json"},
            timeout=self.config.timeout,
            max_chars=self.config.max_chars,
            verify=self.config.verify_tls,
            body=json.dumps(body).encode(),
        )
        return self._dump(payload)

    def _manager_request(self, method: str, url: str, body: dict[str, Any] | None, retry: bool) -> Any:
        raw = None if body is None else json.dumps(body).encode()
        headers = {
            "Authorization": f"Bearer {self._jwt()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            return request_json(
                method,
                url,
                headers=headers,
                timeout=self.config.timeout,
                max_chars=self.config.max_chars,
                verify=self.config.verify_tls,
                body=raw,
            )
        except HttpError as exc:
            if exc.status == 401 and retry:
                self._token = ""
                return self._manager_request(method, url, body, retry=False)
            raise RuntimeError(f"Wazuh API request failed (HTTP {exc.status})") from None
        except RuntimeError:
            raise
        except Exception:
            raise RuntimeError("Wazuh API request failed") from None

    def _jwt(self) -> str:
        if self._token and (time.monotonic() - self._token_at) < 800:
            return self._token
        basic = base64.b64encode(f"{self.config.api_user}:{self.config.api_password}".encode()).decode()
        try:
            payload = request_json(
                "POST",
                f"{self.config.api_url}/security/user/authenticate",
                headers={"Authorization": f"Basic {basic}", "Accept": "application/json"},
                timeout=self.config.timeout,
                max_chars=self.config.max_chars,
                verify=self.config.verify_tls,
            )
        except HttpError as exc:
            raise RuntimeError(f"Wazuh authentication failed (HTTP {exc.status})") from None
        except Exception:
            raise RuntimeError("Wazuh authentication failed") from None
        token = ""
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                token = str(data.get("token") or "")
            elif isinstance(payload.get("token"), str):
                token = payload["token"]
        if not token:
            raise RuntimeError("Wazuh API did not return an authentication token")
        self._token = token
        self._token_at = time.monotonic()
        return token

    def _dump(self, payload: Any) -> str:
        text = json.dumps(redact(payload), default=str)
        if len(text) > self.config.max_chars:
            return text[: self.config.max_chars] + f"\n[truncated: output exceeded {self.config.max_chars} characters]"
        return text

    @staticmethod
    def _check_base(url: str, name: str) -> None:
        if not url.startswith(("https://", "http://")):
            raise RuntimeError(f"{name} must start with http:// or https://")
