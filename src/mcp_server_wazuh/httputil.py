"""Bounded HTTP helper. Raised errors never include headers or response bodies."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

_SECRET_PARTS = ("token", "password", "secret", "authorization", "jwt")


class HttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in _SECRET_PARTS):
                cleaned[str(key)] = "[REDACTED]"
            else:
                cleaned[str(key)] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):  # noqa: ANN001
        if 300 <= response.status < 400:
            raise HttpError(response.status)
        return response

    https_response = http_response


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    timeout: float,
    max_chars: int,
    verify: bool,
    body: bytes | None = None,
) -> Any:
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect())
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as response:
            raw = response.read(max_chars + 1)
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code) from None
    except HttpError:
        raise
    except Exception as exc:
        raise RuntimeError(type(exc).__name__) from None

    truncated = len(raw) > max_chars
    text = raw[:max_chars].decode("utf-8", errors="replace")
    if truncated:
        return {"truncated": True, "text": text}
    try:
        return json.loads(text) if text else {}
    except json.JSONDecodeError:
        return {"text": text}
