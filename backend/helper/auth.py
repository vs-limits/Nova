from __future__ import annotations

import base64
import json
from pathlib import Path


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}


def parse_header_line(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise ValueError("Header must use the format 'Name: value'.")
    name, header_value = value.split(":", 1)
    name = name.strip()
    header_value = header_value.strip()
    if not name or not header_value:
        raise ValueError("Header name and value must not be empty.")
    return name, header_value


def load_auth_headers_file(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("NOVA_AUTH_HEADERS_FILE must contain a JSON object.")
    return {str(name): str(value) for name, value in data.items()}


def basic_auth_header(username: str | None, password: str | None) -> dict[str, str]:
    if not username or not password:
        return {}
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def redact_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADER_NAMES:
            redacted[name] = redact_secret(value)
        else:
            redacted[name] = value
    return redacted


def auth_summary(headers: dict[str, str]) -> dict:
    return {
        "configured": bool(headers),
        "header_names": sorted(headers),
        "redacted_headers": redact_headers(headers),
    }
