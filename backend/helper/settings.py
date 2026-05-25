from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os

from backend.helper.auth import basic_auth_header, load_auth_headers_file
from backend.helper.core import config as llm_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
HELPER_ROOT = Path(__file__).resolve().parent
PROMPTS_DIR = HELPER_ROOT / "prompts"
ARTIFACT_DIR = PROJECT_ROOT / ".Nova"
REPORT_DIR = PROJECT_ROOT / "reports"


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class RuntimeSettings:
    llm_baseurl: str | None
    llm_apikey: str | None
    llm_model: str | None
    llm_provider: str | None
    request_timeout: int = 10
    max_links: int = 30
    max_pages: int = 10
    max_depth: int = 1
    rate_limit: float = 0.2
    active_scan: bool = True
    active_request_timeout: float = 3.0
    max_active_inputs: int = 5
    llm_analysis: bool = True
    llm_on_local_targets: bool = True
    llm_payload_advisor: bool = True
    llm_payload_max_per_param: int = 5
    llm_payload_report_only: bool = True
    report_confirmed_only: bool = True
    allowed_hosts: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    auth_headers: dict[str, str] = field(default_factory=dict)

    @property
    def llm_enabled(self) -> bool:
        return all(
            [
                self.llm_baseurl,
                self.llm_apikey,
                self.llm_model,
                self.llm_provider,
            ]
        )


def load_runtime_settings() -> RuntimeSettings:
    auth_headers = load_auth_headers_file(os.getenv("NOVA_AUTH_HEADERS_FILE"))
    auth_headers.update(
        basic_auth_header(
            os.getenv("NOVA_BASIC_USER"),
            os.getenv("NOVA_BASIC_PASS"),
        )
    )
    return RuntimeSettings(
        llm_baseurl=llm_config.LLM_BASEURL,
        llm_apikey=llm_config.LLM_APIKEY,
        llm_model=llm_config.LLM_MODEL or "deepseekV4-flash",
        llm_provider=llm_config.LLM_PROVIDER,
        request_timeout=_env_int("NOVA_REQUEST_TIMEOUT", 10),
        max_links=_env_int("NOVA_MAX_LINKS", 30),
        max_pages=_env_int("NOVA_MAX_PAGES", 10),
        max_depth=_env_int("NOVA_MAX_DEPTH", 1),
        rate_limit=_env_float("NOVA_RATE_LIMIT", 0.2),
        active_scan=_env_bool("NOVA_ACTIVE_SCAN", True),
        active_request_timeout=_env_float("NOVA_ACTIVE_REQUEST_TIMEOUT", 3.0),
        max_active_inputs=_env_int("NOVA_MAX_ACTIVE_INPUTS", 5),
        llm_analysis=_env_bool("NOVA_LLM_ANALYSIS", True),
        llm_on_local_targets=_env_bool("NOVA_LLM_ON_LOCAL_TARGETS", True),
        llm_payload_advisor=_env_bool("NOVA_LLM_PAYLOAD_ADVISOR", True),
        llm_payload_max_per_param=_env_int("NOVA_LLM_PAYLOAD_MAX_PER_PARAM", 5),
        llm_payload_report_only=_env_bool("NOVA_LLM_PAYLOAD_REPORT_ONLY", True),
        report_confirmed_only=_env_bool("NOVA_REPORT_CONFIRMED_ONLY", True),
        allowed_hosts=_env_list("NOVA_ALLOWED_HOSTS"),
        exclude_paths=_env_list("NOVA_EXCLUDE_PATHS"),
        auth_headers=auth_headers,
    )
