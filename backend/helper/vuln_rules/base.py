from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from backend.helper.evidence.finding import FindingFactory
from backend.helper.evidence.http import HttpClient
from backend.helper.settings import RuntimeSettings


class BaseRule(Protocol):
    rule_id: str
    phase: str

    def evaluate(self, context: "RuleContext") -> list[dict]:
        ...


@dataclass
class RuleContext:
    settings: RuntimeSettings
    webscan: dict
    finding_factory: FindingFactory
    http_client: HttpClient
    target: str
    headers: dict[str, str]
    page: dict | None = None
    input_point: dict | None = None
    form: dict | None = None
    probe_failed: bool = False

    def new_id(self, prefix: str) -> str:
        return self.finding_factory.new_id(prefix)

    def finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        confidence: str,
        category: str,
        url: str,
        evidence: str,
        payloads: list[str],
        status: str,
        request_response: dict | None = None,
        details: dict | None = None,
    ) -> dict:
        details = {"rule_id": finding_id.rsplit("-", 1)[0], **(details or {})}
        return self.finding_factory.create(
            finding_id,
            title,
            severity,
            confidence,
            category,
            url,
            evidence,
            payloads,
            status,
            request_response=request_response,
            details=details,
        )
