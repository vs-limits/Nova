from __future__ import annotations

from copy import deepcopy
import ipaddress
import json
import re
from urllib.parse import urlparse
from urllib.request import urlopen

from backend.helper.agent.sub_agent.llm_payload import LLMPayloadAdvisor
from backend.helper.evidence import (
    FindingFactory,
    HttpClient,
    IdFactory,
    STATUS_FAILED,
    STATUS_NOTICE,
)
from backend.helper.llm.client import LLMClient
from backend.helper.settings import RuntimeSettings, load_runtime_settings
from backend.helper.utils import utc_now
from backend.helper.vuln_rules import RuleRegistry


class AuditorAgent:
    def __init__(self, settings: RuntimeSettings | None = None, registry: RuleRegistry | None = None) -> None:
        self.settings = settings or load_runtime_settings()
        self.llm = LLMClient(self.settings)
        self.payload_advisor = LLMPayloadAdvisor(self.settings)
        self.registry = registry or RuleRegistry.default_rules()

    def audit(self, webscan: dict) -> dict:
        finding_factory = FindingFactory(IdFactory())
        http_client = HttpClient(self.settings, opener=urlopen)
        findings: list[dict] = []
        target = webscan.get("target", "")

        if self._auth_required_without_credentials(webscan):
            findings.append(
                finding_factory.create(
                    "NOVA-AUTH-000",
                    "目标需要登录态才能完整扫描",
                    "Info",
                    "High",
                    "authentication",
                    webscan.get("final_url") or target,
                    "TargetProbe 判断目标需要认证，但本次扫描未配置 Cookie、Authorization 或 Basic Auth。",
                    payloads=[],
                    status=STATUS_NOTICE,
                    details={"rule_id": "auth_required", "evidence_type": "target_probe"},
                )
            )

        if self._looks_like_login_page_without_credentials(webscan):
            findings.append(
                finding_factory.create(
                    "NOVA-AUTH-002",
                    "当前扫描停留在登录页，未进入目标业务页面",
                    "Info",
                    "High",
                    "authentication",
                    webscan.get("final_url") or target,
                    "扫描结果显示最终页面是登录页；未提供有效 Cookie/Authorization 时，NOVA 无法访问并验证登录后的漏洞页面。",
                    payloads=[],
                    status=STATUS_NOTICE,
                    details={
                        "rule_id": "auth_login_page",
                        "evidence_type": "login_page",
                        "confirmation_basis": "最终 URL 或页面标题包含 login，且未配置认证信息",
                    },
                )
            )

        if self._auth_looks_invalid(webscan):
            findings.append(
                finding_factory.create(
                    "NOVA-AUTH-001",
                    "认证信息可能无效或已过期",
                    "Info",
                    "Medium",
                    "authentication",
                    webscan.get("final_url") or target,
                    "TargetProbe 判断目标需要认证，但扫描结果仍停留在登录页或未获取到有效业务页面。",
                    payloads=[],
                    status=STATUS_NOTICE,
                    details={"rule_id": "auth_invalid", "evidence_type": "target_probe"},
                )
            )

        if not webscan.get("reachable"):
            findings.append(
                finding_factory.create(
                    "NOVA-000",
                    "目标不可访问",
                    "Info",
                    "High",
                    "availability",
                    target,
                    webscan.get("errors", [{}])[0].get("error", "请求失败。"),
                    payloads=[],
                    status=STATUS_FAILED,
                    details={"rule_id": "availability", "evidence_type": "request_error"},
                )
            )
            return self._result(webscan, findings, self.payload_advisor.generate(webscan, findings))

        findings.extend(self.registry.run(webscan, self.settings, finding_factory, http_client))

        llm_analysis = self._llm_analysis(webscan, findings)
        if llm_analysis:
            findings = self._merge_llm_analysis(findings, llm_analysis)

        llm_payload_advice = self.payload_advisor.generate(webscan, findings)
        return self._result(webscan, findings, llm_payload_advice)

    def _auth_looks_invalid(self, webscan: dict) -> bool:
        probe = webscan.get("target_probe", {})
        if not probe.get("auth_required"):
            return False
        if webscan.get("auth", {}).get("configured"):
            title = (webscan.get("title") or "").lower()
            final_url = (webscan.get("final_url") or "").lower()
            return "login" in title or "login" in final_url or not webscan.get("reachable")
        return False

    def _auth_required_without_credentials(self, webscan: dict) -> bool:
        probe = webscan.get("target_probe", {})
        if not probe.get("auth_required"):
            return False
        return not webscan.get("auth", {}).get("configured")

    def _looks_like_login_page_without_credentials(self, webscan: dict) -> bool:
        if webscan.get("auth", {}).get("configured"):
            return False
        title = str(webscan.get("title") or "").lower()
        final_url = str(webscan.get("final_url") or "").lower()
        target = str(webscan.get("target") or "").lower()
        if target and target == final_url:
            return False
        return "login" in title or "/login" in final_url or final_url.endswith("login.php")

    def _llm_analysis(self, webscan: dict, findings: list[dict]) -> dict:
        if not self.settings.llm_enabled or not self.settings.llm_analysis or not self._should_call_llm(webscan):
            return {}

        system_prompt = (
            "你是 NOVA 的中文安全审计助手。只返回严格 JSON。"
            "请基于已有扫描证据进行中文分析，指出可能的误报并给出中文修复建议。"
            "不要编造新的漏洞或证据。"
        )
        user_prompt = json.dumps(
            {
                "target": webscan.get("target"),
                "scope": webscan.get("scope", {}),
                "pages": webscan.get("pages", [])[:3],
                "findings": findings,
                "output_schema": {
                    "overall_summary": "string",
                    "finding_notes": [{"id": "string", "analysis": "string", "recommendation": "string"}],
                },
            },
            ensure_ascii=False,
            indent=2,
        )
        try:
            raw = self.llm.chat(system_prompt, user_prompt)
            if not raw.strip():
                return {}
            return json.loads(self._extract_json(raw))
        except Exception:
            return {}

    def _merge_llm_analysis(self, findings: list[dict], llm_payload: dict) -> list[dict]:
        notes = {item.get("id"): item for item in llm_payload.get("finding_notes", []) if isinstance(item, dict)}
        merged = []
        for finding in findings:
            item = deepcopy(finding)
            note = notes.get(item.get("id"))
            if note:
                item["llm_analysis"] = note.get("analysis", "")
                item["recommendation"] = note.get("recommendation", "")
            merged.append(item)
        return merged

    def _result(self, webscan: dict, findings: list[dict], llm_payload_advice: dict | None = None) -> dict:
        advice = llm_payload_advice or self.payload_advisor.generate(webscan, findings)
        return {
            "agent": "Auditor Agent",
            "target": webscan.get("target"),
            "audited_at": utc_now(),
            "findings": findings,
            "llm_payload_advice": advice.get("items", []),
            "llm_payload_summary": {
                "enabled": advice.get("enabled", False),
                "status": advice.get("status", "unavailable"),
                "message": advice.get("message", ""),
                "report_only": advice.get("report_only", True),
                **advice.get("summary", {}),
            },
            "summary": {
                "risk_level": self._risk_level(findings),
                "total_findings": len(findings),
                "llm_enabled": self.settings.llm_enabled,
                "llm_payload_advisor": self.settings.llm_payload_advisor,
                "confirmed": len([item for item in findings if item.get("status") == "确认漏洞"]),
                "suspected": len([item for item in findings if item.get("status") == "疑似漏洞"]),
            },
        }

    def _risk_level(self, findings: list[dict]) -> str:
        order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        if not findings:
            return "Info"
        return max(findings, key=lambda item: order.get(item.get("severity", "Info"), 0)).get("severity", "Info")

    def _extract_json(self, raw: str) -> str:
        match = re.search(r"\{.*\}", raw, re.S)
        return match.group(0) if match else raw

    def _should_call_llm(self, webscan: dict) -> bool:
        if self.settings.llm_on_local_targets:
            return True
        target = str(webscan.get("final_url") or webscan.get("target") or "")
        host = urlparse(target).hostname or ""
        if host.lower() in {"localhost"}:
            return False
        try:
            address = ipaddress.ip_address(host)
            return not (address.is_loopback or address.is_private or address.is_link_local)
        except ValueError:
            return True
