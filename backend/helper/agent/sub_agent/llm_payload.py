from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

from backend.helper.llm.client import LLMClient
from backend.helper.settings import RuntimeSettings


ADVISORY_CATEGORIES = {
    "sqli": "sqli",
    "sql injection": "sqli",
    "sql_injection": "sqli",
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
}


@dataclass(frozen=True)
class FilteredPayload:
    input_point: str
    category: str
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
        if any(token in payload_lower for token in ("1=1", "1=2", " or ", " and ")):
            return "sqli_blind" if "1=2" in payload_lower else "sqli"
        if "<script" in payload_lower or "onerror=" in payload_lower or "svg/onload" in payload_lower:
            return "xss"
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
            true_payload = str(candidate.get("true_payload") or "").strip()
            false_payload = str(candidate.get("false_payload") or "").strip()
            if true_payload or false_payload:
                pair_index += 1
                pair_id = str(candidate.get("pair_id") or f"pair-{pair_index:03d}")
                for role, payload, signal_key in (
                    ("true", true_payload, "expected_true_signal"),
                    ("false", false_payload, "expected_false_signal"),
                ):
                    if not payload:
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

            payload = str(candidate.get("payload") or "").strip()
            if not payload:
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
        if not allowed:
            result["payload_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return result

    def _is_allowed(self, payload: str, category: str) -> tuple[bool, str]:
        lowered = payload.lower()
        if len(payload) > 300:
            return False, "payload 过长，第一版不进入报告复现步骤"
        for pattern, reason in self.DANGEROUS_PATTERNS:
            if re.search(pattern, lowered, re.I):
                return False, reason
        if category == "unknown":
            return False, "无法归类到允许的非破坏性测试类型"
        return True, "通过本地非破坏性 Safety Filter"

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
        elif self.settings.llm_enabled:
            llm_error = "本地/内网目标默认跳过 LLM 网络调用，可设置 NOVA_LLM_ON_LOCAL_TARGETS=true 开启"
        else:
            llm_error = "LLM 未配置或不可用"

        candidates = self._dedupe_candidates(local_candidates + llm_candidates)
        limited = self._limit_per_param(candidates)
        filtered = self.filter.filter_many(limited)

        status = "ok" if filtered else ("local_only" if local_candidates else "unavailable")
        message = "候选 Payload 已生成；第一版仅写入报告，不自动执行"
        if llm_error and local_candidates:
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
                "llm_candidates": len(llm_candidates),
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
        for point in self._collect_input_points(webscan):
            name = point.get("name", "")
            url = point.get("url", "")
            input_type = (point.get("type") or "").lower()
            hints = self._infer_categories(url, name, input_type, findings)
            for category in hints:
                candidates.extend(self._template_candidates(url, name, category))
        return candidates

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
                    "true_payload": "1' AND '1'='1' #",
                    "false_payload": "1' AND '1'='2' #",
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
        for candidate in candidates:
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
        for candidate in candidates:
            key = (str(candidate.get("input_point") or ""), str(candidate.get("target_param") or ""))
            counts[key] = counts.get(key, 0) + 1
            if counts[key] <= max_per_param:
                selected.append(candidate)
        return selected

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
            "SQL 盲注必须生成 true_payload 和 false_payload 成对候选，并写明 expected_true_signal 与 expected_false_signal。"
            "单条 payload 或单条 exists 响应不能证明 SQL 盲注。"
            "禁止生成 DROP、DELETE、UPDATE、INSERT、ALTER、TRUNCATE、INTO OUTFILE、LOAD_FILE、"
            "xp_cmdshell、反弹 shell、写文件、长时间 SLEEP/BENCHMARK。"
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
                    "categories": ["sqli", "sqli_blind", "xss", "lfi", "command_injection", "traversal"],
                    "max_per_param": self.settings.llm_payload_max_per_param,
                    "do_not_repeat_same_payload_for_all_inputs": True,
                    "blind_sqli_pair_schema": {
                        "true_payload": "string",
                        "false_payload": "string",
                        "expected_true_signal": "string",
                        "expected_false_signal": "string",
                    },
                },
                "output_schema": {
                    "payloads": [
                        {
                            "input_point": "url or form action",
                            "category": "sqli|sqli_blind|xss|lfi|command_injection|traversal",
                            "target_param": "parameter name",
                            "payload": "single candidate payload, or omit when using true/false pair",
                            "true_payload": "optional blind SQLi true case",
                            "false_payload": "optional blind SQLi false case",
                            "purpose": "Chinese short purpose",
                            "expected_signal": "Chinese expected response signal",
                            "expected_true_signal": "optional Chinese true signal",
                            "expected_false_signal": "optional Chinese false signal",
                            "risk_note": "Chinese short risk note",
                        }
                    ]
                },
            },
            ensure_ascii=False,
            indent=2,
        )
