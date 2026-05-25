from __future__ import annotations

from copy import deepcopy
import ipaddress
import json
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from backend.helper.agent.sub_agent.llm_payload import LLMPayloadAdvisor
from backend.helper.llm.client import LLMClient
from backend.helper.settings import RuntimeSettings, load_runtime_settings
from backend.helper.utils import utc_now
from backend.helper.vuln_types import category_group, category_label


STATUS_CONFIRMED = "确认漏洞"
STATUS_SUSPECTED = "疑似漏洞"
STATUS_PENDING = "待验证"
STATUS_CONFIG = "配置建议"
STATUS_INFO = "信息提示"
STATUS_FAILED = "扫描失败"
STATUS_NOTICE = "扫描提示"
SQL_COMMENT_SUFFIX = "-- -"


SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"mysqli?_fetch",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"odbc.*driver",
    r"ora-\d{5}",
    r"postgresql.*error",
    r"sqlite.*error",
    r"unknown column",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
]


class AuditorAgent:
    def __init__(self, settings: RuntimeSettings | None = None) -> None:
        self.settings = settings or load_runtime_settings()
        self.llm = LLMClient(self.settings)
        self.payload_advisor = LLMPayloadAdvisor(self.settings)
        self._last_probe_failed = False

    def audit(self, webscan: dict) -> dict:
        findings: list[dict] = []
        target = webscan.get("target", "")
        headers = {key.lower(): value for key, value in webscan.get("headers", {}).items()}
        pages = webscan.get("pages", []) or [webscan]

        if self._auth_required_without_credentials(webscan):
            findings.append(
                self._finding(
                    "NOVA-AUTH-000",
                    "目标需要登录态才能完整扫描",
                    "Info",
                    "High",
                    "authentication",
                    webscan.get("final_url") or target,
                    "TargetProbe 判断目标需要认证，但本次扫描未配置 Cookie、Authorization 或 Basic Auth。",
                    payloads=[],
                    status=STATUS_NOTICE,
                )
            )

        if self._auth_looks_invalid(webscan):
            findings.append(
                self._finding(
                    "NOVA-AUTH-001",
                    "认证信息可能无效或已过期",
                    "Info",
                    "Medium",
                    "authentication",
                    webscan.get("final_url") or target,
                    "TargetProbe 判断目标需要认证，但扫描结果仍停留在登录页或未获取到有效业务页面。",
                    payloads=[],
                    status=STATUS_NOTICE,
                )
            )

        if not webscan.get("reachable"):
            findings.append(
                self._finding(
                    "NOVA-000",
                    "目标不可访问",
                    "Info",
                    "High",
                    "availability",
                    target,
                    webscan.get("errors", [{}])[0].get("error", "请求失败。"),
                    payloads=[],
                    status=STATUS_FAILED,
                )
            )
            return self._result(webscan, findings, self.payload_advisor.generate(webscan, findings))

        findings.extend(self._check_security_headers(target, headers))
        findings.extend(self._check_cookie_flags(target, webscan.get("cookies", [])))
        findings.extend(self._check_forms(target, webscan.get("forms", [])))
        findings.extend(self._check_input_points(pages))

        llm_analysis = self._llm_analysis(webscan, findings)
        if llm_analysis:
            findings = self._merge_llm_analysis(findings, llm_analysis)

        llm_payload_advice = self.payload_advisor.generate(webscan, findings)
        return self._result(webscan, findings, llm_payload_advice)

    def _check_security_headers(self, target: str, headers: dict[str, str]) -> list[dict]:
        findings: list[dict] = []
        checks = {
            "content-security-policy": ("缺少 Content-Security-Policy 响应头", "Medium", "High"),
            "x-frame-options": ("缺少 X-Frame-Options 响应头", "Low", "High"),
            "x-content-type-options": ("缺少 X-Content-Type-Options 响应头", "Low", "High"),
            "referrer-policy": ("缺少 Referrer-Policy 响应头", "Low", "Medium"),
        }
        for header, (title, severity, confidence) in checks.items():
            if header not in headers:
                findings.append(
                    self._finding(
                        self._new_id("H", len(findings) + 1),
                        title,
                        severity,
                        confidence,
                        "security_header",
                        target,
                        f"响应头中未包含 {header}。",
                        payloads=[],
                        status=STATUS_CONFIG,
                    )
                )

        if "server" in headers:
            findings.append(
                self._finding(
                    "NOVA-I-001",
                    "Server 响应头信息泄露",
                    "Low",
                    "High",
                    "information_disclosure",
                    target,
                    f"响应中暴露了 Server 头：{headers['server']}",
                    payloads=[],
                    status=STATUS_INFO,
                )
            )
        if "x-powered-by" in headers:
            findings.append(
                self._finding(
                    "NOVA-I-002",
                    "X-Powered-By 响应头信息泄露",
                    "Low",
                    "High",
                    "information_disclosure",
                    target,
                    f"响应中暴露了 X-Powered-By 头：{headers['x-powered-by']}",
                    payloads=[],
                    status=STATUS_INFO,
                )
            )
        return findings

    def _check_cookie_flags(self, target: str, cookies: list[dict]) -> list[dict]:
        findings: list[dict] = []
        for index, cookie in enumerate(cookies, start=1):
            missing_flags = []
            if not cookie.get("secure"):
                missing_flags.append("Secure")
            if not cookie.get("httponly"):
                missing_flags.append("HttpOnly")
            if not cookie.get("samesite"):
                missing_flags.append("SameSite")
            if missing_flags:
                findings.append(
                    self._finding(
                        f"NOVA-C-{index:03d}",
                        f"Cookie 缺少安全属性：{cookie.get('name', 'unknown')}",
                        "Low",
                        "Medium",
                        "cookie",
                        target,
                        f"Cookie 缺少以下属性：{', '.join(missing_flags)}",
                        payloads=[],
                        status=STATUS_CONFIG,
                    )
                )
        return findings

    def _check_forms(self, target: str, forms: list[dict]) -> list[dict]:
        findings: list[dict] = []
        for index, form in enumerate(forms, start=1):
            method = form.get("method", "GET").upper()
            input_names = [item.get("name", "").lower() for item in form.get("inputs", [])]
            has_csrf = any("csrf" in name or "token" in name for name in input_names)
            if method != "GET" and not has_csrf:
                findings.append(
                    self._finding(
                        f"NOVA-F-{index:03d}",
                        "表单缺少明显的 CSRF Token",
                        "Medium",
                        "Medium",
                        "csrf",
                        form.get("action", target),
                        "表单中未发现名称类似 csrf 或 token 的输入字段。",
                        payloads=["无 Token 的状态变更请求"],
                        status=STATUS_SUSPECTED,
                    )
                )
        return findings

    def _check_input_points(self, pages: list[dict]) -> list[dict]:
        findings: list[dict] = []
        seen: set[tuple[str, str]] = set()
        active_inputs = 0
        for page in pages:
            for input_point in page.get("input_points", []):
                if input_point.get("method", "GET").upper() != "GET":
                    continue
                name = input_point.get("name", "")
                url = input_point.get("url", "")
                if not name or not url:
                    continue
                key = (url, name)
                if key in seen:
                    continue
                seen.add(key)

                if not input_point.get("active_testable", True):
                    continue
                active_inputs += 1
                if active_inputs > self.settings.max_active_inputs:
                    findings.append(
                        self._finding(
                            self._new_id("Q", len(findings) + 1),
                            "主动探测输入点数量达到上限",
                            "Info",
                            "High",
                            "scanner_limit",
                            url,
                            f"为避免靶场或本地服务卡死，本次最多主动探测 {self.settings.max_active_inputs} 个输入点，后续输入点已跳过。",
                            payloads=[],
                            status=STATUS_NOTICE,
                        )
                    )
                    return findings

                context_params = input_point.get("form_defaults", {})
                self._last_probe_failed = False
                sqli_finding = (
                    self._probe_sqli(url, name, context_params, len(findings) + 1)
                    if self.settings.active_scan
                    else None
                )
                if sqli_finding:
                    findings.append(sqli_finding)
                    continue
                if self._last_probe_failed:
                    findings.append(
                        self._finding(
                            self._new_id("Q", len(findings) + 1),
                            "输入点主动探测请求失败或超时",
                            "Info",
                            "Medium",
                            "scanner_limit",
                            url,
                            f"参数 {name} 的基线或单引号探测请求失败，NOVA 已停止对该输入点继续发送更多 payload，避免扫描长时间卡住。",
                            payloads=[],
                            status=STATUS_NOTICE,
                        )
                    )
                    continue

                reflection = (
                    self._probe_reflection(url, name, context_params, len(findings) + 1)
                    if self.settings.active_scan
                    else None
                )
                if reflection:
                    findings.append(reflection)
                    continue

                findings.append(
                    self._finding(
                        self._new_id("Q", len(findings) + 1),
                        "URL 参数需要注入风险验证",
                        "Low",
                        "Medium",
                        "injection",
                        url,
                        f"目标 URL 或 GET 表单中发现参数：{name}。",
                        payloads=["'", "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"],
                        status=STATUS_PENDING,
                    )
                )
        return findings

    def _probe_sqli(self, url: str, param: str, context_params: dict, finding_index: int) -> dict | None:
        self._last_probe_failed = False
        baseline = self._http_get(self._mutate_url(url, param, "1", context_params))
        if not baseline:
            self._last_probe_failed = True
            return None
        quote_probe = self._http_get(self._mutate_url(url, param, "1'", context_params))
        if not quote_probe:
            self._last_probe_failed = True
            return None
        if quote_probe and self._has_sql_error(quote_probe.get("body", "")):
            followup = self._sqli_error_followup(url, param, context_params)
            payloads = ["1'", *followup.get("payloads", [])]
            details = self._sqli_details(quote_probe.get("body", ""), followup)
            evidence = "单引号 payload 触发了数据库错误特征。"
            if followup.get("column_count"):
                evidence += f" ORDER BY 探测推测列数为 {followup['column_count']}。"
            if followup.get("union_marker_reflected"):
                evidence += " UNION SELECT 标记在响应中回显，说明可继续做联合查询型验证。"
            return self._finding(
                self._new_id("SQLI", finding_index),
                "确认存在 SQL 注入错误回显",
                "High",
                "High",
                "sqli",
                quote_probe["url"],
                evidence,
                payloads=payloads,
                status=STATUS_CONFIRMED,
                request_response={
                    "error_probe": self._evidence_block(quote_probe, matched="SQL error pattern"),
                    "followup": followup,
                    "sqli_details": details,
                },
                details=details,
            )

        payload_pairs = [
            ("1 AND 1=1", "1 AND 1=2"),
            (f"1' AND '1'='1' {SQL_COMMENT_SUFFIX}", f"1' AND '1'='2' {SQL_COMMENT_SUFFIX}"),
            (f"1' AND 1=1 {SQL_COMMENT_SUFFIX}", f"1' AND 1=2 {SQL_COMMENT_SUFFIX}"),
        ]
        for true_payload, false_payload in payload_pairs:
            true_probe = self._http_get(self._mutate_url(url, param, true_payload, context_params))
            false_probe = self._http_get(self._mutate_url(url, param, false_payload, context_params))
            if not true_probe or not false_probe:
                self._last_probe_failed = True
                return None
            if baseline and true_probe and false_probe:
                true_score = self._similarity_score(baseline["body"], true_probe["body"])
                false_score = self._similarity_score(baseline["body"], false_probe["body"])
                if true_score >= 0.90 and false_score <= 0.75 and abs(true_score - false_score) >= 0.20:
                    return self._finding(
                        self._new_id("SQLI", finding_index),
                        "疑似布尔型 SQL 注入",
                        "High",
                        "Medium",
                        "sqli_blind",
                        false_probe["url"],
                        f"布尔条件响应存在明显差异：true 相似度 {true_score:.2f}，false 相似度 {false_score:.2f}。",
                        payloads=[true_payload, false_payload],
                        status=STATUS_SUSPECTED,
                        request_response={
                            "baseline": self._evidence_block(baseline),
                            "true_case": self._evidence_block(true_probe, matched=f"similarity={true_score:.2f}"),
                            "false_case": self._evidence_block(false_probe, matched=f"similarity={false_score:.2f}"),
                        },
                    )
        return None

    def _sqli_error_followup(self, url: str, param: str, context_params: dict) -> dict:
        payloads: list[str] = []
        order_by: list[dict] = []
        column_count = 0
        first_error_column = 0

        for column in range(1, 9):
            payload = f"1' ORDER BY {column} {SQL_COMMENT_SUFFIX}"
            response = self._http_get(self._mutate_url(url, param, payload, context_params))
            if not response:
                break
            payloads.append(payload)
            has_error = self._has_sql_error(response.get("body", ""))
            order_by.append(
                {
                    "payload": payload,
                    "status_code": response.get("status_code"),
                    "body_length": response.get("body_length"),
                    "sql_error": has_error,
                }
            )
            if has_error:
                first_error_column = column
                break
            column_count = column

        if first_error_column > 1:
            column_count = first_error_column - 1

        union_probe = {}
        union_marker_reflected = False
        if column_count > 0:
            markers = [f"NOVA{index}" for index in range(1, column_count + 1)]
            select_list = ",".join(f"'{marker}'" for marker in markers)
            union_payload = f"-1' UNION SELECT {select_list} {SQL_COMMENT_SUFFIX}"
            response = self._http_get(self._mutate_url(url, param, union_payload, context_params))
            payloads.append(union_payload)
            if response:
                body = response.get("body", "")
                reflected = [marker for marker in markers if marker in body]
                union_marker_reflected = bool(reflected)
                union_probe = {
                    "payload": union_payload,
                    "status_code": response.get("status_code"),
                    "body_length": response.get("body_length"),
                    "reflected_markers": reflected,
                }

        return {
            "payloads": payloads,
            "order_by": order_by,
            "column_count": column_count,
            "union_probe": union_probe,
            "union_marker_reflected": union_marker_reflected,
            "comment_suffix": SQL_COMMENT_SUFFIX,
            "note": "后续 payload 仅用于授权靶场的错误回显、列数和 UNION 回显点验证。",
        }

    def _sqli_details(self, error_body: str, followup: dict) -> dict:
        column_count = int(followup.get("column_count") or 0)
        reflected_columns = self._reflected_columns(followup)
        techniques = ["错误回显 SQL 注入"]
        if column_count:
            techniques.append("ORDER BY 列数探测")
        if followup.get("union_marker_reflected"):
            techniques.append("UNION SELECT 回显验证")

        return {
            "dbms_guess": self._guess_dbms(error_body),
            "injection_context": "单引号字符串闭合",
            "comment_suffix": SQL_COMMENT_SUFFIX,
            "techniques": techniques,
            "column_count": column_count,
            "reflected_columns": reflected_columns,
            "visible_columns": reflected_columns,
            "payload_pattern": self._sqli_payload_pattern(column_count, reflected_columns),
            "note": "sqli-labs Less-1 属于单引号字符串型错误回显注入；复制 payload 时需要保留注释后缀，避免原 SQL 的 LIMIT 0,1 继续拼接。",
        }

    def _guess_dbms(self, body: str) -> str:
        lowered = body.lower()
        if "mysql" in lowered or "mysqli" in lowered:
            return "MySQL/MariaDB"
        if "postgresql" in lowered or "postgres" in lowered:
            return "PostgreSQL"
        if "sqlite" in lowered:
            return "SQLite"
        if "ora-" in lowered or "oracle" in lowered:
            return "Oracle"
        if "odbc" in lowered or "sql server" in lowered:
            return "SQL Server"
        return "未知"

    def _reflected_columns(self, followup: dict) -> list[int]:
        markers = (followup.get("union_probe") or {}).get("reflected_markers") or []
        columns: list[int] = []
        for marker in markers:
            match = re.search(r"NOVA(\d+)", str(marker))
            if match:
                columns.append(int(match.group(1)))
        return columns

    def _sqli_payload_pattern(self, column_count: int, reflected_columns: list[int]) -> str:
        if column_count <= 0:
            return f"1' <SQL> {SQL_COMMENT_SUFFIX}"
        visible = reflected_columns[0] if reflected_columns else min(2, column_count)
        columns = [str(index) for index in range(1, column_count + 1)]
        columns[visible - 1] = "<表达式>"
        return f"-1' UNION SELECT {','.join(columns)} {SQL_COMMENT_SUFFIX}"

    def _probe_reflection(self, url: str, param: str, context_params: dict, finding_index: int) -> dict | None:
        payloads = [("xss", "<script>alert(1)</script>")]
        for category, payload in payloads:
            response = self._http_get(self._mutate_url(url, param, payload, context_params))
            if not response:
                continue
            if payload in response["body"]:
                return self._finding(
                    self._new_id("P", finding_index),
                    f"疑似 {category.upper()} 反射点",
                    "Medium",
                    "Medium",
                    category,
                    response["url"],
                    f"参数 {param} 的测试 payload 在响应中被原样反射，状态码为 {response['status_code']}。",
                    payloads=[payload],
                    status=STATUS_SUSPECTED,
                    request_response=self._evidence_block(response, matched=payload),
                )
        return None

    def _http_get(self, url: str) -> dict | None:
        try:
            request = Request(
                url,
                headers={"User-Agent": "NOVA-safe-scanner/1.0", **self.settings.auth_headers},
                method="GET",
            )
            timeout = max(0.5, min(float(self.settings.request_timeout), float(self.settings.active_request_timeout)))
            with urlopen(request, timeout=timeout) as response:
                body = response.read(300000).decode(
                    response.headers.get_content_charset() or "utf-8",
                    errors="replace",
                )
                return {
                    "url": response.url,
                    "status_code": response.status,
                    "body": body,
                    "body_length": len(body),
                }
        except Exception:
            return None

    def _mutate_url(self, url: str, param: str, payload: str, context_params: dict | None = None) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        for name, value in (context_params or {}).items():
            query.setdefault(name, [str(value)])
        if not query and param:
            query = {param: [""]}
        query[param] = [payload]
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(query, doseq=True),
                parsed.fragment,
            )
        )

    def _has_sql_error(self, body: str) -> bool:
        lowered = body.lower()
        return any(re.search(pattern, lowered, re.I) for pattern in SQL_ERROR_PATTERNS)

    def _similarity_score(self, left: str, right: str) -> float:
        left_norm = re.sub(r"\s+", " ", left).strip()
        right_norm = re.sub(r"\s+", " ", right).strip()
        if not left_norm and not right_norm:
            return 1.0
        if not left_norm or not right_norm:
            return 0.0
        left_tokens = set(left_norm.split())
        right_tokens = set(right_norm.split())
        if not left_tokens or not right_tokens:
            return 0.0
        return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)

    def _evidence_block(self, response: dict, matched: str = "") -> dict:
        return {
            "url": response.get("url"),
            "status_code": response.get("status_code"),
            "body_length": response.get("body_length"),
            "matched": matched,
        }

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
                "confirmed": len([item for item in findings if item.get("status") == STATUS_CONFIRMED]),
                "suspected": len([item for item in findings if item.get("status") == STATUS_SUSPECTED]),
            },
        }

    def _finding(
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
        return {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "status": status,
            "category": category,
            "category_label": category_label(category),
            "category_group": category_group(category),
            "url": url,
            "evidence": evidence,
            "payloads": payloads,
            "request_response": request_response or {},
            "details": details or {},
            "recommendation": self._default_recommendation(category),
            "llm_analysis": "",
        }

    def _default_recommendation(self, category: str) -> str:
        recommendations = {
            "security_header": "根据业务场景补充缺失的安全响应头，并设置合适的策略值。",
            "information_disclosure": "减少服务端横幅和框架信息暴露，避免泄露实现细节。",
            "cookie": "为敏感 Cookie 设置 Secure、HttpOnly 和 SameSite 等属性。",
            "csrf": "为状态变更请求增加 CSRF Token，并在服务端校验。",
            "injection": "对所有用户可控输入做白名单校验，并使用参数化查询或安全 API。",
            "sqli": "使用参数化查询或 ORM 安全绑定，禁止拼接 SQL，并统一处理数据库错误回显。",
            "xss": "对输出内容进行上下文相关编码，并校验所有反射输入点。",
            "traversal": "规范化路径并拒绝目录穿越相关输入模式。",
            "availability": "检查目标可达性、DNS、TLS 和网络连通性配置。",
            "authentication": "重新获取有效登录态 Cookie 或 Token，并确认扫描 URL 位于登录后的业务页面。",
        }
        return recommendations.get(category, "请人工复核该发现，并结合业务上下文确认风险。")

    def _risk_level(self, findings: list[dict]) -> str:
        order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        if not findings:
            return "Info"
        return max(findings, key=lambda item: order.get(item.get("severity", "Info"), 0)).get("severity", "Info")

    def _new_id(self, prefix: str, index: int) -> str:
        return f"NOVA-{prefix}-{index:03d}"

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
