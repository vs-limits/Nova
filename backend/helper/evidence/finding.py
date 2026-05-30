from __future__ import annotations

from collections import defaultdict

from backend.helper.vuln_types import category_group, category_label


STATUS_CONFIRMED = "确认漏洞"
STATUS_SUSPECTED = "疑似漏洞"
STATUS_PENDING = "待验证"
STATUS_CONFIG = "配置建议"
STATUS_INFO = "信息提示"
STATUS_FAILED = "扫描失败"
STATUS_NOTICE = "扫描提示"


class IdFactory:
    def __init__(self) -> None:
        self._counters: defaultdict[str, int] = defaultdict(int)

    def new(self, prefix: str) -> str:
        self._counters[prefix] += 1
        return f"NOVA-{prefix}-{self._counters[prefix]:03d}"


class FindingFactory:
    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.id_factory = id_factory or IdFactory()

    def new_id(self, prefix: str) -> str:
        return self.id_factory.new(prefix)

    def create(
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
        details = dict(details or {})
        request_response = request_response or {}
        poc = self.build_poc(category, url, payloads, status, request_response, details)
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
            "executed_payloads": [] if poc.get("execution") == "manual" else payloads,
            "poc": poc,
            "request_response": request_response,
            "details": details,
            "recommendation": self.default_recommendation(category),
            "llm_analysis": "",
            "llm_payload_advice": [],
        }

    def build_poc(
        self,
        category: str,
        url: str,
        payloads: list[str],
        status: str,
        request_response: dict,
        details: dict,
    ) -> dict:
        evidence_type = details.get("evidence_type", "")
        confirmation_basis = details.get("confirmation_basis", "")
        target_param = details.get("target_param", "")
        if category == "csrf" and evidence_type == "get_state_change_form":
            return {
                "type": "manual",
                "execution": "manual",
                "url": url,
                "payloads": payloads,
                "expected_signal": "已登录用户的浏览器跨站发起该 GET 状态变更请求后，目标状态发生变化。",
                "confirmation_basis": confirmation_basis,
                "note": "NOVA 只根据表单结构确认风险，不会自动触发该状态变更请求。",
            }
        if category == "captcha_bypass":
            return {
                "type": "manual",
                "execution": "manual",
                "url": url,
                "target_param": target_param,
                "payloads": payloads,
                "expected_signal": confirmation_basis or request_response.get("matched", ""),
                "confirmation_basis": confirmation_basis,
                "note": "NOVA 只生成 CAPTCHA 绕过的手工 PoC，不会自动提交会修改密码的请求。",
            }
        if category == "sqli_blind" and len(payloads) >= 2:
            return {
                "type": "boolean_pair",
                "execution": "executed",
                "url": url,
                "target_param": target_param,
                "true_payload": payloads[0],
                "false_payload": payloads[1],
                "expected_signal": "true/false 两次响应与基线相比出现稳定差异。",
                "confirmation_basis": confirmation_basis,
            }
        if payloads:
            return {
                "type": "single_or_sequence",
                "execution": "executed" if status == STATUS_CONFIRMED else "manual",
                "url": url,
                "target_param": target_param,
                "payloads": payloads,
                "expected_signal": confirmation_basis or request_response.get("matched", ""),
                "confirmation_basis": confirmation_basis,
            }
        return {
            "type": "evidence_only",
            "execution": "passive",
            "url": url,
            "target_param": target_param,
            "payloads": [],
            "expected_signal": confirmation_basis or request_response.get("matched", ""),
            "confirmation_basis": confirmation_basis,
        }

    def default_recommendation(self, category: str) -> str:
        recommendations = {
            "security_header": "根据业务场景补充缺失的安全响应头，并设置合适的策略值。",
            "information_disclosure": "减少服务端横幅、错误栈、调试页和路径信息暴露，避免泄露实现细节。",
            "cookie": "为敏感 Cookie 设置 Secure、HttpOnly 和 SameSite 等属性。",
            "csrf": "为状态变更请求增加 CSRF Token，并在服务端校验。",
            "injection": "对所有用户可控输入做白名单校验，并使用参数化查询或安全 API。",
            "sqli": "使用参数化查询或 ORM 安全绑定，禁止拼接 SQL，并统一处理数据库错误回显。",
            "sqli_blind": "使用参数化查询或 ORM 安全绑定，并避免根据布尔条件泄露不同响应。",
            "dom_xss": "避免把 URL、location、hash 等 DOM source 直接写入 document.write/innerHTML 等 HTML sink；对输出做上下文编码或使用安全 DOM API。",
            "xss": "对输出内容进行上下文相关编码，并校验所有反射输入点。",
            "stored_xss": "对持久化内容在写入和输出时分别做校验与上下文编码，并对富文本使用可信 HTML sanitizer。",
            "csp_weakness": "收紧 CSP 策略，移除 unsafe-inline/unsafe-eval 和通配源，并补充 object-src、base-uri、frame-ancestors。",
            "javascript_exposure": "移除前端硬编码密钥、调试端点和 source map 暴露，避免危险 DOM sink 直接接收用户输入。",
            "traversal": "规范化路径并拒绝目录穿越相关输入模式。",
            "lfi": "禁止把用户输入直接拼接到文件路径或 include 参数中，使用固定映射表和路径白名单。",
            "command_injection": "避免拼接系统命令；使用安全 API、参数数组和严格白名单，并在服务端限制可执行命令范围。",
            "ssrf": "对服务端发起请求的 URL 做协议、主机和网段白名单校验，并禁止访问内网、环回和云元数据地址。",
            "file_upload": "限制上传类型、大小和存储位置，重命名文件并禁止上传内容被脚本解释执行。",
            "open_redirect": "只允许跳转到固定白名单路径或同源 URL，禁止直接信任用户提供的完整 URL。",
            "captcha_bypass": "验证码通过状态必须与最终状态变更在服务端强绑定；不要信任客户端隐藏字段、固定响应值或可伪造请求头。",
            "weak_session": "使用高熵随机会话 ID，设置 Secure/HttpOnly/SameSite，并避免可预测或可解码的敏感会话内容。",
            "crypto_weakness": "禁用弱算法和明文敏感 token，避免 JWT alg=none，并优先使用现代 TLS 与成熟密码库。",
            "availability": "检查目标可达性、DNS、TLS 和网络连通性配置。",
            "authentication": "重新获取有效登录态 Cookie 或 Token，并确认扫描 URL 位于登录后的业务页面。",
        }
        return recommendations.get(category, "请人工复核该发现，并结合业务上下文确认风险。")
