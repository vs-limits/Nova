from __future__ import annotations


VULNERABILITY_TYPES: dict[str, dict[str, str]] = {
    "sqli": {"label": "SQL 注入（错误回显/UNION）", "group": "注入类漏洞"},
    "sqli_blind": {"label": "SQL 盲注（布尔型）", "group": "注入类漏洞"},
    "sqli_progression": {"label": "SQL 注入推进候选", "group": "候选 Payload"},
    "dom_xss": {"label": "DOM 型跨站脚本 XSS", "group": "客户端漏洞"},
    "xss": {"label": "跨站脚本 XSS", "group": "客户端漏洞"},
    "stored_xss": {"label": "存储型跨站脚本 XSS", "group": "客户端漏洞"},
    "csp_weakness": {"label": "CSP 策略弱配置", "group": "配置与加固"},
    "javascript_exposure": {"label": "JavaScript 暴露风险", "group": "客户端漏洞"},
    "csrf": {"label": "跨站请求伪造 CSRF", "group": "客户端漏洞"},
    "command_injection": {"label": "命令注入", "group": "注入类漏洞"},
    "ssrf": {"label": "服务端请求伪造 SSRF", "group": "服务端请求漏洞"},
    "injection": {"label": "输入点注入风险待验证", "group": "注入类漏洞"},
    "lfi": {"label": "本地文件包含 LFI", "group": "文件与路径漏洞"},
    "traversal": {"label": "目录穿越", "group": "文件与路径漏洞"},
    "file_upload": {"label": "文件上传风险", "group": "文件与路径漏洞"},
    "open_redirect": {"label": "开放重定向", "group": "跳转与访问控制"},
    "weak_session": {"label": "弱会话标识", "group": "认证与访问控制"},
    "crypto_weakness": {"label": "密码学弱点", "group": "配置与加固"},
    "security_header": {"label": "安全响应头配置", "group": "配置与加固"},
    "cookie": {"label": "Cookie 安全属性", "group": "配置与加固"},
    "information_disclosure": {"label": "信息泄露", "group": "信息泄露"},
    "authentication": {"label": "认证/登录态", "group": "认证与访问控制"},
    "availability": {"label": "可用性/连通性", "group": "扫描状态"},
    "scanner_limit": {"label": "扫描边界/预算限制", "group": "扫描状态"},
}


def category_label(category: str | None) -> str:
    key = (category or "unknown").strip().lower()
    return VULNERABILITY_TYPES.get(key, {}).get("label", f"未分类风险（{key}）")


def category_group(category: str | None) -> str:
    key = (category or "unknown").strip().lower()
    return VULNERABILITY_TYPES.get(key, {}).get("group", "其他")


def category_sort_key(category: str | None) -> tuple[int, str]:
    order = {
        "sqli": 0,
        "sqli_blind": 1,
        "command_injection": 2,
        "ssrf": 3,
        "dom_xss": 4,
        "xss": 5,
        "stored_xss": 6,
        "javascript_exposure": 7,
        "csrf": 8,
        "lfi": 9,
        "traversal": 10,
        "file_upload": 11,
        "open_redirect": 12,
        "weak_session": 13,
        "information_disclosure": 14,
        "authentication": 15,
        "csp_weakness": 16,
        "crypto_weakness": 17,
        "security_header": 18,
        "cookie": 19,
        "scanner_limit": 20,
        "availability": 21,
        "injection": 22,
    }
    key = (category or "unknown").strip().lower()
    return (order.get(key, 99), key)
