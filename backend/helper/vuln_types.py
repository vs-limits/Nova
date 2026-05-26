from __future__ import annotations


VULNERABILITY_TYPES: dict[str, dict[str, str]] = {
    "sqli": {"label": "SQL 注入（错误回显/UNION）", "group": "注入类漏洞"},
    "sqli_blind": {"label": "SQL 盲注（布尔型）", "group": "注入类漏洞"},
    "sqli_progression": {"label": "SQL 注入推进候选", "group": "候选 Payload"},
    "dom_xss": {"label": "DOM 型跨站脚本 XSS", "group": "客户端漏洞"},
    "xss": {"label": "跨站脚本 XSS", "group": "客户端漏洞"},
    "csrf": {"label": "跨站请求伪造 CSRF", "group": "客户端漏洞"},
    "command_injection": {"label": "命令注入", "group": "注入类漏洞"},
    "injection": {"label": "输入点注入风险待验证", "group": "注入类漏洞"},
    "lfi": {"label": "本地文件包含 LFI", "group": "文件与路径漏洞"},
    "traversal": {"label": "目录穿越", "group": "文件与路径漏洞"},
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
        "dom_xss": 3,
        "xss": 4,
        "csrf": 5,
        "lfi": 6,
        "traversal": 7,
        "information_disclosure": 8,
        "authentication": 9,
        "security_header": 10,
        "cookie": 11,
        "scanner_limit": 12,
        "availability": 13,
        "injection": 14,
    }
    key = (category or "unknown").strip().lower()
    return (order.get(key, 99), key)
