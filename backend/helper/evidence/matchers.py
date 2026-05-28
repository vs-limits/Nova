from __future__ import annotations

import re
from urllib.parse import urlparse
import base64
import json
import math


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

FILE_PARAM_NAMES = {
    "file",
    "path",
    "page",
    "template",
    "include",
    "view",
    "doc",
    "document",
    "folder",
    "dir",
    "download",
    "filename",
}

COMMAND_PARAM_NAMES = {
    "cmd",
    "command",
    "exec",
    "ip",
    "host",
    "hostname",
    "ping",
    "target",
    "domain",
    "addr",
    "address",
}

REDIRECT_PARAM_NAMES = {
    "url",
    "next",
    "redirect",
    "redirect_url",
    "return",
    "returnurl",
    "return_url",
    "callback",
    "continue",
    "dest",
    "destination",
    "to",
}

SSRF_PARAM_NAMES = {
    "url",
    "uri",
    "endpoint",
    "proxy",
    "fetch",
    "target",
    "dest",
    "destination",
    "callback",
    "webhook",
    "image",
    "avatar",
    "feed",
    "api",
}

STORED_XSS_FIELD_NAMES = {"comment", "message", "content", "body", "post", "feedback", "review", "bio", "description"}

DANGEROUS_ACTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bdrop\b|\bdelete\b|\bupdate\b|\binsert\b|\balter\b|\btruncate\b", "包含破坏性 SQL 关键字"),
    (r"\binto\s+outfile\b|\bload_file\s*\(", "包含文件读写 SQL 函数"),
    (r"\bsleep\s*\(\s*(?:[5-9]|\d{2,})\s*\)|\bbenchmark\s*\(", "包含长时间延时/消耗型测试"),
    (r"\bxp_cmdshell\b|\bpowershell\b|\bcmd\.exe\b", "包含高危命令执行语义"),
    (r"\brm\s+-rf\b|\bdel\s+/[sq]\b|\bshutdown\b|\breboot\b", "包含破坏性系统命令"),
    (r"\bwget\b|\bcurl\b|\bnc\s+-e\b|\bnetcat\b|\breverse\s+shell\b", "包含外连或反弹 Shell 行为"),
    (r">\s*/|>>\s*/", "包含写入系统路径的重定向"),
)


def response_evidence(response: dict, matched: str = "") -> dict:
    return {
        "url": response.get("url"),
        "status_code": response.get("status_code"),
        "body_length": response.get("body_length"),
        "matched": matched,
    }


def has_sql_error(body: str) -> bool:
    lowered = body.lower()
    return any(re.search(pattern, lowered, re.I) for pattern in SQL_ERROR_PATTERNS)


def guess_dbms(body: str) -> str:
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


def similarity_score(left: str, right: str) -> float:
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


def reflected_columns(followup: dict) -> list[int]:
    markers = (followup.get("union_probe") or {}).get("reflected_markers") or []
    columns: list[int] = []
    for marker in markers:
        match = re.search(r"NOVA(\d+)", str(marker))
        if match:
            columns.append(int(match.group(1)))
    return columns


def sqli_payload_pattern(column_count: int, reflected: list[int]) -> str:
    if column_count <= 0:
        return f"1' <SQL> {SQL_COMMENT_SUFFIX}"
    visible = reflected[0] if reflected else min(2, column_count)
    columns = [str(index) for index in range(1, column_count + 1)]
    columns[visible - 1] = "<表达式>"
    return f"-1' UNION SELECT {','.join(columns)} {SQL_COMMENT_SUFFIX}"


def prefer_xss_checks(page: dict, input_point: dict) -> bool:
    url = str(input_point.get("url") or page.get("final_url") or page.get("url") or "")
    lowered = " ".join(
        [urlparse(url).path.lower(), str(page.get("title") or "").lower(), str(input_point.get("name") or "").lower()]
    )
    return any(token in lowered for token in ("xss", "script", "message", "comment", "search", "keyword", "default"))


def looks_like_dom_xss_context(lowered_context: str) -> bool:
    return any(token in lowered_context for token in ("xss_d", "dom based cross site scripting", "dom-based xss", "xss (dom)"))


def has_dom_source_to_sink(lowered_context: str) -> bool:
    sources = ("document.location", "location.href", "window.location", "document.url")
    sinks = ("document.write", "innerhtml", "outerhtml", "insertadjacenthtml")
    return any(source in lowered_context for source in sources) and any(sink in lowered_context for sink in sinks)


def is_executable_xss_reflection(body: str, payload: str) -> bool:
    if payload not in body:
        return False
    lowered = payload.lower()
    executable_markers = ("<script", "</script>", "<svg", "onload=", "onerror=", "javascript:")
    return any(marker in lowered for marker in executable_markers)


def reflection_context(body: str, payload: str) -> str:
    index = body.find(payload)
    if index < 0:
        return "未定位"
    last_lt = body.rfind("<", 0, index)
    last_gt = body.rfind(">", 0, index)
    if last_lt > last_gt:
        return "HTML 标签属性上下文"
    lowered_window = body[max(0, index - 80) : index + len(payload) + 80].lower()
    if "<script" in lowered_window:
        return "脚本标签上下文"
    return "HTML 正文上下文"


def file_param_hint(name: str, url: str) -> bool:
    lowered_name = name.lower()
    path = urlparse(url).path.lower()
    return lowered_name in FILE_PARAM_NAMES or any(token in path for token in ("/fi", "file", "include", "download"))


def lfi_signal(body: str) -> str:
    lowered = body.lower()
    if "root:x:0:0:" in lowered or "daemon:x:" in lowered or "/bin/bash" in lowered:
        return "/etc/passwd 特征"
    if "[extensions]" in lowered or "[fonts]" in lowered or "for 16-bit app support" in lowered:
        return "Windows win.ini 特征"
    return ""


def command_param_hint(name: str, url: str) -> bool:
    lowered_name = name.lower()
    path = urlparse(url).path.lower()
    return lowered_name in COMMAND_PARAM_NAMES or any(token in path for token in ("exec", "command", "ping"))


def command_signal(body: str, marker: str = "NOVA_CMD") -> str:
    return marker if marker in body else ""


def safe_active_payload(payload: str) -> tuple[bool, str]:
    if len(payload) > 180:
        return False, "payload 过长"
    lowered = payload.lower()
    for pattern, reason in DANGEROUS_ACTIVE_PATTERNS:
        if re.search(pattern, lowered, re.I):
            return False, reason
    return True, "通过主动探测安全过滤"


def parse_csp(header_value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_part in header_value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        pieces = part.split()
        directives[pieces[0].lower()] = pieces[1:]
    return directives


def csp_weaknesses(header_value: str) -> list[dict]:
    if not header_value:
        return [{"kind": "missing_csp", "matched": "missing Content-Security-Policy", "severity": "Medium"}]
    directives = parse_csp(header_value)
    weaknesses: list[dict] = []
    sources = directives.get("default-src", []) + directives.get("script-src", [])
    source_text = " ".join(sources).lower()
    if "'unsafe-inline'" in source_text:
        weaknesses.append({"kind": "unsafe_inline", "matched": "unsafe-inline", "severity": "Medium"})
    if "'unsafe-eval'" in source_text:
        weaknesses.append({"kind": "unsafe_eval", "matched": "unsafe-eval", "severity": "Medium"})
    if "*" in sources or "https:" in sources or "http:" in sources:
        weaknesses.append({"kind": "wildcard_source", "matched": "wildcard or scheme-wide source", "severity": "Medium"})
    for directive in ("object-src", "base-uri", "frame-ancestors"):
        if directive not in directives:
            weaknesses.append({"kind": f"missing_{directive}", "matched": f"missing {directive}", "severity": "Low"})
    return weaknesses


def javascript_findings(script_body: str) -> list[dict]:
    findings: list[dict] = []
    patterns = (
        (r"\binnerHTML\b|\bouterHTML\b|\bdocument\.write\s*\(", "dangerous_dom_sink", "dangerous DOM sink", "Medium"),
        (r"\beval\s*\(|new\s+Function\s*\(", "dynamic_code_execution", "eval/new Function", "Medium"),
        (r"\blocalStorage\b|\bsessionStorage\b", "browser_storage_token", "browser storage access", "Low"),
        (r"sourceMappingURL=", "source_map", "source map reference", "Low"),
        (r"(?i)(api[_-]?key|token|secret|access[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}", "hardcoded_secret", "hardcoded token-like value", "High"),
        (r"(?i)/(debug|admin|internal|actuator|swagger|graphql)", "sensitive_endpoint", "sensitive endpoint path", "Low"),
    )
    for pattern, kind, matched, severity in patterns:
        if re.search(pattern, script_body):
            findings.append({"kind": kind, "matched": matched, "severity": severity})
    return findings


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def decode_jwt_header(value: str) -> dict:
    parts = value.split(".")
    if len(parts) < 2:
        return {}
    try:
        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="replace"))
    except Exception:
        return {}


def weak_session_signals(name: str, value: str, cookie: dict) -> list[dict]:
    signals: list[dict] = []
    if len(value) < 16:
        signals.append({"kind": "short_session_id", "matched": "session id length < 16", "severity": "Medium"})
    if re.fullmatch(r"\d{6,}", value or ""):
        signals.append({"kind": "numeric_session_id", "matched": "numeric session id", "severity": "Medium"})
    entropy = shannon_entropy(value)
    if value and len(value) >= 8 and entropy < 2.5:
        signals.append({"kind": "low_entropy_session_id", "matched": f"entropy={entropy:.2f}", "severity": "Medium"})
    jwt_header = decode_jwt_header(value)
    if jwt_header.get("alg", "").lower() == "none":
        signals.append({"kind": "jwt_alg_none", "matched": "JWT alg=none", "severity": "High"})
    lowered_name = name.lower()
    if any(token in lowered_name for token in ("sess", "sid", "token", "auth", "jwt")):
        missing = []
        if not cookie.get("secure"):
            missing.append("Secure")
        if not cookie.get("httponly"):
            missing.append("HttpOnly")
        if missing:
            signals.append({"kind": "session_cookie_flags", "matched": ", ".join(missing), "severity": "Low"})
    return signals


def crypto_weaknesses(headers: dict[str, str], body: str, cookies: list[dict]) -> list[dict]:
    findings: list[dict] = []
    lowered_headers = {key.lower(): value for key, value in headers.items()}
    if "strict-transport-security" not in lowered_headers:
        findings.append({"kind": "missing_hsts", "matched": "missing Strict-Transport-Security", "severity": "Low"})
    combined = body + " " + " ".join(str(cookie.get("name", "")) + "=" + str(cookie.get("value", "")) for cookie in cookies)
    if re.search(r"\b[a-fA-F0-9]{32}\b", combined):
        findings.append({"kind": "md5_like_hash", "matched": "32 hex chars MD5-like value", "severity": "Low"})
    if re.search(r"\b[a-fA-F0-9]{40}\b", combined):
        findings.append({"kind": "sha1_like_hash", "matched": "40 hex chars SHA1-like value", "severity": "Low"})
    for cookie in cookies:
        header = decode_jwt_header(str(cookie.get("value", "")))
        if header.get("alg", "").lower() == "none":
            findings.append({"kind": "jwt_alg_none", "matched": f"{cookie.get('name')} JWT alg=none", "severity": "High"})
    return findings


def redirect_param_hint(name: str) -> bool:
    return name.lower() in REDIRECT_PARAM_NAMES


def ssrf_param_hint(name: str, url: str) -> bool:
    lowered_name = name.lower()
    path = urlparse(url).path.lower()
    return lowered_name in SSRF_PARAM_NAMES or any(token in path for token in ("fetch", "proxy", "webhook", "callback"))


def stored_xss_form_hint(form: dict) -> bool:
    if form.get("candidate_purpose") == "stored_xss_candidate":
        return True
    names = {str(field.get("name", "")).lower() for field in form.get("inputs", [])}
    return bool(names & STORED_XSS_FIELD_NAMES)


def upload_form_hint(form: dict) -> bool:
    return bool(form.get("file_inputs")) or "multipart/form-data" in str(form.get("enctype", "")).lower()


def passive_information_leaks(body: str) -> list[dict]:
    lowered = body.lower()
    leaks: list[dict] = []
    if "<?php" in lowered or "phpinfo()" in lowered or "php version" in lowered and "configuration" in lowered:
        leaks.append({"kind": "phpinfo", "matched": "phpinfo/PHP Version", "severity": "Medium"})
    if "traceback (most recent call last)" in lowered or "stack trace:" in lowered or "exception in thread" in lowered:
        leaks.append({"kind": "stack_trace", "matched": "stack trace/traceback", "severity": "Medium"})
    if "notice:" in lowered and ".php on line" in lowered:
        leaks.append({"kind": "php_error", "matched": "PHP Notice/Warning path disclosure", "severity": "Medium"})
    if re.search(r"[a-z]:\\(?:xampp|wamp|inetpub|www|users)\\", body, re.I):
        leaks.append({"kind": "windows_path", "matched": "Windows absolute path", "severity": "Low"})
    if re.search(r"/(?:var/www|home/[^/\s]+|usr/local|opt/lampp)/[^\s<]+", body):
        leaks.append({"kind": "unix_path", "matched": "Unix absolute path", "severity": "Low"})
    if "debug=true" in lowered or "debug mode" in lowered or "django debug" in lowered:
        leaks.append({"kind": "debug", "matched": "debug mode", "severity": "Medium"})
    return leaks
