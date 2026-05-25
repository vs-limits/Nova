from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.helper.agent.sub_agent.auditor import AuditorAgent
from backend.helper.agent.sub_agent.llm_payload import LLMPayloadAdvisor, PayloadSafetyFilter
from backend.helper.agent.sub_agent.payload import PayloadAgent
from backend.helper.agent.sub_agent.probe import TargetProbeAgent
from backend.helper.agent.sub_agent.scanner import ScanScope, WebScannerAgent
from backend.helper.auth import auth_summary
from backend.helper.settings import RuntimeSettings
from backend.helper.utils import normalize_url


def settings(**overrides) -> RuntimeSettings:
    values = {
        "llm_baseurl": None,
        "llm_apikey": None,
        "llm_model": "deepseekV4-flash",
        "llm_provider": None,
        "request_timeout": 2,
        "max_links": 10,
        "max_pages": 3,
        "max_depth": 1,
        "rate_limit": 0,
        "active_scan": False,
        "active_request_timeout": 1,
        "max_active_inputs": 5,
        "llm_analysis": True,
        "llm_on_local_targets": True,
        "llm_payload_advisor": True,
        "llm_payload_max_per_param": 5,
        "llm_payload_report_only": True,
        "report_confirmed_only": True,
        "allowed_hosts": [],
        "exclude_paths": [],
        "auth_headers": {},
    }
    values.update(overrides)
    return RuntimeSettings(**values)


def test_normalize_url_and_scope_rules() -> None:
    target = normalize_url("example.com/search?q=1")
    scope = ScanScope.from_settings(target, settings(exclude_paths=["/admin"]))

    assert target == "http://example.com/search?q=1"
    assert scope.in_scope("http://example.com/about", 1) == (True, "in_scope")
    assert scope.in_scope("https://example.com/about", 1)[1] == "different_scheme"
    assert scope.in_scope("http://other.example/about", 1)[1] == "host_not_allowed"
    assert scope.in_scope("http://example.com/admin/users", 1)[1] == "path_excluded"
    assert scope.in_scope("http://example.com/deep", 2)[1] == "max_depth"


def test_runtime_settings_allow_local_llm_by_default() -> None:
    runtime = RuntimeSettings(None, None, "deepseekV4-flash", None)

    assert runtime.llm_on_local_targets is True


def test_probe_detects_basic_auth_and_redacts_headers(monkeypatch) -> None:
    class Headers(dict):
        def items(self):
            return super().items()

    class FakeHTTPError(Exception):
        code = 401
        headers = Headers({"WWW-Authenticate": "Basic realm=test", "Server": "mock"})

        def read(self, *_args):
            return b""

    def fake_open(self, request, timeout=0):
        raise FakeHTTPError()

    monkeypatch.setattr("backend.helper.agent.sub_agent.probe.socket.getaddrinfo", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("backend.helper.agent.sub_agent.probe.build_opener", lambda *_args: type("Opener", (), {"open": fake_open})())
    monkeypatch.setattr("backend.helper.agent.sub_agent.probe.HTTPError", FakeHTTPError)

    result = TargetProbeAgent(settings(auth_headers={"Authorization": "Bearer secret-token"})).probe("http://example.com")

    assert result["auth_required"] is True
    assert result["auth_type_guess"] == "basic"
    assert result["auth"]["redacted_headers"]["Authorization"] != "Bearer secret-token"


def test_probe_detects_login_form() -> None:
    agent = TargetProbeAgent(settings())
    response = {
        "status_code": 200,
        "headers": {},
        "final_url": "http://example.com/login",
        "login_signals": {"has_password_input": True},
    }

    assert agent._detect_auth_required(response) == (True, "login_page")


def test_scanner_fetch_extracts_get_form_inputs_and_auth(monkeypatch) -> None:
    html = """
    <html><head><title>Mock</title></head>
    <body>
      <a href="/next?item=1">Next</a>
      <form method="get" action="/vulnerabilities/sqli/">
        <input name="id" type="text">
        <input name="Submit" type="submit">
      </form>
    </body></html>
    """
    seen_headers = {}

    class Headers(dict):
        def get_content_charset(self):
            return "utf-8"

        def get_all(self, name, _default=None):
            if name.lower() == "set-cookie":
                return ["sid=abc; HttpOnly"]
            return []

        def items(self):
            return super().items()

    class Response:
        status = 200
        url = "http://example.com/DVWA/vulnerabilities/sqli/"
        headers = Headers({"Content-Type": "text/html", "Server": "mock"})

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            return html.encode("utf-8")

    def fake_urlopen(request, **_kwargs):
        seen_headers.update(dict(request.header_items()))
        return Response()

    monkeypatch.setattr("backend.helper.agent.sub_agent.scanner.urlopen", fake_urlopen)

    result = WebScannerAgent(settings(auth_headers={"Cookie": "sid=secret"})).scan("http://example.com/DVWA/vulnerabilities/sqli/")

    assert result["reachable"] is True
    assert result["title"] == "Mock"
    assert result["pages"][0]["links"] == ["http://example.com/next?item=1"]
    assert result["pages"][0]["forms"][0]["method"] == "GET"
    assert result["cookies"][0]["name"] == "sid"
    points = {item["name"]: item for item in result["input_points"]}
    assert {"id", "Submit"}.issubset(points)
    assert points["id"]["active_testable"] is True
    assert points["id"]["form_defaults"]["Submit"] == "Submit"
    assert points["Submit"]["active_testable"] is False
    assert seen_headers["Cookie"] == "sid=secret"
    assert result["auth"]["redacted_headers"]["Cookie"] != "sid=secret"


def test_scanner_dedupes_reflected_query_links_to_avoid_crawl_loop(monkeypatch) -> None:
    calls = []

    class Headers(dict):
        def get_content_charset(self):
            return "utf-8"

        def get_all(self, name, _default=None):
            return []

        def items(self):
            return super().items()

    class Response:
        status = 200
        headers = Headers({"Content-Type": "text/html"})

        def __init__(self, url: str) -> None:
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            index = len(calls)
            html = f"""
            <html><head><title>XSS</title></head>
            <body>
              <a href="/DVWA/vulnerabilities/xss_r/?name=NOVA{index}">again</a>
              <form method="get" action="/DVWA/vulnerabilities/xss_r/">
                <input name="name" type="text">
              </form>
            </body></html>
            """
            return html.encode("utf-8")

    def fake_urlopen(request, **_kwargs):
        calls.append(request.full_url)
        return Response(request.full_url)

    monkeypatch.setattr("backend.helper.agent.sub_agent.scanner.urlopen", fake_urlopen)

    result = WebScannerAgent(settings(max_pages=20, max_depth=5, max_links=10)).scan(
        "http://example.com/DVWA/vulnerabilities/xss_r/?name=start"
    )

    assert result["reachable"] is True
    assert len(result["pages"]) == 1
    assert len(calls) == 1


def test_auditor_detects_sqli_error(monkeypatch) -> None:
    class Headers(dict):
        def get_content_charset(self):
            return "utf-8"

    class Response:
        def __init__(self, url: str, body: str) -> None:
            self.url = url
            self.status = 200
            self.headers = Headers({"Content-Type": "text/html"})
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            return self.body.encode("utf-8")

    def fake_urlopen(request, **_kwargs):
        url = request.full_url
        query = parse_qs(urlparse(url).query)
        value = query.get("id", [""])[0]
        assert query.get("Submit") == ["Submit"]
        if "'" in value:
            return Response(url, "You have an error in your SQL syntax near ''' at line 1")
        return Response(url, "User ID exists")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://example.com/sqli/?id=1",
        "reachable": True,
        "headers": {
            "Server": "mock",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [
            {
                "final_url": "http://example.com/sqli/",
                "input_points": [
                    {
                        "name": "id",
                        "method": "GET",
                        "url": "http://example.com/sqli/",
                        "active_testable": True,
                        "form_defaults": {"Submit": "Submit"},
                    }
                ],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True)).audit(webscan)

    assert any(item["title"] == "确认存在 SQL 注入错误回显" for item in audit["findings"])
    assert audit["summary"]["confirmed"] == 1


def test_auditor_error_sqli_runs_order_by_and_union_followup(monkeypatch) -> None:
    class Headers(dict):
        def get_content_charset(self):
            return "utf-8"

    class Response:
        def __init__(self, url: str, body: str) -> None:
            self.url = url
            self.status = 200
            self.headers = Headers({"Content-Type": "text/html"})
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            return self.body.encode("utf-8")

    def fake_urlopen(request, **_kwargs):
        url = request.full_url
        value = parse_qs(urlparse(url).query).get("id", [""])[0]
        lowered = value.lower()
        if value == "1'":
            return Response(url, "You have an error in your SQL syntax; MySQL server version")
        if "order by 4" in lowered:
            return Response(url, "Unknown column '4' in 'order clause'")
        if "order by" in lowered:
            return Response(url, "Dumb user page")
        if "union select" in lowered:
            return Response(url, "Your Login name: NOVA2<br>Your Password: NOVA3")
        return Response(url, "Dumb user page")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [
            {
                "input_points": [
                    {
                        "name": "id",
                        "method": "GET",
                        "url": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
                        "active_testable": True,
                    }
                ]
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["status"] == "确认漏洞")

    assert finding["payloads"][0] == "1'"
    assert "1' ORDER BY 4 -- -" in finding["payloads"]
    assert "-1' UNION SELECT 'NOVA1','NOVA2','NOVA3' -- -" in finding["payloads"]
    assert finding["request_response"]["followup"]["column_count"] == 3
    assert finding["request_response"]["followup"]["union_marker_reflected"] is True
    assert finding["details"]["dbms_guess"] == "MySQL/MariaDB"
    assert finding["details"]["injection_context"] == "单引号字符串闭合"
    assert finding["details"]["comment_suffix"] == "-- -"
    assert finding["details"]["visible_columns"] == [2, 3]


def test_auditor_detects_boolean_sqli(monkeypatch) -> None:
    class Headers(dict):
        def get_content_charset(self):
            return "utf-8"

    class Response:
        def __init__(self, url: str, body: str) -> None:
            self.url = url
            self.status = 200
            self.headers = Headers({"Content-Type": "text/html"})
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            return self.body.encode("utf-8")

    def fake_urlopen(request, **_kwargs):
        url = request.full_url
        query = parse_qs(urlparse(url).query)
        value = query.get("id", [""])[0].lower()
        assert query.get("Submit") == ["Submit"]
        if "1=2" in value:
            return Response(url, "User ID is MISSING")
        return Response(url, "User ID exists First name: admin Surname: admin")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://example.com/sqli/?id=1",
        "reachable": True,
        "headers": {
            "Server": "mock",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [
            {
                "final_url": "http://example.com/sqli/",
                "input_points": [
                    {
                        "name": "id",
                        "method": "GET",
                        "url": "http://example.com/sqli/",
                        "active_testable": True,
                        "form_defaults": {"Submit": "Submit"},
                    }
                ],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True)).audit(webscan)

    assert any(item["title"] == "疑似布尔型 SQL 注入" for item in audit["findings"])
    assert audit["summary"]["suspected"] == 1


def test_auditor_short_circuits_active_probe_when_baseline_times_out(monkeypatch) -> None:
    calls = []

    def fake_urlopen(request, **_kwargs):
        calls.append(request.full_url)
        raise TimeoutError("timeout")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/sqli-labs-master/Less-1/",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [
            {
                "final_url": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
                "input_points": [
                    {
                        "name": "id",
                        "method": "GET",
                        "url": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
                        "active_testable": True,
                    }
                ],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, active_request_timeout=0.5)).audit(webscan)

    assert len(calls) == 1
    assert any(item["title"] == "输入点主动探测请求失败或超时" for item in audit["findings"])


def test_auditor_limits_active_input_points(monkeypatch) -> None:
    class Headers(dict):
        def get_content_charset(self):
            return "utf-8"

    class Response:
        status = 200
        headers = Headers({"Content-Type": "text/html"})

        def __init__(self, url: str) -> None:
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            return b"baseline"

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", lambda request, **_kwargs: Response(request.full_url))
    points = [
        {"name": f"q{i}", "method": "GET", "url": f"http://example.com/?q{i}=1", "active_testable": True}
        for i in range(3)
    ]
    webscan = {
        "target": "http://example.com/",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [{"input_points": points}],
    }

    audit = AuditorAgent(settings(active_scan=True, max_active_inputs=1)).audit(webscan)

    assert any(item["title"] == "主动探测输入点数量达到上限" for item in audit["findings"])


def test_auditor_rules_detect_headers_cookies_forms_and_query() -> None:
    webscan = {
        "target": "http://example.com/?q=1",
        "reachable": True,
        "headers": {"Server": "mock"},
        "cookies": [{"name": "sid", "secure": False, "httponly": False, "samesite": ""}],
        "forms": [{"method": "POST", "action": "http://example.com/save", "inputs": [{"name": "email", "type": "email"}]}],
        "pages": [
            {
                "final_url": "http://example.com/?q=1",
                "headers": {"Server": "mock"},
                "input_points": [{"name": "q", "method": "GET", "url": "http://example.com/?q=1"}],
            }
        ],
    }

    audit = AuditorAgent(settings()).audit(webscan)
    titles = {item["title"] for item in audit["findings"]}

    assert "缺少 Content-Security-Policy 响应头" in titles
    assert "Server 响应头信息泄露" in titles
    assert any(title.startswith("Cookie 缺少安全属性") for title in titles)
    assert "表单缺少明显的 CSRF Token" in titles
    assert "URL 参数需要注入风险验证" in titles
    assert audit["summary"]["llm_enabled"] is False


def test_auditor_reports_missing_auth_context() -> None:
    webscan = {
        "target": "http://example.com/login.php",
        "reachable": True,
        "headers": {},
        "cookies": [],
        "forms": [],
        "pages": [],
        "auth": {"configured": False},
        "target_probe": {"auth_required": True},
    }

    audit = AuditorAgent(settings()).audit(webscan)

    assert any(item["id"] == "NOVA-AUTH-000" for item in audit["findings"])


def test_llm_payload_safety_filter_allows_blind_pair_and_blocks_dangerous_payloads() -> None:
    filter_ = PayloadSafetyFilter()
    candidates = [
        {
            "input_point": "http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/",
            "category": "sqli_blind",
            "target_param": "id",
            "true_payload": "1' AND '1'='1' -- -",
            "false_payload": "1' AND '1'='2' -- -",
            "expected_true_signal": "User ID exists in the database.",
            "expected_false_signal": "User ID is MISSING from the database.",
            "purpose": "验证布尔条件响应差异",
        },
        {"category": "sqli", "target_param": "id", "payload": "1'; DROP TABLE users; #"},
        {"category": "sqli", "target_param": "id", "payload": "1' UNION SELECT 'x' INTO OUTFILE 'shell.php' #"},
        {"category": "command_injection", "target_param": "cmd", "payload": "1; EXEC xp_cmdshell 'whoami' --"},
        {"category": "sqli_blind", "target_param": "id", "payload": "1' OR SLEEP(30)--"},
    ]

    results = filter_.filter_many(candidates)

    allowed = [item for item in results if item["allowed"]]
    blocked = [item for item in results if not item["allowed"]]
    assert len(allowed) == 2
    assert {item["pair_role"] for item in allowed} == {"true", "false"}
    assert "1' AND '1'='1' -- -" in {item["payload"] for item in allowed}
    assert len(blocked) == 4
    assert all(item["payload"].startswith("[已过滤]") for item in blocked)


def test_llm_payload_safety_filter_allows_read_only_sqli_progression() -> None:
    filter_ = PayloadSafetyFilter()
    results = filter_.filter_many(
        [
            {
                "input_point": "http://example.com/Less-1/?id=1",
                "category": "sqli_progression",
                "target_param": "id",
                "payload": "-1' UNION SELECT 1,database(),version() -- -",
                "purpose": "确认 SQLi 后读取库名和版本",
            },
            {
                "input_point": "http://example.com/Less-1/?id=1",
                "category": "sqli_progression",
                "target_param": "id",
                "payload": "1' UNION SELECT LOAD_FILE('/etc/passwd') -- -",
            },
        ]
    )

    allowed = [item for item in results if item["allowed"]]
    blocked = [item for item in results if not item["allowed"]]
    assert len(allowed) == 1
    assert allowed[0]["category"] == "sqli_progression"
    assert allowed[0]["category_label"] == "SQL 注入推进候选"
    assert "database()" in allowed[0]["payload"]
    assert allowed[0]["payload"].endswith("-- -")
    assert len(blocked) == 1
    assert "LOAD_FILE" in blocked[0]["filter_reason"]


def test_llm_payload_advisor_parses_json_and_does_not_change_findings(monkeypatch) -> None:
    def fake_chat(self, system_prompt: str, user_prompt: str) -> str:
        return """
        {
          "payloads": [
            {
              "input_point": "http://example.com/sqli_blind/",
              "category": "sqli_blind",
              "target_param": "id",
              "true_payload": "1' AND '1'='1' -- -",
              "false_payload": "1' AND '1'='2' -- -",
              "expected_true_signal": "exists",
              "expected_false_signal": "MISSING",
              "purpose": "验证盲注布尔差异"
            }
          ]
        }
        """

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fake_chat)
    webscan = {
        "target": "http://example.com/sqli_blind/",
        "final_url": "http://example.com/sqli_blind/",
        "pages": [{"input_points": [{"name": "id", "method": "GET", "url": "http://example.com/sqli_blind/"}]}],
    }
    findings = [{"id": "NOVA-Q-001", "title": "URL 参数需要注入风险验证", "status": "待验证"}]

    result = LLMPayloadAdvisor(settings(llm_baseurl="http://llm.local", llm_apikey="k", llm_provider="deepseek")).generate(webscan, findings)

    assert result["status"] == "ok"
    assert result["summary"]["allowed"] >= 2
    assert result["items"][0]["allowed"] is True
    assert findings[0]["status"] == "待验证"


def test_payload_advisor_adds_confirmed_sqli_progression_templates(monkeypatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("local targets should skip LLM network calls when disabled")

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fail_if_called)
    webscan = {
        "target": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
        "final_url": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
        "pages": [
            {
                "final_url": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
                "input_points": [
                    {
                        "name": "id",
                        "method": "GET",
                        "url": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1",
                        "active_testable": True,
                        "type": "text",
                    }
                ],
            }
        ],
    }
    findings = [
        {
            "id": "NOVA-SQLI-001",
            "title": "确认存在 SQL 注入错误回显",
            "status": "确认漏洞",
            "category": "sqli",
            "url": "http://127.0.0.1/sqli-labs-master/Less-1/?id=1%27",
            "payloads": ["1'", "1' ORDER BY 1 -- -", "-1' UNION SELECT 'NOVA1','NOVA2','NOVA3' -- -"],
            "request_response": {
                "followup": {
                    "column_count": 3,
                    "union_probe": {"reflected_markers": ["NOVA2", "NOVA3"]},
                    "union_marker_reflected": True,
                }
            },
        }
    ]

    result = LLMPayloadAdvisor(
        settings(llm_baseurl="http://llm.local", llm_apikey="k", llm_provider="deepseek", llm_on_local_targets=False)
    ).generate(
        webscan,
        findings,
    )

    allowed = [item for item in result["items"] if item["allowed"]]
    progression = [item for item in allowed if item["source"] == "local_progression_template"]
    assert progression
    assert any("database()" in item["payload"] for item in progression)
    assert any("information_schema.tables" in item["payload"] for item in progression)
    assert {item["target_param"] for item in progression} == {"id"}


def test_llm_payload_advisor_calls_progression_prompt_for_confirmed_findings(monkeypatch) -> None:
    calls: list[str] = []

    def fake_chat(self, system_prompt: str, user_prompt: str) -> str:
        calls.append(system_prompt)
        if "Confirmed Vulnerability Payload Advisor" not in system_prompt:
            return '{"payloads": []}'
        assert "column_count" in user_prompt
        return """
        {
          "payloads": [
            {
              "input_point": "http://example.com/Less-1/?id=1",
              "category": "sqli_progression",
              "target_param": "id",
              "payload": "-1' UNION SELECT 1,database(),3 -- -",
              "purpose": "确认后读取当前数据库名",
              "expected_signal": "响应中出现数据库名",
              "risk_note": "仅报告参考，不自动执行"
            }
          ]
        }
        """

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fake_chat)
    webscan = {
        "target": "http://example.com/Less-1/?id=1",
        "final_url": "http://example.com/Less-1/?id=1",
        "pages": [{"input_points": [{"name": "id", "method": "GET", "url": "http://example.com/Less-1/?id=1"}]}],
    }
    findings = [
        {
            "id": "NOVA-SQLI-001",
            "title": "确认存在 SQL 注入错误回显",
            "status": "确认漏洞",
            "category": "sqli",
            "url": "http://example.com/Less-1/?id=1%27",
            "payloads": ["1'"],
            "request_response": {"followup": {"column_count": 3, "union_probe": {"reflected_markers": ["NOVA2"]}}},
        }
    ]

    result = LLMPayloadAdvisor(settings(llm_baseurl="http://llm.local", llm_apikey="k", llm_provider="deepseek")).generate(
        webscan,
        findings,
    )

    assert len(calls) == 2
    assert result["summary"]["llm_candidates"] == 1
    assert any(item["source"] == "llm_progression" and "database()" in item["payload"] for item in result["items"])


def test_payload_advisor_adds_contextual_pairs_and_does_not_target_submit(monkeypatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("local targets should skip LLM network calls when disabled")

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fail_if_called)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/",
        "final_url": "http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/",
        "pages": [
            {
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/",
                "input_points": [
                    {
                        "name": "id",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/?id=&Submit=Submit",
                        "active_testable": True,
                        "type": "text",
                    },
                    {
                        "name": "Submit",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/?id=&Submit=Submit",
                        "active_testable": False,
                        "type": "submit",
                    },
                ],
            }
        ],
    }

    result = LLMPayloadAdvisor(
        settings(llm_baseurl="http://llm.local", llm_apikey="k", llm_provider="deepseek", llm_on_local_targets=False)
    ).generate(
        webscan,
        [],
    )

    allowed = [item for item in result["items"] if item["allowed"]]
    assert result["summary"]["local_candidates"] >= 2
    assert {item["target_param"] for item in allowed} == {"id"}
    assert any(item["pair_role"] == "true" for item in allowed)
    assert any(item["pair_role"] == "false" for item in allowed)
    assert any("单条响应不能证明漏洞成立" in item["purpose"] for item in allowed)


def test_llm_payload_advisor_non_json_degrades(monkeypatch) -> None:
    def fake_chat(self, system_prompt: str, user_prompt: str) -> str:
        return "这里不是 JSON"

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fake_chat)
    result = LLMPayloadAdvisor(settings(llm_baseurl="http://llm.local", llm_apikey="k", llm_provider="deepseek")).generate({}, [])

    assert result["status"] == "unavailable"
    assert result["items"] == []


def test_report_contains_probe_payloads_status_evidence_and_llm_advice(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NOVA_REPORT_CONFIRMED_ONLY", "false")
    audit = {
        "target": "http://example.com/?q=1",
        "audited_at": "2026-05-22T00:00:00+00:00",
        "findings": [
            {
                "id": "NOVA-Q-001",
                "title": "URL 参数需要注入风险验证",
                "severity": "Low",
                "confidence": "Medium",
                "status": "待验证",
                "category": "injection",
                "url": "http://example.com/?q=1",
                "evidence": "目标 URL 中发现参数：q。",
                "payloads": ["' OR '1'='1"],
                "request_response": {"status_code": 200, "body_length": 123, "matched": "demo"},
                "recommendation": "校验输入。",
                "llm_analysis": "",
            }
        ],
        "llm_payload_advice": [
            {
                "input_point": "http://example.com/?q=1",
                "category": "sqli_blind",
                "target_param": "q",
                "payload": "1' AND '1'='1' -- -",
                "allowed": True,
                "filter_reason": "通过本地非破坏性 Safety Filter",
                "purpose": "验证布尔条件响应差异",
                "expected_signal": "exists",
                "risk_note": "",
            },
            {
                "input_point": "http://example.com/?q=1",
                "category": "sqli",
                "target_param": "q",
                "payload": "[已过滤] 1'; DROP...users;",
                "allowed": False,
                "filter_reason": "包含破坏性 SQL 关键字 DROP",
                "purpose": "",
                "expected_signal": "",
                "risk_note": "",
            },
        ],
        "llm_payload_summary": {
            "enabled": True,
            "status": "ok",
            "message": "ok",
            "report_only": True,
            "generated": 2,
            "allowed": 1,
            "blocked": 1,
        },
    }
    probe = {
        "reachable": True,
        "final_url": "http://example.com/?q=1",
        "status_code": 200,
        "auth_required": False,
        "auth_type_guess": "none",
        "in_scope": True,
        "dns": {"addresses": ["127.0.0.1"]},
        "tls": {"valid": None},
        "auth": auth_summary({"Authorization": "Bearer secret"}),
        "redirect_chain": [],
        "probe_errors": [],
    }

    report, json_path, markdown_path = PayloadAgent().build_report(
        "http://example.com/?q=1",
        {"status_code": 200, "title": "Mock"},
        audit,
        tmp_path,
        target_probe=probe,
    )

    assert report["summary"]["risk_level"] == "Low"
    assert report["summary"]["llm_payload_allowed"] == 1
    assert report["summary"]["finding_types"][0]["label"] == "输入点注入风险待验证"
    assert json_path.exists()
    markdown = markdown_path.read_text(encoding="utf-8-sig")
    assert "# NOVA 扫描报告" in markdown
    assert "## 目标探测结果" in markdown
    assert "## 漏洞类型汇总" in markdown
    assert "输入点注入风险待验证" in markdown
    assert "状态：待验证" in markdown
    assert "status=200" in markdown
    assert "' OR '1'='1" in markdown
    assert "## 候选 Payload" in markdown
    assert "1' AND '1'='1' -- -" in markdown
    assert "包含破坏性 SQL 关键字 DROP" in markdown
    assert "Bearer secret" not in markdown


def test_report_hides_non_confirmed_findings_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("NOVA_REPORT_CONFIRMED_ONLY", raising=False)
    audit = {
        "target": "http://example.com/?q=1",
        "audited_at": "2026-05-22T00:00:00+00:00",
        "findings": [
            {
                "id": "NOVA-H-001",
                "title": "缺少 Content-Security-Policy 响应头",
                "severity": "Medium",
                "confidence": "High",
                "status": "配置建议",
                "category": "security_header",
                "url": "http://example.com/",
                "evidence": "header missing",
                "payloads": [],
                "request_response": {},
                "recommendation": "fix header",
                "llm_analysis": "",
            },
            {
                "id": "NOVA-SQLI-001",
                "title": "确认存在 SQL 注入错误回显",
                "severity": "High",
                "confidence": "High",
                "status": "确认漏洞",
                "category": "sqli",
                "url": "http://example.com/?q=1",
                "evidence": "SQL error",
                "payloads": ["1'", "1' ORDER BY 1 -- -"],
                "request_response": {},
                "recommendation": "use prepared statements",
                "llm_analysis": "",
            },
        ],
        "llm_payload_advice": [],
        "llm_payload_summary": {"enabled": False, "status": "disabled", "message": "", "report_only": True},
    }

    report, _, markdown_path = PayloadAgent().build_report(
        "http://example.com/?q=1",
        {"status_code": 200, "title": "Mock"},
        audit,
        tmp_path,
        target_probe={"reachable": True, "auth": {}, "redirect_chain": [], "probe_errors": []},
    )

    markdown = markdown_path.read_text(encoding="utf-8-sig")
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["raw_total_findings"] == 2
    assert "确认存在 SQL 注入错误回显" in markdown
    assert "缺少 Content-Security-Policy" not in markdown


def test_report_notes_llm_unavailable(tmp_path: Path) -> None:
    audit = {
        "target": "http://example.com",
        "audited_at": "2026-05-22T00:00:00+00:00",
        "findings": [],
        "llm_payload_advice": [],
        "llm_payload_summary": {
            "enabled": True,
            "status": "unavailable",
            "message": "LLM 未配置或不可用",
            "report_only": True,
            "generated": 0,
            "allowed": 0,
            "blocked": 0,
        },
    }
    report, _, markdown_path = PayloadAgent().build_report(
        "http://example.com",
        {"status_code": 200, "title": "Mock"},
        audit,
        tmp_path,
        target_probe={"reachable": True, "auth": {}, "redirect_chain": [], "probe_errors": []},
    )

    markdown = markdown_path.read_text(encoding="utf-8-sig")
    assert report["summary"]["total_findings"] == 0
    assert "候选 Payload 未启用或不可用" in markdown
