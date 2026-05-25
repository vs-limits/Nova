from __future__ import annotations

from html.parser import HTMLParser
import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from backend.helper.auth import auth_summary
from backend.helper.settings import RuntimeSettings
from backend.helper.utils import utc_now


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _LoginSignalParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.has_password_input = False
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        data = {key.lower(): value or "" for key, value in attrs}
        if tag == "form":
            self._current_form = {
                "method": data.get("method", "GET").upper(),
                "action": urljoin(self.base_url, data.get("action", self.base_url)),
                "has_password": False,
            }
        elif tag == "input":
            input_type = data.get("type", "text").lower()
            if input_type == "password":
                self.has_password_input = True
                if self._current_form is not None:
                    self._current_form["has_password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class TargetProbeAgent:
    def __init__(self, settings: RuntimeSettings) -> None:
        self.settings = settings

    def probe(self, target_url: str) -> dict:
        result = self._empty_result(target_url)
        result["dns"] = self._resolve_dns(target_url)
        result["tls"] = self._check_tls(target_url)

        response = self._request_with_redirect_chain(target_url)
        result.update(response)
        result["auth"] = auth_summary(self.settings.auth_headers)

        auth_required, auth_type = self._detect_auth_required(response)
        result["auth_required"] = auth_required
        result["auth_type_guess"] = auth_type
        result["in_scope"] = self._same_origin_or_allowed(target_url, result.get("final_url", target_url))
        result["scan_allowed"] = bool(result["reachable"] and result["in_scope"])
        return result

    def _empty_result(self, target_url: str) -> dict:
        return {
            "agent": "TargetProbe Agent",
            "target": target_url,
            "probed_at": utc_now(),
            "reachable": False,
            "status_code": None,
            "final_url": target_url,
            "redirect_chain": [],
            "headers": {},
            "server_fingerprint": [],
            "auth_required": False,
            "auth_type_guess": "none",
            "login_signals": {},
            "in_scope": True,
            "scan_allowed": False,
            "probe_errors": [],
            "safety_constraints": (
                "TargetProbe only checks the provided URL, follows explicit HTTP redirects, "
                "does not enumerate subdomains, does not brute force, and never writes raw secrets."
            ),
        }

    def _resolve_dns(self, target_url: str) -> dict:
        host = urlparse(target_url).hostname
        if not host:
            return {"host": "", "addresses": [], "error": "missing host"}
        try:
            records = socket.getaddrinfo(host, None)
            addresses = sorted({item[4][0] for item in records})
            return {"host": host, "addresses": addresses, "error": ""}
        except Exception as exc:
            return {"host": host, "addresses": [], "error": str(exc)}

    def _check_tls(self, target_url: str) -> dict:
        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return {"checked": False, "valid": None, "error": ""}
        host = parsed.hostname
        if not host:
            return {"checked": True, "valid": False, "error": "missing host"}
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.settings.request_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
            return {"checked": True, "valid": True, "subject": cert.get("subject", []), "error": ""}
        except Exception as exc:
            return {"checked": True, "valid": False, "error": str(exc)}

    def _request_with_redirect_chain(self, target_url: str) -> dict:
        current_url = target_url
        redirect_chain: list[dict] = []
        errors: list[str] = []
        headers: dict[str, str] = {}
        body_sample = ""
        status_code = None
        method_used = "HEAD"

        for _ in range(5):
            response = self._single_request(current_url, method_used)
            if response.get("error") and method_used == "HEAD":
                method_used = "GET"
                response = self._single_request(current_url, method_used)

            if response.get("error"):
                errors.append(response["error"])
                break

            status_code = response["status_code"]
            headers = response["headers"]
            body_sample = response.get("body_sample", "")
            location = headers.get("Location") or headers.get("location")
            if status_code in {301, 302, 303, 307, 308} and location:
                next_url = urljoin(current_url, location)
                redirect_chain.append({"from": current_url, "to": next_url, "status_code": status_code})
                current_url = next_url
                method_used = "GET" if status_code == 303 else method_used
                continue
            break

        if status_code is not None and method_used == "HEAD":
            body_response = self._single_request(current_url, "GET")
            if not body_response.get("error"):
                status_code = body_response["status_code"]
                headers = body_response["headers"] or headers
                body_sample = body_response.get("body_sample", "")

        login_signals = self._parse_login_signals(current_url, body_sample)
        return {
            "reachable": status_code is not None,
            "status_code": status_code,
            "final_url": current_url,
            "redirect_chain": redirect_chain,
            "headers": headers,
            "server_fingerprint": self._fingerprint(headers),
            "login_signals": login_signals,
            "probe_errors": errors,
        }

    def _single_request(self, url: str, method: str) -> dict:
        headers = {"User-Agent": "NOVA-target-probe/1.0"}
        headers.update(self.settings.auth_headers)
        request = Request(url, headers=headers, method=method)
        opener = build_opener(_NoRedirectHandler)
        try:
            with opener.open(request, timeout=self.settings.request_timeout) as response:
                body_sample = ""
                if method == "GET":
                    body_sample = response.read(200000).decode(
                        response.headers.get_content_charset() or "utf-8",
                        errors="replace",
                    )
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers.items()),
                    "body_sample": body_sample,
                    "error": "",
                }
        except HTTPError as exc:
            body_sample = ""
            try:
                if method == "GET":
                    body_sample = exc.read(200000).decode(
                        exc.headers.get_content_charset() or "utf-8",
                        errors="replace",
                    )
            except Exception:
                body_sample = ""
            return {
                "status_code": exc.code,
                "headers": dict(exc.headers.items()),
                "body_sample": body_sample,
                "error": "",
            }
        except URLError as exc:
            return {"status_code": None, "headers": {}, "body_sample": "", "error": str(exc)}
        except Exception as exc:
            return {"status_code": None, "headers": {}, "body_sample": "", "error": str(exc)}

    def _detect_auth_required(self, response: dict) -> tuple[bool, str]:
        status_code = response.get("status_code")
        headers = {key.lower(): value for key, value in response.get("headers", {}).items()}
        login_signals = response.get("login_signals", {})
        final_path = urlparse(response.get("final_url", "")).path.lower()

        if status_code == 401:
            auth_header = headers.get("www-authenticate", "").lower()
            if "basic" in auth_header:
                return True, "basic"
            if "bearer" in auth_header:
                return True, "bearer"
            return True, "http_auth"
        if status_code == 403:
            return True, "forbidden"
        if "login" in final_path or "signin" in final_path:
            return True, "login_page"
        if login_signals.get("has_password_input"):
            return True, "form_login"
        return False, "none"

    def _parse_login_signals(self, final_url: str, body_sample: str) -> dict:
        parser = _LoginSignalParser(final_url)
        parser.feed(body_sample or "")
        password_forms = [form for form in parser.forms if form.get("has_password")]
        return {
            "has_password_input": parser.has_password_input,
            "password_form_count": len(password_forms),
            "login_form_actions": [form.get("action") for form in password_forms],
        }

    def _same_origin_or_allowed(self, target_url: str, final_url: str) -> bool:
        target = urlparse(target_url)
        final = urlparse(final_url)
        if (target.scheme, target.netloc.lower()) == (final.scheme, final.netloc.lower()):
            return True
        return final.netloc.lower() in {host.lower() for host in self.settings.allowed_hosts}

    def _fingerprint(self, headers: dict[str, str]) -> list[str]:
        lowered = {key.lower(): value for key, value in headers.items()}
        signals: list[str] = []
        for name in ("server", "x-powered-by", "cf-ray", "x-sucuri-id", "x-akamai-transformed"):
            if lowered.get(name):
                signals.append(f"{name}:{lowered[name]}")
        return signals
