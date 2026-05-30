from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
from http.cookies import SimpleCookie
from html.parser import HTMLParser
import re
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from backend.helper.auth import auth_summary
from backend.helper.settings import RuntimeSettings
from backend.helper.utils import utc_now


RISKY_PATH_PARTS = ("/logout", "/signout", "/delete", "/remove")
IGNORED_LINK_SCHEMES = {"javascript", "mailto", "tel", "data"}


@dataclass(frozen=True)
class ScanScope:
    scheme: str
    netloc: str
    max_depth: int
    allowed_hosts: tuple[str, ...]
    exclude_paths: tuple[str, ...]

    @classmethod
    def from_settings(cls, target_url: str, settings: RuntimeSettings) -> "ScanScope":
        parsed = urlparse(target_url)
        allowed_hosts = tuple(host.lower() for host in settings.allowed_hosts)
        return cls(
            scheme=parsed.scheme,
            netloc=parsed.netloc.lower(),
            max_depth=settings.max_depth,
            allowed_hosts=allowed_hosts,
            exclude_paths=tuple(settings.exclude_paths),
        )

    def in_scope(self, candidate_url: str, depth: int) -> tuple[bool, str]:
        parsed = urlparse(candidate_url)
        if depth > self.max_depth:
            return False, "max_depth"
        if parsed.scheme != self.scheme:
            return False, "different_scheme"
        host_allowed = parsed.netloc.lower() == self.netloc or parsed.netloc.lower() in self.allowed_hosts
        if not host_allowed:
            return False, "host_not_allowed"
        if any(parsed.path.startswith(path) for path in self.exclude_paths):
            return False, "path_excluded"
        if any(part in parsed.path.lower() for part in RISKY_PATH_PARTS):
            return False, "risky_path"
        return True, "in_scope"

    def as_dict(self) -> dict:
        return {
            "scheme": self.scheme,
            "netloc": self.netloc,
            "max_depth": self.max_depth,
            "allowed_hosts": list(self.allowed_hosts),
            "exclude_paths": list(self.exclude_paths),
        }


class _PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.title = ""
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[dict] = []
        self._in_title = False
        self._in_script = False
        self._current_script: list[str] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        data = {key.lower(): value or "" for key, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "a" and data.get("href"):
            link = urljoin(self.base_url, data["href"])
            parsed = urlparse(link)
            if parsed.scheme.lower() not in IGNORED_LINK_SCHEMES and not parsed.fragment:
                self.links.append(link)
        elif tag == "script" and data.get("src"):
            self.scripts.append(urljoin(self.base_url, data["src"]))
        elif tag == "script":
            self._in_script = True
            self._current_script = []
        elif tag == "form":
            self._current_form = {
                "method": data.get("method", "GET").upper(),
                "action": urljoin(self.base_url, data.get("action", self.base_url)),
                "enctype": data.get("enctype", "application/x-www-form-urlencoded").lower(),
                "page_url": self.base_url,
                "active_testable": True,
                "active_scope_reason": "in_scope",
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            input_type = data.get("type", "text").lower()
            name = data.get("name", "")
            value = data.get("value", "")
            self._current_form["inputs"].append(
                {
                    "tag": tag,
                    "name": name,
                    "type": input_type,
                    "value": value,
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
        elif tag.lower() == "script" and self._in_script:
            inline = "".join(self._current_script).strip()
            if inline:
                self.inline_scripts.append(inline)
            self._in_script = False
            self._current_script = []
        elif tag.lower() == "form" and self._current_form is not None:
            self._finalize_form(self._current_form)
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()
        if self._in_script:
            self._current_script.append(data)

    def _finalize_form(self, form: dict) -> None:
        file_inputs = [field for field in form.get("inputs", []) if field.get("type") == "file"]
        names = " ".join(str(field.get("name", "")).lower() for field in form.get("inputs", []))
        action = str(form.get("action", "")).lower()
        purpose = "generic"
        if file_inputs or "multipart/form-data" in str(form.get("enctype", "")):
            purpose = "file_upload"
        elif any(token in names or token in action for token in ("comment", "message", "content", "body", "post", "feedback")):
            purpose = "stored_xss_candidate"
        form["file_inputs"] = file_inputs
        form["candidate_purpose"] = purpose


class WebScannerAgent:
    def __init__(self, settings: RuntimeSettings) -> None:
        self.settings = settings

    def scan(self, target_url: str) -> dict:
        scope = ScanScope.from_settings(target_url, self.settings)
        queue: deque[tuple[str, int]] = deque([(target_url, 0)])
        queued: set[str] = {self._normalize_for_seen(target_url)}
        seen: set[str] = set()
        pages: list[dict] = []
        errors: list[dict] = []
        events: list[dict] = []
        max_queue_items = max(self.settings.max_pages * max(self.settings.max_links, 1) * 2, self.settings.max_pages)

        while queue and len(pages) < self.settings.max_pages:
            url, depth = queue.popleft()
            normalized = self._normalize_for_seen(url)
            queued.discard(normalized)
            if normalized in seen:
                continue
            seen.add(normalized)

            allowed, reason = scope.in_scope(url, depth)
            if not allowed:
                events.append({"url": url, "depth": depth, "event": "skipped", "reason": reason})
                continue

            page = self._fetch_page(url, depth)
            if not page.get("reachable"):
                errors.append({"url": url, "error": page.get("error", "请求失败")})
                continue

            if self.settings.focus_target_path and not self._active_path_allowed(target_url, page.get("final_url") or url):
                page["active_testable"] = False
                page["active_scope_reason"] = "outside_target_path"
                self._deactivate_page_inputs(page, "outside_target_path")
                self._deactivate_page_forms(page, "outside_target_path")
                events.append(
                    {
                        "url": page.get("final_url") or url,
                        "depth": depth,
                        "event": "active_inputs_disabled",
                        "reason": "outside_target_path",
                    }
                )
            if self.settings.focus_target_path:
                self._deactivate_outside_target_active_surfaces(page, target_url)

            pages.append(page)
            for link in page.get("links", [])[: self.settings.max_links]:
                normalized_link = self._normalize_for_seen(link)
                if normalized_link in seen or normalized_link in queued:
                    continue
                if len(queue) >= max_queue_items:
                    events.append({"url": link, "depth": depth + 1, "event": "link_skipped", "reason": "queue_limit"})
                    continue
                link_allowed, link_reason = scope.in_scope(link, depth + 1)
                if link_allowed:
                    queue.append((link, depth + 1))
                    queued.add(normalized_link)
                else:
                    events.append({"url": link, "depth": depth + 1, "event": "link_skipped", "reason": link_reason})
            if self.settings.rate_limit:
                time.sleep(self.settings.rate_limit)

        first = pages[0] if pages else {}
        input_points = self._dedupe_input_points([point for page in pages for point in page.get("input_points", [])])
        forms = [form for page in pages for form in page.get("forms", [])]
        links = self._dedupe([link for page in pages for link in page.get("links", [])])[: self.settings.max_links]
        cookies = self._dedupe_cookies([cookie for page in pages for cookie in page.get("cookies", [])])
        return {
            "agent": "Webscanner Agent",
            "target": target_url,
            "scanned_at": utc_now(),
            "reachable": bool(pages),
            "status_code": first.get("status_code"),
            "final_url": first.get("final_url", target_url),
            "headers": first.get("headers", {}),
            "title": first.get("title", ""),
            "links": links,
            "forms": forms,
            "cookies": cookies,
            "technologies": self._fingerprint(first.get("headers", {})),
            "input_points": input_points,
            "pages": pages,
            "events": events,
            "errors": errors,
            "scope": scope.as_dict(),
            "auth": auth_summary(self.settings.auth_headers),
            "safety_constraints": [
                "默认只扫描同 scheme、host、port 范围内的 URL",
                "不提交 POST/PUT/PATCH/DELETE 表单",
                "主动验证仅限 GET 参数和 GET 表单",
                "默认排除 logout、delete、remove 等危险路径",
                "爬取去重按路径和参数名处理，避免反射页面因参数值变化反复入队",
                "默认只对目标 URL 所在路径内的输入点做主动验证，导航到其它模块的页面只记录不主动测试",
            ],
        }

    def _fetch_page(self, url: str, depth: int) -> dict:
        request = Request(
            url,
            headers={"User-Agent": "NOVA-safe-scanner/1.0", **self.settings.auth_headers},
            method="GET",
        )
        try:
            with urlopen(request, timeout=self.settings.request_timeout) as response:
                raw = response.read(500000)
                charset = response.headers.get_content_charset() or "utf-8"
                html = raw.decode(charset, errors="replace")
                headers = dict(response.headers.items())
                set_cookie_values = []
                if hasattr(response.headers, "get_all"):
                    set_cookie_values = list(response.headers.get_all("Set-Cookie", []) or [])
                if set_cookie_values and "Set-Cookie" not in headers:
                    headers["Set-Cookie"] = "\n".join(set_cookie_values)
                final_url = response.url
                status_code = response.status
        except Exception as exc:
            return {"url": url, "reachable": False, "error": str(exc)}

        parser = _PageParser(final_url)
        parser.feed(html)
        html_sample = re.sub(r"\s+", " ", html[:3000]).strip()
        input_points = self._extract_input_points(final_url, parser.forms)
        input_points.extend(self._extract_query_input_points(final_url))
        input_points.extend(self._extract_link_input_points(final_url, parser.links))
        script_items = self._script_items(final_url, parser.scripts, parser.inline_scripts)
        return {
            "url": url,
            "depth": depth,
            "reachable": True,
            "status_code": status_code,
            "final_url": final_url,
            "active_testable": True,
            "headers": headers,
            "title": parser.title[:120],
            "links": self._dedupe(parser.links)[: self.settings.max_links],
            "scripts": script_items[: self.settings.max_links],
            "forms": parser.forms,
            "cookies": self._parse_cookies(headers),
            "input_points": self._dedupe_input_points(input_points),
            "html_sample": html_sample,
            "response_summary": html_sample[:500],
        }

    def _extract_input_points(self, page_url: str, forms: list[dict]) -> list[dict]:
        points: list[dict] = []
        for form in forms:
            method = form.get("method", "GET").upper()
            action = form.get("action") or page_url
            defaults = self._form_defaults(form)
            for field in form.get("inputs", []):
                name = field.get("name", "")
                if not name:
                    continue
                input_type = (field.get("type") or "text").lower()
                active_testable = method == "GET" and input_type not in {"submit", "button", "reset", "hidden"}
                points.append(
                    {
                        "name": name,
                        "method": method,
                        "url": self._url_with_defaults(action, defaults) if method == "GET" else action,
                        "source": "form",
                        "type": input_type,
                        "active_testable": active_testable,
                        "form_defaults": defaults,
                    }
                )
        return points

    def _script_items(self, page_url: str, script_urls: list[str], inline_scripts: list[str]) -> list[dict]:
        items: list[dict] = []
        for index, inline in enumerate(inline_scripts, start=1):
            sample = inline[: min(len(inline), self.settings.max_script_bytes)]
            items.append(
                {
                    "url": f"{page_url}#inline-script-{index}",
                    "inline": True,
                    "content_sample": sample,
                    "hash": hashlib.sha256(sample.encode("utf-8", errors="ignore")).hexdigest(),
                }
            )
        for script_url in self._dedupe(script_urls)[: self.settings.max_links]:
            item = {"url": script_url, "inline": False}
            if self.settings.fetch_same_origin_scripts and self._same_origin(page_url, script_url):
                fetched = self._fetch_script(script_url)
                item.update(fetched)
            items.append(item)
        return items

    def _same_origin(self, left_url: str, right_url: str) -> bool:
        left = urlparse(left_url)
        right = urlparse(right_url)
        return left.scheme == right.scheme and left.netloc.lower() == right.netloc.lower()

    def _fetch_script(self, script_url: str) -> dict:
        request = Request(
            script_url,
            headers={"User-Agent": "NOVA-safe-scanner/1.0", **self.settings.auth_headers},
            method="GET",
        )
        try:
            with urlopen(request, timeout=self.settings.request_timeout) as response:
                raw = response.read(self.settings.max_script_bytes)
                charset = response.headers.get_content_charset() or "utf-8"
                content = raw.decode(charset, errors="replace")
                return {
                    "content_sample": content,
                    "body_length": len(content),
                    "status_code": response.status,
                    "hash": hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest(),
                }
        except Exception as exc:
            return {"fetch_error": str(exc)}

    def _active_path_allowed(self, target_url: str, candidate_url: str) -> bool:
        target = urlparse(target_url)
        candidate = urlparse(candidate_url)
        target_path = target.path or "/"
        candidate_path = candidate.path or "/"
        if target_path == "/":
            return True
        normalized_target = target_path.rstrip("/")
        return candidate_path == normalized_target or candidate_path.startswith(f"{normalized_target}/")

    def _deactivate_page_inputs(self, page: dict, reason: str) -> None:
        for point in page.get("input_points", []):
            if point.get("active_testable"):
                point["active_testable"] = False
                point["active_scope_reason"] = reason

    def _deactivate_page_forms(self, page: dict, reason: str) -> None:
        for form in page.get("forms", []):
            form["active_testable"] = False
            form["active_scope_reason"] = reason

    def _deactivate_outside_target_active_surfaces(self, page: dict, target_url: str) -> None:
        for point in page.get("input_points", []):
            if not point.get("active_testable"):
                continue
            point_url = str(point.get("url") or "")
            if point_url and not self._active_path_allowed(target_url, point_url):
                point["active_testable"] = False
                point["active_scope_reason"] = "outside_target_path"
        for form in page.get("forms", []):
            if form.get("active_testable") is False:
                continue
            action = str(form.get("action") or form.get("page_url") or page.get("final_url") or "")
            if action and not self._active_path_allowed(target_url, action):
                form["active_testable"] = False
                form["active_scope_reason"] = "outside_target_path"

    def _extract_query_input_points(self, url: str) -> list[dict]:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        return [
            {
                "name": name,
                "method": "GET",
                "url": url,
                "source": "query",
                "type": "query",
                "active_testable": True,
                "form_defaults": {},
            }
            for name in query
        ]

    def _extract_link_input_points(self, page_url: str, links: list[str]) -> list[dict]:
        points: list[dict] = []
        for link in links:
            parsed = urlparse(link)
            query = parse_qs(parsed.query, keep_blank_values=True)
            if not query:
                continue
            same_origin = self._same_origin(page_url, link)
            for name in query:
                points.append(
                    {
                        "name": name,
                        "method": "GET",
                        "url": link,
                        "source": "link",
                        "type": "query",
                        "active_testable": same_origin,
                        "form_defaults": {},
                    }
                )
        return points

    def _form_defaults(self, form: dict) -> dict[str, str]:
        defaults: dict[str, str] = {}
        for field in form.get("inputs", []):
            name = field.get("name", "")
            if not name:
                continue
            input_type = (field.get("type") or "text").lower()
            value = field.get("value") or ""
            if input_type == "submit" and not value:
                value = name
            defaults[name] = value
        return defaults

    def _url_with_defaults(self, url: str, defaults: dict[str, str]) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        for name, value in defaults.items():
            query.setdefault(name, [value])
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

    def _parse_cookies(self, headers: dict[str, str]) -> list[dict]:
        raw_values: list[str] = []
        for name, value in headers.items():
            if name.lower() == "set-cookie":
                raw_values.extend([item for item in value.splitlines() if item.strip()])
        cookies = []
        for raw in raw_values:
            parsed = SimpleCookie()
            parsed.load(raw)
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

    def _fingerprint(self, headers: dict[str, str]) -> list[str]:
        lowered = {key.lower(): value for key, value in headers.items()}
        signals = []
        for key in ("server", "x-powered-by", "cf-ray", "x-sucuri-id"):
            if lowered.get(key):
                signals.append(f"{key}:{lowered[key]}")
        return signals

    def _dedupe(self, values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    def _dedupe_input_points(self, values: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        result: list[dict] = []
        for item in values:
            key = (item.get("method", ""), item.get("url", ""), item.get("name", ""))
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    def _dedupe_cookies(self, values: list[dict]) -> list[dict]:
        seen: set[str] = set()
        result = []
        for item in values:
            name = item.get("name", "")
            if name in seen:
                continue
            seen.add(name)
            result.append(item)
        return result

    def _normalize_for_seen(self, url: str) -> str:
        parsed = urlparse(url)
        query_names = sorted(parse_qs(parsed.query, keep_blank_values=True))
        normalized_query = urlencode([(name, "") for name in query_names])
        return urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", normalized_query, ""))
