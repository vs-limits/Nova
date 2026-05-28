from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from backend.helper.settings import RuntimeSettings


class HttpClient:
    def __init__(self, settings: RuntimeSettings, opener) -> None:
        self.settings = settings
        self.opener = opener

    def get(self, url: str) -> dict | None:
        try:
            request = Request(
                url,
                headers={"User-Agent": "NOVA-safe-scanner/1.0", **self.settings.auth_headers},
                method="GET",
            )
            timeout = max(0.5, min(float(self.settings.request_timeout), float(self.settings.active_request_timeout)))
            with self.opener(request, timeout=timeout) as response:
                body = response.read(300000).decode(
                    response.headers.get_content_charset() or "utf-8",
                    errors="replace",
                )
                return {
                    "url": response.url,
                    "status_code": response.status,
                    "headers": self._headers_dict(response.headers),
                    "set_cookie": self._set_cookie_values(response.headers),
                    "body": body,
                    "body_length": len(body),
                }
        except Exception:
            return None

    def get_no_redirect(self, url: str) -> dict | None:
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
                return None

        request = Request(
            url,
            headers={"User-Agent": "NOVA-safe-scanner/1.0", **self.settings.auth_headers},
            method="GET",
        )
        timeout = max(0.5, min(float(self.settings.request_timeout), float(self.settings.active_request_timeout)))
        opener = build_opener(NoRedirect)
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read(300000).decode(
                    response.headers.get_content_charset() or "utf-8",
                    errors="replace",
                )
                return {
                    "url": response.url,
                    "status_code": response.status,
                    "headers": self._headers_dict(response.headers),
                    "set_cookie": self._set_cookie_values(response.headers),
                    "body": body,
                    "body_length": len(body),
                }
        except HTTPError as exc:
            body = exc.read(300000).decode(
                exc.headers.get_content_charset() or "utf-8",
                errors="replace",
            )
            return {
                "url": exc.url,
                "status_code": exc.code,
                "headers": self._headers_dict(exc.headers),
                "set_cookie": self._set_cookie_values(exc.headers),
                "body": body,
                "body_length": len(body),
            }
        except Exception:
            return None

    def mutate_url(self, url: str, param: str, payload: str, context_params: dict | None = None) -> str:
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

    def post_form(self, url: str, fields: dict[str, str]) -> dict | None:
        data = urlencode(fields, doseq=True).encode("utf-8")
        request = Request(
            url,
            data=data,
            headers={
                "User-Agent": "NOVA-safe-scanner/1.0",
                "Content-Type": "application/x-www-form-urlencoded",
                **self.settings.auth_headers,
            },
            method="POST",
        )
        return self._send_request(request)

    def post_multipart_text_file(self, url: str, fields: dict[str, str], file_field: str, filename: str, content: str) -> dict | None:
        boundary = "----NOVAUploadBoundary"
        parts: list[bytes] = []
        for name, value in fields.items():
            parts.append(
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                    f"{value}\r\n"
                ).encode("utf-8")
            )
        parts.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
                "Content-Type: text/plain\r\n\r\n"
                f"{content}\r\n"
                f"--{boundary}--\r\n"
            ).encode("utf-8")
        )
        request = Request(
            url,
            data=b"".join(parts),
            headers={
                "User-Agent": "NOVA-safe-scanner/1.0",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                **self.settings.auth_headers,
            },
            method="POST",
        )
        return self._send_request(request)

    def _send_request(self, request: Request) -> dict | None:
        try:
            timeout = max(0.5, min(float(self.settings.request_timeout), float(self.settings.active_request_timeout)))
            with self.opener(request, timeout=timeout) as response:
                body = response.read(300000).decode(
                    response.headers.get_content_charset() or "utf-8",
                    errors="replace",
                )
                return {
                    "url": response.url,
                    "status_code": response.status,
                    "headers": self._headers_dict(response.headers),
                    "set_cookie": self._set_cookie_values(response.headers),
                    "body": body,
                    "body_length": len(body),
                }
        except Exception:
            return None

    def _headers_dict(self, headers) -> dict:
        result = dict(headers.items())
        set_cookie_values = self._set_cookie_values(headers)
        if set_cookie_values and "Set-Cookie" not in result:
            result["Set-Cookie"] = "\n".join(set_cookie_values)
        return result

    def _set_cookie_values(self, headers) -> list[str]:
        if hasattr(headers, "get_all"):
            return list(headers.get_all("Set-Cookie", []) or [])
        value = headers.get("Set-Cookie") if hasattr(headers, "get") else None
        return [value] if value else []
