from __future__ import annotations

import time

import requests

from backend.helper.settings import RuntimeSettings


class LLMClient:
    def __init__(self, settings: RuntimeSettings) -> None:
        self.settings = settings

    def _proxies(self) -> dict[str, str] | None:
        proxy = getattr(self.settings, "llm_proxy", None)
        if not proxy:
            return None
        return {"http": proxy, "https": proxy}

    def _friendly_error(self, exc: Exception) -> str:
        message = str(exc)
        if "10054" in message or "UNEXPECTED_EOF_WHILE_READING" in message or "Connection aborted" in message:
            return "DeepSeek API 连接被远端重置或中断，请检查网络、代理或 API 访问策略"
        if "timed out" in message.lower():
            return "DeepSeek API 请求超时，请尝试增大 NOVA_LLM_REQUEST_TIMEOUT 或检查网络"
        return message

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        if not self.settings.llm_enabled:
            return ""

        baseurl = self.settings.llm_baseurl.rstrip("/")
        endpoint = baseurl
        if not endpoint.endswith("/chat/completions"):
            endpoint = f"{endpoint}/chat/completions"

        payload = {
            "model": self.settings.llm_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }
        headers = {
            "Authorization": f"Bearer {self.settings.llm_apikey}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "NOVA/1.0",
        }
        timeout = getattr(self.settings, "llm_request_timeout", None) or self.settings.request_timeout
        retries = max(0, int(getattr(self.settings, "llm_request_retries", 2)))
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            try:
                response = requests.post(
                    endpoint,
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                    proxies=self._proxies(),
                )
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
            except Exception as exc:
                last_error = exc
                if attempt >= retries:
                    break
                time.sleep(min(0.5 * (attempt + 1), 2.0))
        raise RuntimeError(
            f"LLM request failed after {retries + 1} attempts: {self._friendly_error(last_error or RuntimeError('unknown error'))}"
        ) from last_error
