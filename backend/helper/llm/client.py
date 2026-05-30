from __future__ import annotations

import json
import time

import requests

from backend.helper.settings import RuntimeSettings


class LLMClient:
    def __init__(self, settings: RuntimeSettings) -> None:
        self.settings = settings

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
        }
        timeout = getattr(self.settings, "llm_request_timeout", None) or self.settings.request_timeout
        retries = max(0, int(getattr(self.settings, "llm_request_retries", 2)))
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            try:
                response = requests.post(endpoint, headers=headers, data=json.dumps(payload), timeout=timeout)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
            except Exception as exc:
                last_error = exc
                if attempt >= retries:
                    break
                time.sleep(min(0.5 * (attempt + 1), 2.0))
        raise RuntimeError(f"LLM request failed after {retries + 1} attempts: {last_error}") from last_error
