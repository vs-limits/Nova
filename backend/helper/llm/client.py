from __future__ import annotations

from urllib.request import Request, urlopen
import json

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
        request = Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.settings.llm_apikey}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        with urlopen(request, timeout=self.settings.request_timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]
