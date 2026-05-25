from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


ENV_PATH = Path(__file__).parent.parent / "config" / ".env"

LLM_BASEURL: str | None = None
LLM_APIKEY: str | None = None
LLM_MODEL: str | None = None
LLM_PROVIDER: str | None = None

if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)

LLM_BASEURL = os.getenv("LLM_BASEURL")
LLM_APIKEY = os.getenv("LLM_APIKEY")
LLM_MODEL = os.getenv("LLM_MODEL") or "deepseekV4-flash"
LLM_PROVIDER = os.getenv("LLM_PROVIDER")
