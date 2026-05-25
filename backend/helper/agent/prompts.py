from __future__ import annotations

from backend.helper.settings import PROMPTS_DIR


def load_prompt(name: str) -> str:
    path = PROMPTS_DIR / f"{name}.md"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")
