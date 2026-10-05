"""运行期配置。全部来自环境变量，不硬编码任何凭据。"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_LOG_PATH = "/data/events.jsonl"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} 必须是整数，实际为 {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} 必须为正数，实际为 {value}")
    return value


@dataclass(frozen=True)
class Config:
    """蜜罐的不可变配置。"""

    host: str
    port: int
    ollama_version: str
    log_path: str
    max_body_bytes: int
    max_field_chars: int
    read_timeout_seconds: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            host=os.environ.get("HONEYPOT_HOST", "0.0.0.0"),
            port=_env_int("HONEYPOT_PORT", 11434),
            # 对外宣称的版本，用于吸引针对特定版本的利用尝试
            ollama_version=os.environ.get("HONEYPOT_OLLAMA_VERSION", "0.5.7"),
            log_path=os.environ.get("HONEYPOT_LOG_PATH", DEFAULT_LOG_PATH),
            max_body_bytes=_env_int("HONEYPOT_MAX_BODY_BYTES", 256 * 1024),
            max_field_chars=_env_int("HONEYPOT_MAX_FIELD_CHARS", 4096),
            read_timeout_seconds=_env_int("HONEYPOT_READ_TIMEOUT_SECONDS", 15),
        )
