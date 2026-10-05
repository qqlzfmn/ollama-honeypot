"""事件落盘：一行一个 JSON 对象。所有不可信文本在这里被清洗。"""

from __future__ import annotations

import json
import os
import threading
import time

# 去掉除制表符以外的控制字符，防止攻击者用换行/转义污染日志
_DROP_CHARS = {code: None for code in range(0x20) if chr(code) not in "\t"}
_DROP_CHARS[0x7F] = None

TRUNCATED_SUFFIX = "…<truncated>"


class LogPathError(RuntimeError):
    """日志路径不可写。启动阶段就要失败，不能等到有流量时才发现。"""

    def __init__(self, path: str, exc: OSError) -> None:
        super().__init__(
            f"日志路径不可写：{path}（{exc.strerror}）。"
            "容器内以非 root 运行，宿主目录必须归属容器用户，例如："
            "mkdir -p data && sudo chown -R 10001:10001 data"
        )


def sanitize(value: str, max_chars: int) -> str:
    """把不可信文本压成可安全写入日志的单行文本。"""
    text = value.translate(_DROP_CHARS)
    if len(text) > max_chars:
        return text[:max_chars] + TRUNCATED_SUFFIX
    return text


class EventWriter:
    """线程安全的 JSONL 追加写入器，同时输出到标准输出。"""

    def __init__(self, path: str, max_field_chars: int) -> None:
        self._path = path
        self._max_field_chars = max_field_chars
        self._lock = threading.Lock()
        directory = os.path.dirname(path)
        try:
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise LogPathError(path, exc) from exc

    @property
    def max_field_chars(self) -> int:
        return self._max_field_chars

    def write(self, event: dict) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line)
        print(line, end="", flush=True)
