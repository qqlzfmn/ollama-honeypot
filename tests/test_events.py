import os
from pathlib import Path

import pytest

from honeypot.events import EventWriter, LogPathError, sanitize


def test_sanitize_strips_control_characters() -> None:
    assert sanitize("a\x00b\nc\rd\x1b", 100) == "abcd"


def test_sanitize_truncates_long_values() -> None:
    result = sanitize("x" * 50, 10)
    assert result.startswith("x" * 10)
    assert "truncated" in result
    assert len(result) < 50


def test_writer_appends_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    writer = EventWriter(str(path), 64)
    writer.write({"category": "other"})
    writer.write({"category": "llm_use"})

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


@pytest.mark.skipif(os.geteuid() == 0, reason="root 不受目录权限限制")
def test_unwritable_log_path_fails_fast(tmp_path: Path) -> None:
    directory = tmp_path / "locked"
    directory.mkdir()
    directory.chmod(0o500)
    try:
        with pytest.raises(LogPathError, match="日志路径不可写"):
            EventWriter(str(directory / "events.jsonl"), 64)
    finally:
        directory.chmod(0o700)
