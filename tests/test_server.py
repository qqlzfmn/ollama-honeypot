import http.client
import json
import threading
from pathlib import Path

import pytest

from honeypot.config import Config
from honeypot.events import EventWriter
from honeypot.server import HoneypotServer


@pytest.fixture()
def honeypot(tmp_path: Path):
    config = Config(
        host="127.0.0.1",
        port=0,
        ollama_version="0.5.7",
        log_path=str(tmp_path / "events.jsonl"),
        max_body_bytes=4096,
        max_field_chars=512,
        read_timeout_seconds=5,
    )
    server = HoneypotServer(config, EventWriter(config.log_path, config.max_field_chars))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, Path(config.log_path), tmp_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(server: HoneypotServer, method: str, path: str, body: bytes = b"") -> http.client.HTTPResponse:
    connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
    connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    response.read()
    connection.close()
    return response


def test_request_is_recorded_with_category(honeypot) -> None:
    server, log_path, _ = honeypot
    payload = {
        "model": "x",
        "files": {"../../../../usr/lib/ollama/libm.so.6.safetensors": "sha256:" + "a" * 64},
    }
    response = _request(server, "POST", "/api/create", json.dumps(payload).encode())

    assert response.status == 200
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    assert events[0]["category"] == "safetensors_link_abuse"
    assert events[0]["method"] == "POST"
    assert events[0]["body_bytes"] > 0


def test_only_the_log_file_is_written(honeypot) -> None:
    server, log_path, workdir = honeypot
    _request(server, "POST", "/api/blobs/sha256-" + "a" * 64, b"payload")

    assert sorted(p.name for p in workdir.iterdir()) == [log_path.name]


def test_control_characters_do_not_break_jsonl(honeypot) -> None:
    server, log_path, _ = honeypot
    _request(server, "POST", "/api/pull", b'{"name":"a\x00b\nc\r"}')

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["category"] == "model_write"
    assert "\x00" not in event["body"] and "\n" not in event["body"]
