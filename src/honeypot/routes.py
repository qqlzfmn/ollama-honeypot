"""伪造的 Ollama 响应。只回固定内容：不解析、不执行、不落盘、不回连。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

BLOB_PATH = re.compile(r"^/api/blobs/[A-Za-z0-9:_-]+$")

NOT_FOUND_BODY = b"404 page not found\n"
TEXT_PLAIN = "text/plain; charset=utf-8"
JSON = "application/json"


@dataclass(frozen=True)
class Response:
    status: int
    content_type: str
    body: bytes


def _json(status: int, payload: dict | list) -> Response:
    return Response(status, JSON, json.dumps(payload, ensure_ascii=False).encode())


def _text(status: int, body: str) -> Response:
    return Response(status, TEXT_PLAIN, body.encode())


def _model_missing() -> Response:
    """没有模型可聊，把攻击者推向 /api/pull —— 那才是我们要观测的流量。"""
    return _json(404, {"error": "model not found"})


def route(method: str, path: str, version: str) -> Response:
    if method == "GET":
        if path == "/":
            return _text(200, "Ollama is running")
        if path == "/api/version":
            return _json(200, {"version": version})
        if path in ("/api/tags", "/api/ps"):
            return _json(200, {"models": []})
        if path == "/v1/models":
            return _json(200, {"object": "list", "data": []})

    if BLOB_PATH.match(path):
        # 未上传过的 blob 就是不存在，HEAD 用于探测，写入则接受
        if method == "HEAD":
            return Response(404, TEXT_PLAIN, b"")
        if method in ("POST", "PUT"):
            return _json(201, {"status": "success"})

    if method == "POST":
        if path in ("/api/pull", "/api/push", "/api/create", "/api/delete", "/api/copy"):
            return _json(200, {"status": "success"})
        if path in ("/api/show", "/api/chat", "/api/generate", "/api/embed"):
            return _model_missing()
        if path in ("/v1/chat/completions", "/v1/completions"):
            return _json(404, {"error": {"message": "model not found", "type": "invalid_request_error"}})

    if method in ("DELETE",) and path == "/api/delete":
        return _json(200, {"status": "success"})

    return Response(404, TEXT_PLAIN, NOT_FOUND_BODY)
