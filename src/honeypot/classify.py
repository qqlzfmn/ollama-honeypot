"""攻击分类。v0.1 只用静态规则，规则表随观测结果扩充。"""

from __future__ import annotations

import re

TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e)", re.IGNORECASE)
PAYLOAD = re.compile(
    r"(xmrig|/bin/sh|/bin/bash|base64\s+-d|curl\s+https?://|wget\s+https?://"
    r"|chmod\s+\+x|nc\s+-e|/dev/tcp/|mkfifo|ld\.so\.preload)",
    re.IGNORECASE,
)
REGISTRY = re.compile(r"[\w.-]+:\d{2,5}/", re.IGNORECASE)

MODEL_WRITE_PATHS = ("/api/pull", "/api/create", "/api/push", "/api/blobs/", "/api/copy")
CHAT_PATHS = ("/api/chat", "/api/generate", "/api/embed", "/v1/chat/completions", "/v1/completions")
SCANNER_PATHS = (
    "/.env",
    "/.git/",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/actuator",
    "/cgi-bin",
    "/vendor/phpunit",
    "/solr/",
    "/druid/",
)


def classify(path: str, body: str) -> str:
    """按「越具体越优先」的顺序给请求贴一个标签。"""
    probe = f"{path}\n{body}"
    if "/api/create" in path and ".safetensors" in body:
        return "safetensors_link_abuse"
    if PAYLOAD.search(probe):
        return "payload_drop"
    if TRAVERSAL.search(probe):
        return "path_traversal"
    if "/api/blobs/" in path:
        return "blob_upload"
    if "/api/pull" in path and REGISTRY.search(body):
        return "third_party_registry_pull"
    if any(prefix in path for prefix in MODEL_WRITE_PATHS):
        return "model_write"
    if any(prefix in path for prefix in CHAT_PATHS):
        return "llm_use"
    if any(prefix in path for prefix in SCANNER_PATHS):
        return "generic_scanner"
    return "other"
