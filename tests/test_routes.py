import json

from honeypot.routes import route


def test_root_reports_running() -> None:
    assert route("GET", "/", "0.5.7").body == b"Ollama is running"


def test_version_matches_advertised() -> None:
    response = route("GET", "/api/version", "0.5.7")
    assert json.loads(response.body) == {"version": "0.5.7"}


def test_unknown_path_is_not_found() -> None:
    assert route("GET", "/nope", "0.5.7").status == 404


def test_blob_head_is_missing_and_post_is_accepted() -> None:
    assert route("HEAD", "/api/blobs/sha256-aa", "0.5.7").status == 404
    assert route("POST", "/api/blobs/sha256-aa", "0.5.7").status == 201


def test_pull_and_create_report_success() -> None:
    assert route("POST", "/api/pull", "0.5.7").status == 200
    assert route("POST", "/api/create", "0.5.7").status == 200


def test_chat_without_model_is_not_found() -> None:
    assert route("POST", "/api/chat", "0.5.7").status == 404
