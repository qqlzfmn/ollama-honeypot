"""HTTP 入口：读取、分类、记录、回包。所有外部输入都视为不可信。"""

from __future__ import annotations

import socketserver
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .classify import classify
from .config import Config
from .events import EventWriter, sanitize
from .routes import Response, route

MAX_HEADERS_RECORDED = 32
MAX_REMOTE_FIELD_CHARS = 256


class HoneypotHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # 单连接读超时，避免慢速连接长期占用线程
    timeout = 15

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    # 事件走结构化日志，屏蔽默认的文本访问日志
    def log_message(self, format: str, *args: object) -> None:
        return

    def send_response(self, code: int, message: str | None = None) -> None:
        # 与 Go net/http 一致：只发 Date，不发 Server
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _handle(self) -> None:
        try:
            self._dispatch()
        except Exception as exc:  # 单个畸形请求不允许拖垮蜜罐
            self._record_internal_error(exc)
            self._respond(Response(500, "text/plain; charset=utf-8", b"internal error\n"))

    def _dispatch(self) -> None:
        config: Config = self.server.config  # type: ignore[attr-defined]
        raw_path, _, query = self.path.partition("?")
        path = urllib.parse.unquote(raw_path)
        body, truncated = self._read_body(config)
        response = route(self.command, path, config.ollama_version)
        self._record(config, path, query, body, response)
        self._respond(response, truncated)

    def _read_body(self, config: Config) -> tuple[bytes, bool]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return b"", True
        if length <= 0:
            return b"", False
        body = self.rfile.read(min(length, config.max_body_bytes))
        return body, length > config.max_body_bytes

    def _respond(self, response: Response, truncated: bool = False) -> None:
        try:
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            if truncated:
                # 请求体没读完，连接状态已不可用
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response.body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _record(self, config: Config, path: str, query: str, body: bytes, response: Response) -> None:
        writer: EventWriter = self.server.writer  # type: ignore[attr-defined]
        limit = writer.max_field_chars
        text = body.decode("utf-8", errors="replace")
        headers = {name: sanitize(value, limit) for name, value in list(self.headers.items())[:MAX_HEADERS_RECORDED]}
        writer.write(
            {
                "remote_ip": sanitize(self.client_address[0], MAX_REMOTE_FIELD_CHARS),
                "remote_port": self.client_address[1],
                "method": self.command,
                "path": sanitize(path, limit),
                "query": sanitize(query, limit),
                "host": sanitize(self.headers.get("Host", ""), MAX_REMOTE_FIELD_CHARS),
                "user_agent": sanitize(self.headers.get("User-Agent", ""), limit),
                "forwarded_for": sanitize(self.headers.get("X-Forwarded-For", ""), MAX_REMOTE_FIELD_CHARS),
                "headers": headers,
                "body_bytes": len(body),
                "body": sanitize(text, limit),
                "status": response.status,
                "category": classify(path, text),
            }
        )

    def _record_internal_error(self, exc: Exception) -> None:
        writer: EventWriter | None = getattr(self.server, "writer", None)
        limit = writer.max_field_chars if writer else MAX_REMOTE_FIELD_CHARS
        record = {
            "remote_ip": sanitize(self.client_address[0], MAX_REMOTE_FIELD_CHARS),
            "method": getattr(self, "command", "-"),
            "path": sanitize(getattr(self, "path", "-"), limit),
            "category": "internal_error",
            "error": sanitize(f"{type(exc).__name__}: {exc}", limit),
        }
        try:
            if writer is None:
                raise RuntimeError("事件写入器未初始化")
            writer.write(record)
        except Exception as log_exc:  # 记录失败也不能再抛，否则请求线程直接崩掉
            print(f"[honeypot] 事件未能落盘（{log_exc}）：{record}", flush=True)


class HoneypotServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: Config, writer: EventWriter) -> None:
        self.config = config
        self.writer = writer
        super().__init__((config.host, config.port), HoneypotHandler)


def serve(config: Config) -> socketserver.BaseServer:
    """启动蜜罐并阻塞。返回 server 便于测试关闭。"""
    server = HoneypotServer(config, EventWriter(config.log_path, config.max_field_chars))
    print(
        f"honeypot listening on {config.host}:{config.port} "
        f"(version={config.ollama_version}, log={config.log_path})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("honeypot stopping", flush=True)
    finally:
        server.server_close()
    return server
