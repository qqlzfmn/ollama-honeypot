"""进程入口：python -m honeypot"""

from __future__ import annotations

from .config import Config
from .events import LogPathError
from .server import serve


def main() -> None:
    try:
        serve(Config.from_env())
    except (ValueError, LogPathError) as exc:
        raise SystemExit(f"启动失败：{exc}") from exc


if __name__ == "__main__":
    main()
