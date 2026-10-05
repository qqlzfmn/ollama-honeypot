"""进程入口：python -m honeypot"""

from __future__ import annotations

from .config import Config
from .server import serve


def main() -> None:
    serve(Config.from_env())


if __name__ == "__main__":
    main()
