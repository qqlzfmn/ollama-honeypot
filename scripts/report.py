#!/usr/bin/env python3
"""汇总蜜罐事件：按分类、来源、路径、User-Agent 统计。"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

TOP_N = 10
FIELDS = (("攻击分类", "category"), ("来源 IP", "remote_ip"), ("请求路径", "path"), ("User-Agent", "user_agent"))


def load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="汇总 Ollama 蜜罐事件")
    parser.add_argument("path", nargs="?", default="data/events.jsonl", help="事件日志路径")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.is_file():
        raise SystemExit(f"日志不存在：{path}")

    events = load_events(path)
    print(f"文件        : {path}")
    print(f"事件总数    : {len(events)}")
    if not events:
        return
    print(f"时间范围    : {events[0].get('ts')} → {events[-1].get('ts')}")
    print(f"独立来源 IP : {len({event.get('remote_ip') for event in events})}")

    for title, field in FIELDS:
        counter = Counter(str(event.get(field, "")) for event in events)
        print(f"\n== {title} top{TOP_N} ==")
        for name, count in counter.most_common(TOP_N):
            print(f"{count:>8}  {name}")


if __name__ == "__main__":
    main()
