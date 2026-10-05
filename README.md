# ollama-honeypot

一个低交互蜜罐，监听 11434，用来记录全网针对 Ollama 的探测与利用行为。

背景：暴露在公网的 Ollama 没有认证。已观测到的真实攻击链是
`POST /api/blobs/:digest` 上传载荷 → `POST /api/create` 借助未净化的文件名写入符号链接 →
下一次加载模型时动态链接器加载攻击者的 `libm.so.6`，以 root 执行。
本项目只记录这些请求，不复现任何行为。

## 安全模型

蜜罐本身是攻击目标，所以按「假定会被打」设计。

| 措施 | 说明 |
|---|---|
| 不解析、不执行 | 请求体只做字符串匹配与截断，不反序列化后使用，不写文件，不建连接 |
| 非 root | 容器内以 UID 10001 运行 |
| 只读根文件系统 | `read_only: true`，仅 `./data` 可写 |
| 丢弃全部能力 | `cap_drop: [ALL]`、`no-new-privileges` |
| 资源上限 | `mem_limit: 256m`、`pids_limit: 128`、请求体上限 256 KiB、单连接读超时 |
| 无出站 | 不请求外部地址，不回调，不做反向代理 |
| 日志注入防护 | 所有不可信文本去除控制字符后写入 JSONL，长度截断 |

## 快速开始

容器以 UID 10001 运行，`./data` 必须归属该用户，否则启动就会报错退出：

```bash
mkdir -p data && sudo chown -R 10001:10001 data
docker compose up -d --build
docker compose logs -f honeypot
python3 scripts/report.py data/events.jsonl
```

若不想改属主，就让容器用户对齐你自己：

```bash
HONEYPOT_UID=$(id -u) HONEYPOT_GID=$(id -g) docker compose up -d
```

本机试跑（不需要容器）：

```bash
PYTHONPATH=src HONEYPOT_LOG_PATH=./data/events.jsonl python3 -m honeypot
curl -s localhost:11434/api/version
```

测试：

```bash
uv run pytest
```

## 事件格式

`data/events.jsonl`，一行一个 JSON 对象。

```json
{
  "ts": "2026-10-06T01:02:03+0800",
  "remote_ip": "203.0.113.7",
  "remote_port": 51234,
  "method": "POST",
  "path": "/api/create",
  "query": "",
  "host": "203.0.113.7:11434",
  "user_agent": "curl/8.5.0",
  "forwarded_for": "",
  "headers": {"Content-Type": "application/json"},
  "body_bytes": 128,
  "body": "{\"files\":{\"../../usr/lib/ollama/libm.so.6.safetensors\":\"sha256:...\"}}",
  "status": 200,
  "category": "safetensors_link_abuse"
}
```

`X-Forwarded-For` 单独存字段，不与真实来源混淆。

## 分类

| 分类 | 触发条件 |
|---|---|
| `safetensors_link_abuse` | `/api/create` 且请求体含 `.safetensors` |
| `payload_drop` | 出现 `xmrig`、`curl http`、`chmod +x`、`ld.so.preload` 等 |
| `path_traversal` | 路径或请求体含 `../`、`%2e%2e` |
| `blob_upload` | `/api/blobs/` |
| `third_party_registry_pull` | `/api/pull` 且目标含 `host:port` |
| `model_write` | 其余 `/api/pull`、`/api/push`、`/api/create`、`/api/copy` |
| `llm_use` | `/api/chat`、`/api/generate`、`/v1/chat/completions` |
| `generic_scanner` | `/.env`、`/wp-admin`、`/actuator` 等通用扫描路径 |
| `other` | 其余 |

## 响应策略

- `GET /` 返回 `Ollama is running`
- `GET /api/version` 返回可配置的版本号（默认 `0.5.7`，用于吸引针对旧版本的利用）
- 未拉取过模型时，`/api/chat`、`/api/generate` 返回 404 `model not found`
  —— 把攻击者推向 `/api/pull`，那是最有观测价值的流量
- 未匹配的路径返回 `404 page not found`，与 Go `net/http` 的默认行为一致

## 路线图

一次只加一件事，每项都要求可观测、可验证。

- [x] v0.1 最小可用：伪造 API、JSONL 事件、分类、统计脚本、容器安全基线
- [ ] 给 `/api/pull` 返回逐行流式进度，观察攻击者是否等待完成
- [ ] 记录 TCP/TLS 层特征（JA4 之类），区分扫描器与人工利用
- [ ] 会话聚合：把同一来源的连续请求合成一次「攻击事件」
- [ ] 每日汇总与告警导出（Prometheus 指标或 Webhook）

## 许可

尚未选择许可证，开源前需要确定。
