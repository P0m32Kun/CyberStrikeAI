# HTTP 流量库

HTTP 流量库把 Burp Suite、浏览器插件同步或手动导入的 HTTP 请求/响应统一存档，让人与 Agent 在同一批流量上检索、标注和引用。它是通用的流量存储/检索设施，本身不包含任何攻击或扫描语义。

> 仅对自有系统或已获得明确授权的目标采集与共享流量。

## 功能概览

- **批量导入**：一次最多 1000 条；同项目内内容完全相同的流量自动去重（按方法、URL、状态码、请求/响应头与正文的哈希判定，时间戳不参与），重复导入只计数不翻倍。
- **检索**：按项目、host、方法、状态码、标签过滤；`q` 关键字搜索（构建启用 FTS5 时为全文搜索，含请求/响应正文；否则自动降级为 URL/host/Content-Type 等元数据匹配）。
- **详情预览**：单条流量返回请求/响应头与正文的预览（各截断至 8KB，`body_truncated` 标记是否截断）；超过 256KB 的正文溢出到内容寻址 blob 文件，同内容只存一份。
- **标签**：给重点流量打标签（如 `auth-bypass`、`retest`），列表可按标签过滤。
- **按项目清理**：删除某项目下全部流量并回收不再被引用的存储。

流量库默认启用，数据落在本仓库 `data/traffic/`（`index.sqlite` 索引 + `blobs/` 内容寻址文件树），与主业务库分离，可整体删除不影响其他数据。

## REST API

鉴权与平台其他 `/api/*` 接口一致（登录后的 JWT/session），并按 RBAC 权限执行：检索/详情需 `httpflow:read`，导入/标签需 `httpflow:write`，按项目清理需 `httpflow:delete`（admin 与 operator 默认具备，viewer/auditor 只读）。

### 批量导入

```
POST /api/http-flows
{
  "project_id": "proj-xxx",            // 可空；为空时进入全局范围
  "source": "burp",                    // burp | browser | manual，缺省 manual
  "flows": [
    {
      "ts": 1697000000000,             // 毫秒时间戳
      "method": "GET",
      "url": "https://host/path?x=1",
      "status": 200,
      "content_type": "text/html",
      "req_headers": "GET /path?x=1 HTTP/1.1\r\nHost: host",
      "req_body": "",
      "resp_headers": "HTTP/1.1 200 OK\r\n...",
      "resp_body": "<html>...</html>"
    }
  ]
}
→ {"imported": 2, "duplicates": 1, "errors": []}
```

- `project_id` 非空时必须是已存在的项目，否则 400。
- 导入时自动归一 `host`（小写、不含端口）与 `url_template`（剥 query，如 `/path?x=1 → /path`）。

### 检索列表

```
GET /api/http-flows?project_id=&q=&host=&method=&status=&tag=&limit=50&offset=0
→ {"total": 12, "items": [{"id","ts","method","url","url_template","host","status",
    "content_type","req_len","resp_len","tags":[],"source","project_id"}]}
```

按时间倒序；`limit` 默认 50、上限 200。

### 单条详情

```
GET /api/http-flows/{id}
→ 列表字段 + {"req_headers","req_body","resp_headers","resp_body","body_truncated"}
```

四个内容字段各截断至 8KB 预览；任一字段被截断时 `body_truncated` 为 `true`。

### 更新标签

```
POST /api/http-flows/{id}/tags
{"tags": ["auth-bypass", "retest"]}
→ {"ok": true}
```

整体替换标签集合，最多 50 个、单个最长 100 字符。

### 按项目清理

```
DELETE /api/http-flows?project_id=proj-xxx
→ {"deleted": 5}
```

删除该项目下全部流量，并回收不再被任何流量引用的 blob 文件。此操作不可恢复。

## Agent 工具

对话中的 Agent 可用以下内置工具访问流量库（权限分别为 `httpflow:read` / `httpflow:write`，系统角色 admin/operator/auditor/viewer 已按只读或读写预授权）：

| 工具 | 用途 |
|------|------|
| `query_http_flows` | 按 project_id / q / host 分页检索流量摘要 |
| `get_http_flow` | 按 ID 查看单条流量详情（字段截断保护上下文） |
| `tag_http_flow` | 给流量打标签 |
| `start_chat_from_flow` | 把一条流量格式化为可引用的请求/响应文本（与 Burp 插件「Send to Agent」输出形态兼容），在对话中针对该流量继续分析 |

对话绑定项目时，Agent 只能看到该项目的流量；显式传入其他项目 ID 也会被服务端项目边界覆盖。

## 全文搜索与构建说明

流量库的 `q` 搜索依赖 SQLite FTS5（trigram 分词，支持任意子串与中文）。本平台使用的 `mattn/go-sqlite3` 驱动默认构建不含 FTS5：

- 官方 `run.sh` 构建已携带 `-tags "sqlite_fts5"`，开箱即有全文搜索；平台「系统更新」自更新重建二进制时同样带该 tag，升级不会丢失全文检索。
- 自行构建（`go build ./cmd/server`）不带该 tag 时功能正常，`q` 自动降级为元数据匹配（URL/host/Content-Type），启动日志会出现降级提示。
- trigram 最短匹配 3 个字符，更短的关键字自动走元数据匹配。

## 数据布局与清理

```
data/traffic/
├── index.sqlite      # 索引库（元数据 + 正文 inline + blob 引用表）
└── blobs/            # 内容寻址 blob（sha256 前两位分片目录）
```

- 正文 ≤256KB 直接存索引库；超出溢出到 `blobs/`，同内容（同 sha256）只存一份。
- 单条流量无全局大小上限；按项目清理（`DELETE /api/http-flows?project_id=...`）会同步删除索引行、全文索引行并回收无引用 blob。
- 需要彻底重置流量库时，停止平台后删除 `data/traffic/` 目录即可，不影响主业务库。
