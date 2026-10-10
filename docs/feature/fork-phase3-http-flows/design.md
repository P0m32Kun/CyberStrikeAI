# Fork Phase 3 首刀 · HTTP 流量共享库 · 设计

对齐 `CyberStrikeAI-二开计划.md` §6.2/§6.3 与 §0 已锁定决策 D12。分支：`P0m32Kun/phase-3-http-flows`（基线 main=4584aaa2）。

## 目标

平台具备通用 HTTP 流量存储/检索能力：Burp/浏览器插件同步（Phase 3 另票）、手动导入的流量进入统一流量库，人与 agent 在同一批流量上检索、标注与引用。本票只做后端（库 + REST API + agent 工具），无任何攻击/扫描语义。

## 设计六条（对齐计划 §6.2，干净重写）

1. **独立子系统、独立库**：`internal/traffic/` 自成包；`data/traffic/index.sqlite`（索引）+ `data/traffic/blobs/`（内容寻址 blob 树），不进主业务库，可整体删除不伤主库。库默认启用，无开关。
2. **元数据/正文分离**：`http_flows` 表只存元数据（ts/method/url/url_template/host/status/content_type/req_len/resp_len/path/project_id/source/tags/content_hash）；`http_flow_bodies` 表存头部与小正文。正文 ≤256KB inline，超出溢出 blob，inline 保留 8KB 预览（识别 JSON/SQL/ZIP 形态无需取回全文）。
3. **内容寻址去重**：blob 文件名 = 正文 sha256（两级分片 `blobs/<hash[0:2]>/<hash>`），`blob_refs` 表记录 hash↔flow 引用；同一正文多处出现只存一份。同项目内整条流量按 `content_hash`（method+url+req+status+resp 的 sha256，**不含 ts**）去重，重复导入只计 `duplicates`。
4. **FTS5 trigram 全文索引**：`http_flow_fts` 表单独应用（`CREATE VIRTUAL TABLE ... USING fts5(text, tokenize='trigram')`，带内容副本以支持直接删除）；驱动不含 FTS5 时记日志降级为仅元数据 LIKE 搜索（url/host/url_template/content_type），不 panic。`run.sh` 构建加 `-tags "sqlite_fts5"`；不带 tag 也能编译运行。词长 <3 rune（trigram 最短匹配）自动走 LIKE。
5. **URL 模板化**：导入时剥 query 归一 `url_template`（`/p?x=1 → /p`），`(host, url_template)` 聚合索引，另建 `host`、`ts`、`status`、`project_id` 单列索引。
6. **项目适配**：索引带 `project_id` 列；查询/清理按项目过滤；对话绑定项目时 agent 工具的项目范围是服务端强制边界（沿用资产工具模式）。

## REST API（固定合同，前端并行开发）

```
POST /api/http-flows                      批量导入 {"imported","duplicates","errors"}
GET  /api/http-flows?project_id=&q=&host=&method=&status=&tag=&limit=50&offset=0
                                          {"total","items":[...]}
GET  /api/http-flows/{id}                 详情（四字段各 ≤8KB 预览 + body_truncated）
POST /api/http-flows/{id}/tags            {"tags":[...]} → {"ok":true}
DELETE /api/http-flows?project_id=...     {"deleted":N}
```

鉴权复用 `/api/*` 的 JWT/session 中间件（`protected` 路由组）。导入校验：flows 1-1000 条、source ∈ {burp,browser,manual}（默认 manual）、project_id 非空时须为已存在项目。

## Agent 工具（内置注册）

| 工具 | 参数 | 权限 |
|------|------|------|
| `query_http_flows` | project_id/q/host/limit/offset | `httpflow:read` |
| `get_http_flow` | id | `httpflow:read` |
| `tag_http_flow` | id/tags | `httpflow:write` |
| `start_chat_from_flow` | id | `httpflow:read` |

`start_chat_from_flow` 输出与 Burp 插件 `HttpMessageFormatter.toPrompt` 兼容的分节形态（`[Target]`/`[Request]`/`[Optional: Response (truncated)]`，附 `[Meta]` 元信息），正文截断 4KB 保护上下文。工具经 `vulnerabilityRegistrar` 注册，ApplyConfig 清空工具后自动重注册。

新增平台权限 `httpflow:read` / `httpflow:write` / `httpflow:delete`（`internal/security/rbac.go` PermissionCatalog）；系统角色播种规则自动授给 admin，`:read` 授给 operator/auditor/viewer，`:write`/`:delete` 授给 operator。REST 路由经 `permissionForRequest` 按 `crudPermission(method, "httpflow")` 强制执行（fork phase 1 治理：protected 路由必须映射目录内权限，`route_inventory_test.go` 校验）。

## 关键取舍

- **去重键不含 ts**：重复同步（插件重发同一历史流量）时间戳常不同，含 ts 会导致去重失效；状态参与哈希（同请求 200/500 是不同事实）。
- **FTS 表带内容副本**（非 contentless）：按项目清理时 `DELETE FROM http_flow_fts WHERE rowid IN (...)` 直接可删，无需按 contentless_delete 协议回放原文；代价是索引体积近似翻倍，单条正文入索引上限 4MB。
- **Get 详情只回 8KB 预览**：blob 全文当前无消费方（API 合同如此）；未来需要全文时按 hash 读 blob 即可。
- **blob 写盘非事务**：事务回滚可能留下孤儿 blob 文件，只影响磁盘占用不影响正确性。清理 API（DeleteProject）只回收**本次删除流量的候选哈希中**已无引用的 blob，不会自动回收事务回滚留下的孤儿文件。
- **FTS 漂移边界（已知，回填留后续票）**：降级期（FTS 不可用构建）导入的行不进全文索引，之后切回带 tag 构建这些行查不到（`q` 全文命中缺失；元数据过滤不受影响）。回填思路：启动时对 `http_flows` 中 `rowid NOT IN (SELECT rowid FROM http_flow_fts)` 的行重建索引文本并补插（正文预览来自 inline 列，溢出正文取 8KB 预览粒度）；另 FTS 单行插入失败仅 warn 不阻断导入，同样落入此漂移面。
- **Target 外必要偏离（已追认）**：`internal/security/rbac.go`（新增 3 个权限）与 `internal/security/rbac_middleware.go`（路由权限映射）不在任务书 Target 列表内，但 fork phase 1 治理测试（TestEveryProtectedRouteHasCatalogPermission）强制每个 protected 路由映射目录权限，属必要偏离，协调者已追认。
- **流量数据不做用户行级隔离**：与资产库不同，首刀仅项目维度过滤；对话绑定项目时工具侧强制项目边界。
- **二进制正文**：API 合同的正文是字符串，二进制（图片/压缩包）以文本形态入库会有损，首刀接受，后续票可加 base64 字段。

## 涉及路径

- 新建 `internal/traffic/`（store.go/helpers.go + 测试）
- 新建 `internal/handler/http_flow.go`（+ 测试）
- 新建 `internal/app/traffic_tools.go`（+ 测试）
- `internal/app/app.go`（接线：Open/路由/registrar/Shutdown）
- `internal/mcp/builtin/constants.go`（4 个工具常量）
- `internal/security/rbac.go`（2 个权限）
- `internal/app/mcp_authorization.go`（工具授权策略）
- `run.sh`（构建 tag）
- `docs/zh-CN/http-flows.md`
