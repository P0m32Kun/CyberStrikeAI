# Fork Phase 3 首刀 · HTTP 流量共享库 · 实施记录

设计见同目录 `design.md`。实施顺序按 TDD（先失败测试后实现，每步两构建验证）。

## 步骤

1. **`internal/traffic` 库**（store_test.go → store.go/helpers.go）
   - Open：建目录、开 SQLite（WAL/busy_timeout/foreign_keys 走 DSN）、应用基础 schema、单独应用 FTS schema（失败记 warn 降级）
   - ImportFlows：单事务批量；`INSERT OR IGNORE` + RowsAffected 判重；大正文溢出 blob（exists-check 去重落盘）；FTS 可用时写入索引（rowid 关联）
   - Query：动态 where；q 走 FTS MATCH（短语引号包裹）或元数据 LIKE（ESCAPE 转义）；ts 倒序分页
   - Get：四字段 8KB rune 安全截断预览 + body_truncated（inline 超限或溢出均置位）
   - SetTags / DeleteProject（FTS 行同步删、blob 引用计数回收）
   - 测试覆盖：去重计数、跨项目不去重、url_template/host 归一、过滤分页、tags、预览截断、256KB 溢出与 blob 去重、按项目清理 + blob GC、FTS 降级（WithDisableFTS）、FTS 路径（无 tag 构建自动 skip）

2. **`internal/handler/http_flow.go`**
   - 5 端点映射库 API；导入校验（批量上限/source 枚举/项目存在）；错误映射（ErrNotFound→404）
   - 测试：401（真实 AuthMiddleware，五端点逐一）、导入-列表-详情-标签-清理全链、缺失项目 400、LIKE 检索

3. **agent 工具**（internal/app/traffic_tools.go）
   - 4 工具注册；对话项目边界复用 agentAssetProjectScope（显式传其他 project_id 被覆盖；跨项目 get/tag 拒绝）
   - builtin 常量 + IsBuiltinTool；mcpToolAuthorizer 授权策略（httpflow:read/write）；PermissionCatalog 新权限随系统角色播种自动生效
   - 测试：注册齐全、query/get/tag/chat 输出形态、项目边界

4. **接线**（internal/app/app.go）
   - New：`traffic.Open(<dbPath 目录>/traffic)`，失败启动即失败；FTS 降级时打 warn
   - 路由挂 protected 组；工具启动注册一次 + 进 vulnerabilityRegistrar（ApplyConfig 后重注册）
   - App 字段 + Shutdown 关闭连接

5. **构建链**：run.sh 两处 `go build` 加 `-tags "sqlite_fts5"`（316/377 行附近），注释说明降级行为；`bash -n` 校验。

## 验证

- `go test ./...`（不带 tag）全绿；`go test -tags "sqlite_fts5" ./...` 全绿
- 两构建 `go build ./...` 均通过
- API 5 端点 httptest 实测（含 401）见 `internal/handler/http_flow_test.go`

## 未完成 / 后续票

- 插件侧「Send to CyberStrikeAI History」同步（计划 §6.3-2，Phase 3 另票）
- Web UI 流量页（§6.3-5）
- Phase 3b MITM 记录代理（§6.4）
- 二进制正文 base64 通道、blob 全文读取 API（当前合同无消费方）
