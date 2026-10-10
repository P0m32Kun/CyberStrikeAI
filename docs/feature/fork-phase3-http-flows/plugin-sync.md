# Phase 3 首刀·插件同步实现记录（Burp + 浏览器扩展 → HTTP History）

> 分支：`P0m32Kun/phase-3-http-flows`（本 worktree）。后端 `POST /api/http-flows` 由同分支前一刀实现，本文只覆盖插件侧。

## 目标

两个官方插件在既有「送测 Agent」路径之外，各增加一条把流量批量送入共享 HTTP 流量库的通道：

- Burp 扩展：右键多选 → **Send to CyberStrikeAI History**（source=burp）
- 浏览器扩展：DevTools 面板 **Sync History** 按钮（source=browser）

## 合同（与 `internal/handler/http_flow.go` / `internal/traffic/store.go` 对照）

- `POST /api/http-flows`，鉴权与其余 `/api/*` 一致：`Authorization: Bearer <token>`（两端均复用插件现有 login→token 链路）
- 请求体顶层：`project_id`（可空=全局）、`source`（burp|browser）、`flows[]`（1–1000 条）
- `flows[]` 字段：`ts`（毫秒）、`method`、`url`、`status`、`content_type`、`req_headers`、`req_body`、`resp_headers`、`resp_body`
- 成功 `{"imported":N,"duplicates":N,"errors":[...]}`；失败 `{"error":"..."}`（如「项目不存在」）→ 插件原样展示

## Burp 扩展改动（`plugins/burp-suite/cyberstrikeai-burp-extension/`）

| 文件 | 内容 |
|------|------|
| `SimpleJson.java` | 新增 `extractIntField`（读响应 imported/duplicates） |
| `CyberStrikeAIClient.java` | 新增 `FlowPayload`/`ImportSummary`/`MAX_FLOWS_PER_BATCH=1000`；`importHttpFlows`（POST，Bearer，60s 读超时，服务端 error 透出）；`flowFromMessage`（IHttpRequestResponse→FlowPayload）；`buildImportBody`（手写 JSON，字段序与合同一致） |
| `HistorySyncDialog.java`（新） | 确认弹窗：条数 + 项目下拉（复用 `fetchProjects`，默认选中与送测对话框共享的上次选择） |
| `SendOptionsDialog.java` | 暴露 `lastProjectId()`/`rememberProjectId()`，两对话框共享同一份项目记忆 |
| `BurpExtender.java` | 右键菜单新增第二项；多选组装、>1000 自动分批、后台线程同步、`AtomicBoolean` 防重入、结果/错误弹窗 |

关键取舍：

- **ts 取同步时刻**：Burp 旧 extender API（burp-extender-api 2.3）不暴露 Proxy history 条目时间戳，无法取真实请求时间；README 已注明。
- **不重构**：JSON 仍手写（仓库无 JSON 依赖），错误处理/超时/取消模式均照抄 `login`/`fetchProjects` 现有写法；body 按 ISO-8859-1 解码再 UTF-8 写出（byte→U+00XX 映射无损，与既有 `toPrompt` 路径一致）。
- **原「stream test」路径零改动**。

## 浏览器扩展改动（`plugins/browser-extension/cyberstrikeai-browser-extension/`，0.3.10→0.3.11）

| 文件 | 内容 |
|------|------|
| `lib/api.js` | 新增 `importHttpFlows(baseUrl, token, projectId, flows)`，走既有 `apiFetch`（错误即 `json.error`） |
| `lib/history-sync.js`（新） | 纯映射：`syncableEntries`（滤掉 PAGE 伪条目）+ `entryToFlow`（entry→合同字段；content_type 从响应头解析；ts 用 `capturedAt`） |
| `panel/panel.html` | 工具栏 **Sync History** 按钮 + `sync-dialog`（项目下拉复用 cs-select 组件） + 引入 history-sync.js |
| `panel/panel.js` | `openSyncDialog`/`onSyncConfirmed`；复用 `ensureAuthReady`/`fetchCatalogCached`/`config.lastProjectId`；防重入 `syncingHistory`；结果走 `setStatus` |
| `manifest.json` | 版本号 0.3.11 |

关键取舍：

- 同步对象为当前 Tab 捕获列表（≤200 条，远低于后端 1000 上限；仍有 `MAX_HISTORY_SYNC_BATCH` 兜底）；请求/响应体沿用捕获时截断（64KB/4KB），不重新抓全文。
- 项目选择与 Send 弹窗共享 `lastProjectId` 存储。
- 原有 Send/Latest XHR 路径零改动；popup（只读状态）不加功能，与既有分工一致。

## 构建产物

- Burp：`mvn package` → `target/cyberstrikeai-burp-extension-1.0.0.jar`，并同步 `dist/cyberstrikeai-burp-extension.jar`
- 浏览器扩展：`bash package.sh` → `dist/cyberstrikeai-browser-extension.zip`（含 0.3.11 全部改动）

## 验证（2026-10-10，全部本地、无真实外部目标）

1. **编译/语法**
   - `mvn package`：BUILD SUCCESS（本机需走镜像：`mvn -s /tmp/phase3-mvn-settings.xml package`，Maven Central 直连握手失败）
   - `node --check`：`lib/api.js`、`lib/history-sync.js`、`panel/panel.js` 全过；`manifest.json` JSON 合法
2. **Java 侧 mock**（`/tmp/phase3-plugin-verify/HistorySyncVerify.java`，未入仓）：JDK 内置 HttpServer 起 127.0.0.1 mock + 动态代理伪造 Burp API 对象，21 项断言全过——字段映射（含无响应条目、header 引号转义）、Bearer/Content-Type 头、响应计数解析、400 错误透出（「项目不存在」）、空批/超限防御、密码不进请求体
3. **JS 侧 mock**（`/tmp/phase3-plugin-verify/js-mock-test.js`）：stub fetch + `vm.createContext` 整文件加载，15 项断言全过——URL/方法/头、body 顶层结构、服务端错误透出、`entryToFlow` 映射、PAGE 过滤
4. **合同字段逐一对照**：脚本从 `internal/traffic/store.go` 的 `Flow` json tag 提取字段，与 Java `buildImportBody` 产物、JS `JSON.stringify` 产物的 `flows[]` 键分别 `deepStrictEqual` 比对，一致

## 遗留 / 未做

- 两个插件均无单测基建，验证走 /tmp 临时脚本（按任务书约定）；脚本未入仓，若后续建 CI 可将其改造成常驻测试
- Burp 侧 ts 为同步时刻（API 限制，见上）；浏览器扩展 ts 为捕获时刻（准确）
- 浏览器扩展同步的是当前 Tab 捕获列表，不含历史 Tab；如需跨 Tab 聚合需改 background 协议（未在本次范围）
