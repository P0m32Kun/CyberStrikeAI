# Fork Phase 2 nmap → 资产自动入库 · 实施与验证

设计见 [design.md](design.md)。分支 `P0m32Kun/phase-2-nmap-ingest`（基线 main=4584aaa2）。

## 实施步骤（TDD：每步先写失败测试再实现）

| # | 步骤 | 涉及文件 | 状态 |
|---|------|---------|------|
| 1 | `IngressParser` 接口 + nmap 解析器（fixture → 期望资产列表） | `internal/ingest/ingress.go`、`internal/ingest/nmap/parser.go`、`parser_test.go` | 完成 |
| 2 | 挂载点 A：`ToolSuccessHook` + nmap 自动 `-oX` 临时文件 + 成功触发/失败不触发/临时文件删除 | `internal/security/executor.go`、`executor_nmap_xml_test.go` | 完成 |
| 3 | 挂载点 A 接线：项目绑定（ctx → 对话）、无项目不写库、审计日志、重复扫描去重 | `internal/app/nmap_ingest.go`、`nmap_ingest_test.go` | 完成 |
| 4 | 挂载点 B：内置工具 `ingest_nmap_xml`（xml_content/xml_file + project_id）、授权 case（asset:write + project 访问）、常量注册 | `internal/app/nmap_ingest.go`、`internal/mcp/builtin/constants.go`、`internal/app/mcp_authorization.go` | 完成 |
| 5 | app 装配：executor 挂 hook + 双注册点（启动 + 配置重载 registrar） | `internal/app/app.go` | 完成 |
| 6 | 配方与角色：nmap.yaml 行为说明、信息收集-最小 白名单追加 | `tools/nmap.yaml`、`roles/信息收集-最小.yaml` | 完成 |
| 7 | 文档：资产页「扫描自动入库（nmap）」小节、Agent 工具列表 6→7 | `docs/zh-CN/asset-management.md` | 完成 |

## 验证记录（2026-10-10，worktree P0m32Kun/phase-2-nmap-ingest）

### go test ./...

- 结果：**35 包全部 `ok`，0 失败，exit 0**（输出摘要：`ok cyberstrike-ai/internal/ingest/nmap`、`ok cyberstrike-ai/internal/security`、`ok cyberstrike-ai/internal/app` 等）。
- `go vet ./internal/...` 无告警；`go build ./...` 通过。
- **2026-10-10 修复轮**（tester 路径穿越探针 → `xml_file` 白名单）：`go test ./...` 复跑 35 包全绿；新增测试点 14 见下。
- **2026-10-10 二轮修复轮**（reviewer「修后合」：应修 1 项目内去重 + 应修 2 allowGlobal 透传 + nit 3-7）：改动 `internal/database/asset.go`（`UpsertAssets` 抽共享主体 `upsertAssets`，新增 `UpsertAssetsInProject` 项目限定变体：去重键追加 `|<projectID>` 段，不改表、不动 create_asset）、`internal/app/nmap_ingest.go`（两挂载点改走项目限定 upsert、挂载 B 透传 allowGlobal、xml_content/xml_file 同时提供报错、`filepath.EvalSymlinks` 解析后复检 + root 同尺度归一）、文档口径同步（design.md 决策 8/9、hostname 任意 type、asset-management.md 去重四元键）。新增测试点 15-19 见下。

### 新增测试点（18 个 + 1 处 flaky 修复）

解析器（`internal/ingest/nmap/parser_test.go`）：
1. `TestParseFixtureToAssets` — fixture XML → 期望资产列表（IP/Host/端口/协议/指纹/Title/Source/SourceQuery/Tags 独立字面量断言；closed 与 open|filtered 端口、ipv6 主机、PTR 主机名覆盖）
2. `TestParseRejectsInvalidXML` — 非法 XML 报错
3. `TestParseEmptyRunYieldsNoAssets` — 空扫描 0 资产不报错
4. `TestParseTruncatesOverlongFields` — 超长 Title 截断到校验上限内

挂载点 A·执行器（`internal/security/executor_nmap_xml_test.go`，假 nmap 脚本 + fixture XML，不对真实目标扫描）：
5. `TestExecuteToolNmapSuccessInvokesHookWithXML` — 成功触发回调、回调内可读 XML、结果文本追加入库提示、临时文件已删除
6. `TestExecuteToolNmapFailureSkipsHook` — 退出码 1 不触发
7. `TestExecuteToolNonNmapDoesNotInvokeHook` — 非 nmap 工具不注入 -oX 不触发

挂载点 A·接线（`internal/app/nmap_ingest_test.go`）：
8. `TestNmapAutoIngestHookWritesProjectBoundAssets` — 项目绑定正确、Source=nmap、审计日志 1 条（`nmap_auto_ingest`/project）、重复扫描只更新不重复（2→2）
9. `TestNmapAutoIngestHookSkipsWithoutProject` — 无项目不写库并返回跳过提示
10. `TestNmapAutoIngestHookIgnoresOtherTools` — 非 nmap 工具忽略

挂载点 B（`internal/app/nmap_ingest_test.go`）：
11. `TestIngestNmapXMLToolRegisteredAndCallable` — 注册成功；xml_content+project_id 与 xml_file+对话隐式项目两条路径均可入库；重复导入去重；缺参数/非法 XML 报错
12. `TestIngestNmapXMLToolRequiresProject` — 无项目可解析时拒绝且不写库
13. `TestIngestNmapXMLToolRequiresAssetWritePermission` — 缺 `asset:write` 被授权器拦截
14. `TestIngestNmapXMLToolFilePathWhitelist` — `xml_file` 路径白名单（tester 路径穿越探针后补）：临时目录内合法路径可导入（2 资产）；`/etc/passwd`、`/root/...` 绝对路径被拒且错误说明约束不回显内容；含 `..` 段路径拒绝；`<临时目录>-evil` 同前缀路径不绕过（`filepath.Rel` 判定）；二轮补：临时目录内符号链接指向外部实体文件被拒（EvalSymlinks 解析后复检）、指向临时目录内文件放行
15. `TestUpsertAssetsInProjectScopedDedup`（database 包）— 项目限定 upsert：同项目重复更新不新增；跨项目同键各存一行且 project/owner 绑定不漂移；全局 `UpsertAssets` 键空间互不命中；空 projectID 拒绝
16. `TestNmapAutoIngestCrossProjectIsolation` — 挂载 A：项目 A 入库后项目 B 再入库同 XML 各 2 行不迁移；同项目重复扫描仍去重
17. `TestIngestNmapXMLToolGlobalScopeUpdatesForeignRow` — 挂载 B：全局 scope 更新他人 owner 同键行 + 新建缺失行；assigned scope 面对他人行仍跳过（既有语义保持）
18. `TestIngestNmapXMLToolRejectsBothInputs` — `xml_content` 与 `xml_file` 同时提供报错（不静默忽略）
19. 测试 15 的 flaky 修复（coordinator 抽检发现单跑可挂）：断言原按 `ORDER BY project_id`（uuid 随机串）行序硬编码 p1 在前，约 50% 概率反序误报——改为 map[projectID]owner 无序断言 + `WHERE project_id IN (...)` 显式过滤本测试行；修复后单测 -count=1 连跑 10 次、整包、全量三种跑法全绿

### 前端（D10 门禁）

`node --test web/static/js/*.test.cjs`：**292 测试，291 过 / 1 失败**。失败项 `hitl-approval-ui.test.cjs:105`（断言 Go 源码含 `ADD COLUMN reviewer ...` 迁移语句）经 `git stash` 基线复跑确认为**存量失败，与本次改动无关**（本 Phase 未触碰 web/ 与 handler/hitl）。

### 未自动化项（留人工验收）

- §5.4「对本地 lab 靶机跑一次 nmap，资产页出现对应 host:port 行」——约束禁止对真实目标发扫描，已用假 nmap 脚本集成测试等价覆盖执行链；上线后按文档小节人工验证一次。
- 「tool_executions 仍有完整原始 stdout」——executor 未改动输出收集路径，stdout 行为不变（由既有机制保证）。

## 遗留与偏差

1. `IngressParser` 接口放在 `internal/ingest/`（父包）而非 `internal/ingest/nmap/` 内——中性位置便于后续 masscan/httpx 接入，见 design.md 决策 5。
2. en-US 版 `docs/en-US/asset-management.md` 未同步（任务书 Target 仅列 zh-CN；英文版同步建议随发布记录一起做）。
3. 前端存量失败 1 例（hitl-approval-ui），建议单开修复票。
4. nmap `allowed_exit_codes` 路径（非零退出码白名单）不触发自动入库：本 Phase 仅在 exit 0 成功块挂回调；nmap 配方未配置该字段，如后续配置需评估是否纳入。
5. `cmd/mcp-stdio`（独立 stdio MCP 服务）未挂自动入库 hook：该模式无数据库与会话上下文，无从解析项目绑定；未挂 hook 时 Executor 不追加 `-oX`，stdio 行为与原先完全一致。
