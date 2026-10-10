# Fork Phase 1 治理默认收紧 · 实现计划

- Branch: `fork/phase-1-governance`（基线 main=deda642b）
- 输入：`CyberStrikeAI-二开计划.md` §4 / §0 D10-D11、`docs/feature/fork-phase1-governance/design.md`

## 任务分解

1. 三个治理绕过型工具默认关：`tools/exec.yaml`、`tools/execute-python-script.yaml`、`tools/install-python-package.yaml` 仅改 `enabled` 一个键为 `false`。
2. 新增 `roles/信息收集-最小.yaml`：内置（`internal/mcp/builtin/constants.go` 注册）`query_assets` / `get_asset` / `create_asset` / `complete_asset_scan` / `list_project_facts` / `search_project_facts` / `upsert_project_fact` / `record_vulnerability` / `list_knowledge_risk_types` / `search_knowledge_base` + CLI（tools/ 出厂启用）`nmap` / `subfinder` / `amass` / `dnsenum` / `gau` / `waybackurls` / `katana`。
3. 新增 `roles/Web测试-最小.yaml`：内置 `record_vulnerability` / `get_vulnerability` / `list_vulnerabilities` / `query_assets` / `get_asset` / `list_knowledge_risk_types` / `search_knowledge_base` + CLI `ffuf` / `nuclei` / `sqlmap` / `dirsearch` / `wpscan` / `nikto` / `dalfox` / `arjun` / `wafw00f`。
4. `docs/zh-CN/security-hardening.md` 增「本 fork 默认（治理基线）」节（实际 5 行，≤10 行约束满足）。
5. 核对 `roles/README.md`：已写明「不设置 `tools` 字段 = 默认使用全部已开启工具」（`roles/README.md` 方式2 与字段说明两处），无需改动。

## 验证方式（D10 门禁 + 本 Phase 自验）

- `go test ./...` 全绿（已知基线：HITL 2 项断言在基线即失败，维持原状不算新增引入）。
- `node --test web/static/js/*.test.cjs` 全绿（同上基线豁免）。
- YAML 语法自检：Python `yaml.safe_load` 解析两个新角色文件 + 三个工具文件。
- 工具名交叉核对脚本：角色 `tools` 列表每个名字必须命中（a）`internal/mcp/builtin/constants.go` 注册常量 或（b）`tools/<name>.yaml` 且出厂 `enabled: true`；同时断言两角色不含 D11 禁入名单。
- 仓库无「出厂 yaml 断言」现成测试缝（`internal/config/tools_reload_test.go` 仅用临时目录、不引用仓库出厂文件；`role_validation_test.go` 为 HTTP CRUD 校验），按派单约定不新建测试基建，以脚本核对 + 本记录留痕替代。

## 验证记录（2026-10-10，实施完成当日）

- `go test ./...`：34 个包全部 `ok`，0 FAIL / 0 SKIP，退出码 0。计划预告的「HITL 2 项断言基线失败」在 Go 侧未复现（`internal/hitl` 亦绿），如实记录。
- `node --test web/static/js/*.test.cjs`：292 项，291 通过，1 失败——`hitl-approval-ui.test.cjs`「Agent 审查不进入人工审批弹窗、倒计时和项目计数」，为扫描 Go 源码找 `ADD COLUMN reviewer TEXT NOT NULL DEFAULT 'human'` 的源码对齐断言，与当前源不匹配。该测试只读 Go 源码，与本 Phase 改动（YAML/文档，零 Go 文件）无交集，判定为基线既有失败，维持原状。计划预告 2 项失败、实测 1 项，差异如实记录。
- YAML 自检 + 交叉核对脚本（`python3` + PyYAML，临时脚本未入库）：
  - 三个工具 yaml 解析成功且 `enabled=False`；
  - `roles/信息收集-最小.yaml` 解析成功，17 个工具全部命中（10 内置 + 7 CLI 出厂启用）；
  - `roles/Web测试-最小.yaml` 解析成功，16 个工具全部命中（7 内置 + 9 CLI 出厂启用）；
  - 两角色均未命中 D11 禁入名单（exec 三件套/攻击爆破/C2/WebShell）；
  - 出厂 13 个角色文件零改动（`git diff HEAD -- roles/` 为空）；攻击类工具（metasploit/hydra/responder/netexec 等）enabled 保持出厂 `true` 未误伤。
- 改动面核对：`git status` 仅 4 个修改文件（3 工具 yaml 各 1 行 + 安全文档 7 行）+ 4 个新增（2 角色 yaml + 2 feature 文档）；两个计划/评估 md 为开工前已存在的未跟踪文件，非本 Phase 产物。

## 验收对照（计划 §4.3）

- [ ] 按出厂配置启动后，agent 调用 `nmap` 触发 HITL（白名单外）→ 属运行时验收，需用户在 UI 开启 HITL 模式后实测；本 Phase 已具备前提：`nmap` 不在出厂 `tool_whitelist`（`config.example.yaml` hitl 节）。
- [ ] `信息收集-最小` 角色对话里不可见 `exec`（已关）与 metasploit 等（角色面外）→ 由白名单显式声明 + 三工具 `enabled: false` 保证；运行时验收同上留用户实测。
- [ ] 文档写明默认 reviewer=human 与本 fork 工具开关基线 → `docs/zh-CN/security-hardening.md`「本 fork 默认（治理基线）」节，已完成。

## 回滚

YAML/文档纯声明式改动：`git revert` 本分支提交即完全回滚；无数据库/运行时状态迁移。仓库在跑服务（PID 9386）不依赖 tools 目录热加载行为，本改动不影响运行中进程（其配置已加载，重启后生效新默认）。

## 验收记录（2026-10-11 用户实测通过）

- 服务重启后（PID 62846，00:14:42）按新配置运行。
- 会话级开启审批模式（会话设置 → 人机协同 → 模式），`信息收集-最小` 角色对话发出「nmap 对 127.0.0.1:9099 服务识别」。
- 证据（data/conversations.db 只读查询）：`audit_logs` hitl decision ×3 success（00:23:55/00:25:23/00:25:32）；`tool_executions` nmap completed（00:24:16）。
- 结论：审批拦截、人工放行、工具执行全链路通过；角色工具面与文档基线由 tester/reviewer 静态验证。Phase 1 验收通过。
