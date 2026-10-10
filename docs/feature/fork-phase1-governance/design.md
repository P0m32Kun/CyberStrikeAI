# Fork Phase 1 治理默认收紧 · 设计

对齐 `CyberStrikeAI-二开计划.md` §4（Phase 1）与 §0 已锁定决策 D10/D11。分支：`fork/phase-1-governance`（基线 main=deda642b）。

## 目标

开箱即适合「真实授权目标」作业：治理绕过型工具默认关、角色工具面最小、安全基线写入文档。本 Phase 无 Go 代码改动预期，仅 YAML 与文档。

## D11 边界（不可越）

- 默认 `enabled: false` 仅「治理绕过型」三件套：`exec` / `execute-python-script` / `install-python-package`，且只改 `enabled` 一个键。
- metasploit、hydra、responder 等攻击工具保持启用不动，靠 HITL 审批 + 角色最小白名单管住。
- 出厂 13 个角色文件一律不动，只**新增**两个最小角色（`信息收集-最小`、`Web测试-最小`）。
- HITL 默认（`default_reviewer: human`）已被上游出厂值覆盖（`config.example.yaml`），本 Phase 不改代码；但 `hitl.default_mode` 出厂为 `off`（`config.example.yaml:191`，缺省亦视为 off），白名单与 reviewer=human 仅在 HITL 模式显式开启（全局或会话级）后生效，开箱无审批拦截。

## 改动清单

| 文件 | 改动 |
|------|------|
| `tools/exec.yaml` | `enabled: true` → `false`（仅此一键） |
| `tools/execute-python-script.yaml` | 同上 |
| `tools/install-python-package.yaml` | 同上 |
| `roles/信息收集-最小.yaml` | 新增：只读/入库类内置工具 + 默认启用侦察 CLI，白名单显式声明 |
| `roles/Web测试-最小.yaml` | 新增：默认启用 Web 测试 CLI + 漏洞记录/资产查询内置工具 |
| `docs/zh-CN/security-hardening.md` | 新增「本 fork 默认（治理基线）」一节（≤10 行） |
| `docs/feature/fork-phase1-governance/*` | 本文档链 |

## 角色白名单选取规则

- 内置工具名逐一对照 `internal/mcp/builtin/constants.go` 注册常量；CLI 工具名 = `tools/*.yaml` 文件名，且要求该文件出厂 `enabled: true`（默认禁用工具如 `fofa_search` 不进白名单，待用户配 key 后自行加）。
- 两角色均不含：`exec` / `execute-python-script` / `install-python-package` / `metasploit` / `msfvenom` / `hydra` / `john` / `hashcat` / `responder` / `netexec` / `smbmap` / `impacket` 及任何 C2（`c2_*`）/ WebShell（`webshell_*`、`manage_webshell_*`）工具。
- 按 `roles/README.md` 约定，设置 `tools` 字段的角色包含核心三件套（`record_vulnerability` / `list_knowledge_risk_types` / `search_knowledge_base`）。

## 已知事实偏差（记录，不在本 Phase 修）

- 「C2 默认禁用」并非出厂现状：`config.example.yaml` 出厂 `c2.enabled: true`，且 `C2Config.EnabledEffective()`（`internal/config/config.go:2459`）在配置缺省时返回 `true`。本 Phase 文档按「必须显式关闭」表述，改出厂默认留待后续票裁决（涉及行为变化，超本 Phase 边界）。
- Eino 侧另有命令执行面：`multi_agent.eino_skills.filesystem_tools` 出厂 `true`（`config.example.yaml:334`，注册 read_file/glob/grep/write/edit/execute，缺省亦视为启用，见 `internal/config/config.go:463-473`），**不受** `tools/exec.yaml` 的 `enabled: false` 影响（两者注册链路独立：Eino 本地工具 vs MCP 工具目录）。是否翻转出厂默认留后续票裁决；本 Phase 已在 `docs/zh-CN/security-hardening.md` 基线节登记部署侧关闭指引。
- 出厂监听为 `server.host: 0.0.0.0`（全接口）；文档已写入改绑 `127.0.0.1` 建议，不动 `config.example.yaml`。

## 验收前提

计划 §4.3 验收第 1 条（「按出厂配置启动后，agent 调用 `nmap` 触发 HITL」）按**用户开启 HITL 模式**（全局 `default_mode` 或会话级）为前提执行——出厂 `default_mode: off` 下不存在审批拦截，该项验收不检验出厂开箱行为。与 `implementation-plan.md` 验收对照节的口径一致。
