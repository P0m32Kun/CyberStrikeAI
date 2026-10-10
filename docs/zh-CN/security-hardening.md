# 安全加固指南

[English](../en-US/security-hardening.md)

本文给出 CyberStrikeAI 上线前和持续运行中的安全加固清单。

## 本 fork 默认（治理基线）

- HITL 出厂 `default_reviewer: human`（人工审批）；全局白名单为低风险只读/查询与状态回调类工具（`config.example.yaml` 出厂列表可直接沿用）。
- HITL 模式出厂 `default_mode: off`（`config.example.yaml:191`），开箱无审批拦截：须显式开启（全局 `default_mode` 或会话级）后，白名单与 reviewer=human 才生效。
- `exec` / `execute-python-script` / `install-python-package` 三个治理绕过型工具默认 `enabled: false`，需要时显式开启并配合审批使用。
- Eino 本地文件/Shell 工具链出厂启用（`multi_agent.eino_skills.filesystem_tools: true`，注册 read_file/glob/grep/write/edit/execute），**不受** `tools/exec.yaml` 开关影响；按需设 `false` 关闭。
- C2 出厂默认启用（`config.example.yaml` 为 `true`，配置缺省也视为启用），部署时必须显式写 `c2.enabled: false`；WebShell 不配置连接即不可用。
- 监听地址出厂为 `0.0.0.0:8080`（全接口），内网环境有暴露面：建议改绑 `127.0.0.1`，或用防火墙/反向代理限制来源。

## 上线前必做

- 首次部署后立即修改 `admin` 初始密码（Web 界面或平台权限 → 用户管理）。
- 使用 HTTPS，或放在可信反向代理之后。
- 限制来源 IP、VPN 或堡垒机访问。
- 开启 `audit.enabled`。
- 不需要 C2 时设置 `c2.enabled: false`。
- 不暴露独立 HTTP MCP，除非设置强认证和网络隔离。
- 外部 MCP 只接可信服务。
- 备份 `config.yaml`、`data/`、自定义资源目录。

## 反向代理建议

Nginx 基线：

```nginx
client_max_body_size 200m;
proxy_buffering off;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

建议额外加：

```nginx
add_header X-Content-Type-Options nosniff;
add_header Referrer-Policy no-referrer;
add_header X-Frame-Options DENY;
```

## HITL 白名单基线

推荐最小白名单：

```yaml
hitl:
  tool_whitelist:
    - read_file
    - glob
    - grep
    - tool_search
```

不要默认加入：

- `execute`
- WebShell 写入/执行工具
- C2 任务和 payload 工具
- 外部 MCP 高风险工具
- 删除、写入、上传、持久化相关工具

## 文件权限

建议：

```bash
chmod 600 config.yaml
chmod 700 data
```

生产环境使用独立系统用户运行：

```text
cyberstrike-ai:cyberstrike-ai
```

避免 root 运行，除非明确需要绑定低端口或访问特殊资源。

## 外部 MCP 审查

接入前确认：

- 工具是否能执行命令。
- 是否能读写本机文件。
- 是否会把数据发往第三方。
- 是否有自己的认证。
- 是否会返回不可信网页或模型内容。
- 是否需要容器隔离。

接入后：

- 高风险工具不进白名单。
- 定期检查工具列表变化。
- 审计配置变更。

## C2 和 WebShell

C2：

- 默认关闭。
- 演练窗口临时开启。
- Listener 端口与管理端口分离。
- 结束后清理 payload、session、task、event。

WebShell：

- 只保存授权目标。
- 使用清晰命名。
- 写入/删除/执行必须审批。
- 项目结束删除连接。

## 数据保留

建议：

- 审计：30-90 天。
- 工具监控：90-180 天。
- 上传附件：项目结束清理。
- C2/WebShell 输出：只保留报告需要的证据。
- 知识库：不放真实凭证和客户私密数据。

## 周期巡检

每周：

- 登录失败和异常 IP。
- 配置变更。
- 外部 MCP 增删改。
- 长时间运行工具。
- C2 是否被意外开启。
- WebShell 连接是否过期。
- 磁盘空间和数据库大小。

每个项目结束：

- 清理临时 workspace。
- 删除无用附件。
- 归档必要证据。
- 删除过期 WebShell/C2 资源。
- 导出审计记录。
