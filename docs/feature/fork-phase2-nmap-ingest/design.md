# Fork Phase 2 nmap → 资产自动入库 · 设计

对齐 `CyberStrikeAI-二开计划.md` §5 与 §0 已锁定决策 D10/D13。分支：`P0m32Kun/phase-2-nmap-ingest`（基线 main=4584aaa2）。

## 目标

nmap 执行成功后，端口/服务**自动**写入 `assets`（去重键=目标+端口+协议，与现网一致），原始输出保留在 `tool_executions`；另提供手动补导工具。不改 assets 表结构，不引第三方依赖。

## 结构

```
tools/nmap.yaml                 说明文档化自动 -oX 与自动入库行为（参数与默认 args 不变）
internal/ingest/ingress.go      IngressParser 接口（扩展位：masscan/httpx 可插）
internal/ingest/nmap/parser.go  nmap XML → []*database.Asset 草案（标准库 encoding/xml）
internal/security/executor.go   挂载点 A：ToolSuccessHook + nmap 自动 -oX 临时文件
internal/app/nmap_ingest.go     挂载点 A 接线（项目绑定/审计）+ 挂载点 B 工具 ingest_nmap_xml
internal/mcp/builtin/constants.go   新常量 ToolIngestNmapXML
internal/app/mcp_authorization.go   ingest_nmap_xml 授权 case（asset:write + project 访问）
roles/信息收集-最小.yaml        工具白名单追加 ingest_nmap_xml
docs/zh-CN/asset-management.md  「扫描自动入库（nmap）」小节
```

## 关键决策

1. **-oX 注入位置在 Executor 而非 YAML**：临时路径每次执行不同，静态 YAML 无法表达；Executor 在 `buildCommandArgs` 之后追加 `-oX <tmp>`，不影响既有参数顺序测试。仅当注册了成功回调时才注入，未接线时行为与原先一致。
2. **协议取传输层（tcp/udp）而非服务名**：去重键含协议，若用服务名（-sV 才有）会造成有/无版本检测的两次扫描键漂移产生重复行；服务名进 Server 指纹与标签。同理 PTR 主机名只写 Host 不写 Domain，保证去重目标稳定落在 IP。
3. **挂载点 A 不做权限门（D13）**：能跑 nmap 的会话（已有 agent:local-execute）发现端口/服务属数据记录非攻击动作，直接写库、落审计，不触发 HITL；资产归属会话用户，可在资产页删除。挂载点 B 走与 create_asset 相同的 asset:write 门。
4. **无项目不写库（§5.3.5）**：A/B 两挂载点都要求 project（ctx 直带或对话绑定；B 还接受显式 project_id 参数），避免污染全局资产。
5. **接口位置**：`IngressParser` 放在父包 `internal/ingest`（任务书表述为随 `internal/ingest/nmap/` 新建，此处取中性父包，后续 masscan/httpx 实现者不必 import nmap 包）——对目标清单的小幅偏差，语义一致。
6. **临时文件生命周期**：Executor 创建、成功且非空时交给回调、ExecuteTool 返回前删除（含失败路径）；stdout 全量仍在 tool_executions 留痕。
7. **`xml_file` 路径白名单（tester 路径穿越探针后补）**：`ingest_nmap_xml` 的 `xml_file` 仅允许 `os.TempDir()` 及其子路径（`filepath.Rel` 判定，非字符串前缀，防 `/tmp-evil` 型绕过），含 `..` 段一律拒绝（即使规范化后仍在临时目录内），相对路径先转绝对再判定，`filepath.EvalSymlinks` 解析后复检仍在临时目录内（堵住临时目录内符号链接指向外部文件的受限读通道；root 与待检路径均做符号链接归一，macOS `/var`→`/private/var`）；越界路径返回统一说明性错误、不回显文件内容，消除任意文件存在性/可读性 oracle。`xml_content` 与 `xml_file` 同时提供时报错，不静默忽略。`xml_file` 定位为执行器 `-oX` 临时产物的补导入口，历史扫描导入的通用入口是 `xml_content`（贴全文）。挂载点 A 的 hook 不受影响——其读取的是 Executor 自建的可信临时路径。
8. **ingest 按项目内去重（reviewer 二轮裁定）**：`assets.dedup_key` 有 UNIQUE 约束且不改表结构，项目限定形态通过 DB 层新变体 `UpsertAssetsInProject` 实现——去重键内容追加 `|<projectID>` 段，同键资产在不同项目各存一行、命中更新只发生在同项目内，消除「新 engagement 重扫导致旧项目资产整批迁移」的无决策跨项目漂移；与 Phase 3 流量库「项目是数据维度」定案一致。`create_asset`/既有 `UpsertAssets` 全局键空间与行为完全不动（上游兼容），全局键与项目键互不命中（手工行与 nmap 行并存时靠人工 MergeAssets 合并）。`allowGlobal` 仅挂载 B 透传（与 create_asset 同构，全局 scope 管理员可更新他人 owner 同键行）；**挂载 A 固定 false**——后台自动入库非人工决策，命中他人 owner 行时按既有语义跳过更保守，需要跨 owner 合并时走人工路径。
9. **已知取舍：同步入库耗时**：挂载 A 的入库在工具成功返回前同步完成，计入工具调用总时长；万级端口的扫描 XML 解析+逐条 upsert 可能把调用推过超时线。当前量级（渗透作业单目标/网段）可接受，后续如遇超时可异步化（回调投队列、结果经审计日志补记）。

## 字段映射（不改表）

| nmap XML | Asset 字段 |
|---|---|
| address[ipv4/ipv6] | IP（取 Host 展示） |
| hostname（任意 type，取第一个非空，含 PTR/user 等） | Host（不写 Domain，理由见决策 2） |
| port protocol / portid | Protocol / Port（仅 state=open） |
| service product+version（缺省服务名） | Server（截断 255 字符） |
| script http-title | Title（截断 500 字符） |
| 服务名、OS 猜测 | Tags：`nmap`、`nmap-service:<名>`、`nmap-os:<猜>` |
| nmaprun args | SourceQuery；Source=nmap |

## 边界

- closed/filtered/open|filtered 端口不入库；status 非 up 的主机跳过。
- 挂载点 A 回调同步执行（入库耗时在工具执行内返回前完成），失败只记日志与提示，不影响工具成功结果。
