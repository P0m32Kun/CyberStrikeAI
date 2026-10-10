// nmap 扫描结果 → 资产库自动入库（fork Phase 2，D13 定案）。
// 挂载点 A：工具执行成功回调（security.ToolSuccessHook）自动 ingest；
// 挂载点 B：内置工具 ingest_nmap_xml 供人/agent 补导历史扫描。
package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/ingest"
	ingestnmap "cyberstrike-ai/internal/ingest/nmap"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/security"

	"go.uber.org/zap"
)

// nmapAutoIngestHook 返回挂载点 A 的成功回调：tool_name==nmap 且 XML 存在时
// 自动解析写入 assets。入库必须带当前对话/任务的项目绑定（计划 §5.3.5），
// 无项目时不写库并返回提示；不触发 HITL，落审计日志（D13）。
func nmapAutoIngestHook(db *database.DB, auditSvc *audit.Service, logger *zap.Logger) security.ToolSuccessHook {
	parser := ingestnmap.New()
	return func(ctx context.Context, toolName string, args map[string]interface{}, xmlOutputPath string) string {
		if toolName != "nmap" || db == nil {
			return ""
		}
		conversationID := conversationIDFromToolCtx(ctx)
		projectID := nmapIngestProjectID(db, ctx)
		if projectID == "" {
			logger.Info("nmap 自动入库跳过：当前执行未绑定项目",
				zap.String("conversation_id", conversationID),
			)
			return "[nmap-ingest] 当前对话未绑定项目，扫描结果未自动入库；可绑定项目后重扫，或用 ingest_nmap_xml 显式指定 project_id 导入"
		}
		data, err := os.ReadFile(xmlOutputPath)
		if err != nil {
			logger.Warn("nmap 自动入库读取 XML 失败", zap.Error(err))
			return ""
		}
		// 挂载 A 固定 allowGlobal=false：后台自动入库不跨 owner 更新他人行，
		// 命中他人行时按既有语义跳过（取舍见 design.md 决策 8）。
		result, err := ingestNmapAssets(db, auditSvc, logger, parser, data, projectID, nmapIngestOwner(ctx), conversationID, "auto", false)
		if err != nil {
			logger.Warn("nmap 自动入库失败", zap.String("conversation_id", conversationID), zap.Error(err))
			return "[nmap-ingest] 自动入库失败: " + err.Error()
		}
		return fmt.Sprintf("[nmap-ingest] 扫描结果已自动入库：新增 %d、更新 %d、跳过 %d（project=%s）", result.Created, result.Updated, result.Skipped, projectID)
	}
}

// nmapIngestProjectID 解析当前执行的项目绑定：ctx 直带项目 → 对话绑定项目。
func nmapIngestProjectID(db *database.DB, ctx context.Context) string {
	if projectID := strings.TrimSpace(mcp.MCPProjectIDFromContext(ctx)); projectID != "" {
		return projectID
	}
	if conversationID := conversationIDFromToolCtx(ctx); conversationID != "" && db != nil {
		if projectID, err := db.GetConversationProjectID(conversationID); err == nil {
			return strings.TrimSpace(projectID)
		}
	}
	return ""
}

func nmapIngestOwner(ctx context.Context) string {
	if principal, ok := authctx.PrincipalFromContext(ctx); ok {
		return principal.UserID
	}
	return ""
}

// ingestNmapAssets 是挂载点 A/B 共用的入库路径：解析 → 绑定项目 →
// UpsertAssetsInProject（去重键=目标+端口+协议+项目，同键跨项目各存一行、
// 不迁移既有行的项目归属）→ 审计日志。allowGlobal 仅挂载 B 透传（与
// create_asset 同构：全局 scope 可更新他人 owner 的同键行）。
func ingestNmapAssets(db *database.DB, auditSvc *audit.Service, logger *zap.Logger, parser ingest.IngressParser, data []byte, projectID, ownerUserID, conversationID, trigger string, allowGlobal bool) (database.AssetImportResult, error) {
	result := database.AssetImportResult{}
	assets, err := parser.Parse(data)
	if err != nil {
		auditNmapIngest(auditSvc, "failure", "", projectID, conversationID, trigger, map[string]interface{}{"error": err.Error()})
		return result, err
	}
	if len(assets) == 0 {
		return result, nil
	}
	for _, asset := range assets {
		asset.ProjectID = projectID
	}
	result, err = db.UpsertAssetsInProject(assets, ownerUserID, projectID, allowGlobal)
	if err != nil {
		auditNmapIngest(auditSvc, "failure", "", projectID, conversationID, trigger, map[string]interface{}{"error": err.Error()})
		return result, err
	}
	auditNmapIngest(auditSvc, "success", ownerUserID, projectID, conversationID, trigger, map[string]interface{}{
		"created": result.Created, "updated": result.Updated, "skipped": result.Skipped,
		"xml_bytes": len(data), "assets": len(assets),
	})
	return result, nil
}

func auditNmapIngest(auditSvc *audit.Service, result, actor, projectID, conversationID, trigger string, detail map[string]interface{}) {
	if auditSvc == nil {
		return
	}
	action := "nmap_auto_ingest"
	if trigger != "auto" {
		action = "nmap_xml_import"
	}
	message := "nmap 扫描结果自动写入资产库"
	if trigger != "auto" {
		message = "nmap XML 扫描结果手动导入资产库"
	}
	if result == "failure" {
		message += "失败"
	}
	auditSvc.RecordSystem(audit.Entry{
		Category: "asset", Action: action, Result: result, Actor: actor,
		ResourceType: "project", ResourceID: projectID,
		Message: message,
		Detail:  mergeDetail(detail, map[string]interface{}{"tool": "nmap", "trigger": trigger, "conversation_id": conversationID}),
	})
}

func mergeDetail(base, extra map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{}, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	return merged
}

// nmapXMLFileConstraintMsg 是 xml_file 被拒时的统一错误说明（不回显任何文件内容）。
const nmapXMLFileConstraintMsg = "错误: xml_file 仅允许系统临时目录内的文件（执行器 nmap -oX 临时产物）；导入历史扫描请把 XML 全文贴到 xml_content"

// nmapTmpRoot 返回符号链接归一化后的系统临时目录根（macOS 上 /var 是
// /private/var 的符号链接，root 与待检路径必须同尺度比较）。
var nmapTmpRoot = func() string {
	root := os.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		return resolved
	}
	return root
}()

// validateNmapXMLFilePath 把 xml_file 参数约束在系统临时目录（os.TempDir()）及其
// 子路径内，防止工具被当作任意文件存在性/可读性 oracle。相对路径先规范化为
// 绝对路径再判定；含 `..` 段的路径一律拒绝（即使规范化后仍在临时目录内）；
// 符号链接解析后复检仍在临时目录内，堵住指向外部文件的受限读通道。
func validateNmapXMLFilePath(path string) error {
	cleaned := strings.TrimSpace(path)
	if cleaned == "" {
		return fmt.Errorf("xml_file 不能为空")
	}
	for _, seg := range strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == filepath.Separator || r == '/'
	}) {
		if seg == ".." {
			return fmt.Errorf("%s（检测到 .. 路径段）", nmapXMLFileConstraintMsg)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return fmt.Errorf("%s（路径无效）", nmapXMLFileConstraintMsg)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("%s（路径无法解析）", nmapXMLFileConstraintMsg)
	}
	// 文件不存在（尚未生成的 -oX 产物路径）留给后续 ReadFile 报错，此处只拦白名单。
	rel, err := filepath.Rel(nmapTmpRoot, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%s（%s 不在临时目录内）", nmapXMLFileConstraintMsg, filepath.Clean(cleaned))
	}
	return nil
}

// registerNmapIngestTools 注册挂载点 B 的内置工具 ingest_nmap_xml。
func registerNmapIngestTools(server *mcp.Server, db *database.DB, auditSvc *audit.Service, logger *zap.Logger) {
	if server == nil || db == nil {
		return
	}
	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolIngestNmapXML,
		ShortDescription: "导入 nmap XML 扫描结果到资产库",
		Description:      "把一次 nmap 扫描的 XML 输出（-oX 格式）导入资产库，按目标+端口+协议去重，适合补导历史扫描。导入历史扫描请把 XML 全文贴到 xml_content（通用入口）；xml_file 仅用于读取执行器 nmap -oX 临时产物，只允许系统临时目录内的文件路径。项目绑定：优先使用 project_id 参数，缺省使用当前对话绑定的项目；两者都没有时拒绝入库，避免污染全局资产。",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"xml_content": map[string]interface{}{"type": "string", "description": "nmap -oX 输出的 XML 全文（与 xml_file 二选一；导入历史扫描的通用入口）"},
				"xml_file":    map[string]interface{}{"type": "string", "description": "执行器 nmap -oX 临时产物路径（与 xml_content 二选一；仅允许系统临时目录内文件，拒绝临时目录外的路径与含 .. 的路径）"},
				"project_id":  map[string]interface{}{"type": "string", "description": "入库目标项目 ID；缺省使用当前对话绑定的项目"},
			},
		},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		xmlContent := strings.TrimSpace(strArg(args, "xml_content"))
		xmlFile := strings.TrimSpace(strArg(args, "xml_file"))
		if xmlContent == "" && xmlFile == "" {
			return textResult("错误: 需要 xml_content 或 xml_file 之一", true), nil
		}
		if xmlContent != "" && xmlFile != "" {
			return textResult("错误: xml_content 与 xml_file 只能二选一，同时提供会被静默忽略，请只传其一", true), nil
		}
		var data []byte
		var err error
		if xmlContent != "" {
			data = []byte(xmlContent)
		} else {
			if err := validateNmapXMLFilePath(xmlFile); err != nil {
				return textResult(err.Error(), true), nil
			}
			data, err = os.ReadFile(xmlFile)
			if err != nil {
				return textResult("错误: 读取 XML 文件失败: "+err.Error(), true), nil
			}
		}
		projectID := strings.TrimSpace(strArg(args, "project_id"))
		if projectID == "" {
			projectID = nmapIngestProjectID(db, ctx)
		}
		if projectID == "" {
			return textResult("错误: 无法确定入库项目：当前对话未绑定项目且未提供 project_id。请先绑定项目或显式传 project_id", true), nil
		}
		// allowGlobal 与 create_asset 同构：全局 scope 的管理员可更新他人 owner 的同键行。
		_, owner, global := assetAccessFromToolContext(ctx, "asset:write")
		result, err := ingestNmapAssets(db, auditSvc, logger, ingestnmap.New(), data, projectID, owner, conversationIDFromToolCtx(ctx), "manual", global)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return textResult(fmt.Sprintf("nmap XML 导入完成：新增 %d、更新 %d、跳过 %d（project=%s）", result.Created, result.Updated, result.Skipped, projectID), false), nil
	})
}
