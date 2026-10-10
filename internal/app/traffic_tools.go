package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/traffic"

	"go.uber.org/zap"
)

const (
	agentFlowPageSizeMax = 50
	// agent 工具输出的字段截断上限，防止大正文吃掉模型上下文；
	// REST API 与库里保留完整预览（8KB）。
	agentFlowHeaderCap = 2048
	agentFlowBodyCap   = 2048
	agentChatBodyCap   = 4096
)

// registerTrafficTools 注册 HTTP 流量共享库的 agent 工具。
func registerTrafficTools(server *mcp.Server, store *traffic.Store, db *database.DB, logger *zap.Logger) {
	if server == nil || store == nil || logger == nil {
		return
	}

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolQueryHTTPFlows,
		ShortDescription: "检索已存 HTTP 流量",
		Description:      "分页检索平台流量库里已保存的 HTTP 流量（来自 Burp/浏览器插件同步或手动导入）。支持 project_id、q（全文/元数据搜索）、host 过滤，按时间倒序返回摘要行；用 get_http_flow 取单条详情。对话绑定项目时只能查到该项目流量。",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"project_id": map[string]interface{}{"type": "string", "description": "按项目过滤；对话绑定项目时该参数被项目边界覆盖"},
			"q":          map[string]interface{}{"type": "string", "description": "搜索词：FTS 可用时全文匹配（含正文），否则匹配 url/host/content_type 元数据"},
			"host":       map[string]interface{}{"type": "string", "description": "精确 host 过滤（不含端口）"},
			"limit":      map[string]interface{}{"type": "integer", "minimum": 1, "maximum": agentFlowPageSizeMax, "description": "每页条数，默认 20"},
			"offset":     map[string]interface{}{"type": "integer", "minimum": 0, "description": "偏移量，默认 0"},
		}},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		filter := traffic.QueryFilter{
			ProjectID: strings.TrimSpace(strArg(args, "project_id")),
			Q:         strings.TrimSpace(strArg(args, "q")),
			Host:      strings.TrimSpace(strArg(args, "host")),
			Limit:     intArg(args, "limit", 20),
			Offset:    intArg(args, "offset", 0),
		}
		if filter.Limit < 1 || filter.Limit > agentFlowPageSizeMax {
			filter.Limit = 20
		}
		if filter.Offset < 0 {
			filter.Offset = 0
		}
		if db != nil {
			if projectID, scoped, err := agentAssetProjectScope(db, ctx); err != nil {
				return textResult("错误: 无法确定当前对话的项目范围", true), nil
			} else if scoped {
				// 对话绑定项目后，项目范围是服务端强制边界
				filter.ProjectID = projectID
			}
		}
		items, total, err := store.Query(filter)
		if err != nil {
			logger.Error("Agent 检索流量失败", zap.Error(err))
			return textResult("错误: "+err.Error(), true), nil
		}
		totalPages := (total + filter.Limit - 1) / filter.Limit
		if totalPages < 1 {
			totalPages = 1
		}
		page := filter.Offset/filter.Limit + 1
		var b strings.Builder
		b.WriteString(fmt.Sprintf("流量查询：第 %d/%d 页，本页 %d 条，共 %d 条（limit=%d）\n", page, totalPages, len(items), total, filter.Limit))
		for _, item := range items {
			b.WriteString(formatFlowListItem(item))
			b.WriteByte('\n')
		}
		if page < totalPages {
			b.WriteString(fmt.Sprintf("下一页：保持筛选条件并设置 offset=%d。", filter.Offset+filter.Limit))
		}
		return textResult(b.String(), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolGetHTTPFlow,
		ShortDescription: "查看单条流量详情",
		Description:      "按 ID 返回单条 HTTP 流量的详情（方法、URL、请求/响应头与正文预览，字段截断保护上下文）。列表检索先用 query_http_flows。",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"id": map[string]interface{}{"type": "string", "description": "流量 ID"},
		}, "required": []string{"id"}},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		id := strings.TrimSpace(strArg(args, "id"))
		if id == "" {
			return textResult("错误: id 不能为空", true), nil
		}
		detail, err := store.Get(id)
		if errors.Is(err, traffic.ErrNotFound) {
			return textResult("错误: 流量不存在", true), nil
		}
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if db != nil {
			projectID, scoped, err := agentAssetProjectScope(db, ctx)
			if err != nil {
				// 项目边界判定失败必须 fail-closed（对齐 query 工具与资产工具惯例）
				return textResult("错误: 无法确定当前对话的项目范围", true), nil
			}
			if scoped && detail.ProjectID != projectID {
				return textResult("错误: 流量不存在或不属于当前对话绑定的项目", true), nil
			}
		}
		return assetJSONResult(flowToolDetail(detail))
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolTagHTTPFlow,
		ShortDescription: "给流量打标签",
		Description:      "整体替换单条流量的标签（用于人工/agent 标注重点流量，如 auth-bypass、retest）。仅在用户明确要求标注时调用。",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"id":   map[string]interface{}{"type": "string", "description": "流量 ID"},
			"tags": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "maxItems": 50, "description": "新标签集合（整体替换）"},
		}, "required": []string{"id", "tags"}},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		id := strings.TrimSpace(strArg(args, "id"))
		if id == "" {
			return textResult("错误: id 不能为空", true), nil
		}
		tags, err := stringSliceArg(args["tags"])
		if err != nil {
			return textResult("错误: tags "+err.Error(), true), nil
		}
		if db != nil {
			projectID, scoped, err := agentAssetProjectScope(db, ctx)
			if err != nil {
				// 项目边界判定失败必须 fail-closed（对齐 query 工具与资产工具惯例）
				return textResult("错误: 无法确定当前对话的项目范围", true), nil
			}
			if scoped {
				if detail, err := store.Get(id); err != nil || detail.ProjectID != projectID {
					return textResult("错误: 流量不存在或不属于当前对话绑定的项目", true), nil
				}
			}
		}
		if err := store.SetTags(id, tags); err != nil {
			if errors.Is(err, traffic.ErrNotFound) {
				return textResult("错误: 流量不存在", true), nil
			}
			return textResult("错误: "+err.Error(), true), nil
		}
		return textResult(fmt.Sprintf("流量标签已更新: id=%s tags=%v", id, tags), false), nil
	})

	server.RegisterTool(mcp.Tool{
		Name:             builtin.ToolStartChatFromFlow,
		ShortDescription: "从流量生成对话引用文本",
		Description:      "按 ID 取回一条已存流量并格式化为可直接引用的请求/响应文本（与 Burp 插件「Send to Agent」的输出形态兼容），供在对话中针对该流量继续分析。",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{
			"id": map[string]interface{}{"type": "string", "description": "流量 ID"},
		}, "required": []string{"id"}},
	}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		id := strings.TrimSpace(strArg(args, "id"))
		if id == "" {
			return textResult("错误: id 不能为空", true), nil
		}
		detail, err := store.Get(id)
		if errors.Is(err, traffic.ErrNotFound) {
			return textResult("错误: 流量不存在", true), nil
		}
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if db != nil {
			projectID, scoped, err := agentAssetProjectScope(db, ctx)
			if err != nil {
				// 项目边界判定失败必须 fail-closed（对齐 query 工具与资产工具惯例）
				return textResult("错误: 无法确定当前对话的项目范围", true), nil
			}
			if scoped && detail.ProjectID != projectID {
				return textResult("错误: 流量不存在或不属于当前对话绑定的项目", true), nil
			}
		}
		return textResult(formatFlowForChat(detail), false), nil
	})
}

// formatFlowListItem 输出列表摘要行，格式对齐资产工具的摘要行风格。
func formatFlowListItem(item traffic.FlowItem) string {
	tags := strings.Join(item.Tags, ",")
	return fmt.Sprintf("- id=%s | %s %s%s | status=%d | url=%s | resp_len=%d | tags=%s",
		item.ID, item.Method, item.Host, item.URLTemplate, item.Status,
		truncateRunes(item.URL, 200), item.RespLen, tags)
}

// flowToolDetail 控制单条详情进模型上下文的体积。
func flowToolDetail(detail *traffic.FlowDetail) map[string]interface{} {
	if detail == nil {
		return nil
	}
	base := detail.FlowItem
	return map[string]interface{}{
		"id": base.ID, "ts": base.TS, "method": base.Method, "url": truncateRunes(base.URL, 500),
		"url_template": base.URLTemplate, "host": base.Host, "status": base.Status,
		"content_type": truncateRunes(base.ContentType, 100), "req_len": base.ReqLen, "resp_len": base.RespLen,
		"tags": base.Tags, "source": base.Source, "project_id": base.ProjectID,
		"req_headers":  truncateRunes(detail.ReqHeaders, agentFlowHeaderCap),
		"req_body":     truncateRunes(detail.ReqBody, agentFlowBodyCap),
		"resp_headers": truncateRunes(detail.RespHeaders, agentFlowHeaderCap),
		"resp_body":    truncateRunes(detail.RespBody, agentFlowBodyCap),
		"truncated":    detail.BodyTruncated,
	}
}

// formatFlowForChat 生成对话引用文本；分节结构与 Burp 插件
// HttpMessageFormatter.toPrompt 的输出形态兼容（[Target]/[Request]/
// [Optional: Response (truncated)]），正文截断保护上下文。
func formatFlowForChat(detail *traffic.FlowDetail) string {
	var b strings.Builder
	b.WriteString("[Target]\n")
	b.WriteString(strings.TrimSpace(detail.Method + " " + detail.URL))
	b.WriteString("\n\n[Request]\n")
	if h := strings.TrimSpace(detail.ReqHeaders); h != "" {
		b.WriteString(truncateRunes(h, agentChatBodyCap))
		b.WriteString("\n\n")
	}
	if body := detail.ReqBody; body != "" {
		b.WriteString(truncateRunes(body, agentChatBodyCap))
		b.WriteString("\n")
	}
	if strings.TrimSpace(detail.RespHeaders) != "" || detail.RespBody != "" {
		b.WriteString("\n[Optional: Response (truncated)]\n")
		if h := strings.TrimSpace(detail.RespHeaders); h != "" {
			b.WriteString(truncateRunes(h, agentChatBodyCap))
			b.WriteString("\n\n")
		}
		if body := detail.RespBody; body != "" {
			b.WriteString(truncateRunes(body, agentChatBodyCap))
			b.WriteString("\n")
		}
	}
	ts := time.UnixMilli(detail.TS).UTC().Format(time.RFC3339)
	b.WriteString(fmt.Sprintf("\n[Meta]\nid=%s | ts=%s | status=%d | project_id=%s | tags=%s\n",
		detail.ID, ts, detail.Status, detail.ProjectID, strings.Join(detail.Tags, ",")))
	return b.String()
}
