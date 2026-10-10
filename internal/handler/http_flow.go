package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/traffic"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HTTPFlowHandler 处理 HTTP 流量共享库的 REST API。
// 鉴权沿用 /api/* 的 JWT/session 中间件（在路由注册处统一挂载）。
type HTTPFlowHandler struct {
	store  *traffic.Store
	db     *database.DB // 可为 nil；用于校验 project_id 对应项目存在
	logger *zap.Logger
}

const (
	maxFlowImportBatch   = 1000
	maxFlowListLimit     = 200
	defaultFlowListLimit = 50
)

// NewHTTPFlowHandler 创建流量库 handler。
func NewHTTPFlowHandler(store *traffic.Store, db *database.DB, logger *zap.Logger) *HTTPFlowHandler {
	return &HTTPFlowHandler{store: store, db: db, logger: logger}
}

type importHTTPFlowsRequest struct {
	ProjectID string         `json:"project_id"`
	Source    string         `json:"source"`
	Flows     []traffic.Flow `json:"flows" binding:"required"`
}

type setHTTPFlowTagsRequest struct {
	Tags []string `json:"tags" binding:"required"`
}

func validFlowSource(source string) bool {
	switch source {
	case "burp", "browser", "manual":
		return true
	}
	return false
}

// Import 批量导入流量：POST /api/http-flows
func (h *HTTPFlowHandler) Import(c *gin.Context) {
	var req importHTTPFlowsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Flows) == 0 || len(req.Flows) > maxFlowImportBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "flows 数量必须在 1-1000 之间"})
		return
	}
	req.Source = strings.TrimSpace(req.Source)
	if req.Source == "" {
		req.Source = "manual"
	}
	if !validFlowSource(req.Source) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source 仅支持 burp、browser 或 manual"})
		return
	}
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	if req.ProjectID != "" && h.db != nil {
		if _, err := h.db.GetProject(req.ProjectID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "项目不存在"})
			return
		}
	}
	result := h.store.ImportFlows(req.ProjectID, req.Source, req.Flows)
	c.JSON(http.StatusOK, gin.H{"imported": result.Imported, "duplicates": result.Duplicates, "errors": result.Errors})
}

// List 检索流量：GET /api/http-flows
func (h *HTTPFlowHandler) List(c *gin.Context) {
	filter := traffic.QueryFilter{
		ProjectID: strings.TrimSpace(c.Query("project_id")),
		Q:         strings.TrimSpace(c.Query("q")),
		Host:      strings.TrimSpace(c.Query("host")),
		Method:    strings.TrimSpace(c.Query("method")),
		Tag:       strings.TrimSpace(c.Query("tag")),
	}
	if raw := strings.TrimSpace(c.Query("status")); raw != "" {
		status, err := strconv.Atoi(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "status 必须是整数"})
			return
		}
		filter.Status = &status
	}
	// limit/offset 与 status 同口径：非数字一律 400，不做静默回退
	var err error
	if filter.Limit, err = strictIntQuery(c, "limit", defaultFlowListLimit); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "limit 必须是整数"})
		return
	}
	if filter.Limit < 1 || filter.Limit > maxFlowListLimit {
		c.JSON(http.StatusBadRequest, gin.H{"error": "limit 必须在 1-200 之间"})
		return
	}
	if filter.Offset, err = strictIntQuery(c, "offset", 0); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset 必须是整数"})
		return
	}
	if filter.Offset < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset 不能为负"})
		return
	}
	items, total, err := h.store.Query(filter)
	if err != nil {
		h.logger.Error("查询流量失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "items": items})
}

// Get 单条详情：GET /api/http-flows/:id
func (h *HTTPFlowHandler) Get(c *gin.Context) {
	detail, err := h.store.Get(strings.TrimSpace(c.Param("id")))
	if errors.Is(err, traffic.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "流量不存在"})
		return
	}
	if err != nil {
		h.logger.Error("读取流量详情失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, detail)
}

// SetTags 更新标签：POST /api/http-flows/:id/tags
func (h *HTTPFlowHandler) SetTags(c *gin.Context) {
	var req setHTTPFlowTagsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.SetTags(strings.TrimSpace(c.Param("id")), req.Tags); err != nil {
		if errors.Is(err, traffic.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "流量不存在"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ClearProject 按项目清理：DELETE /api/http-flows?project_id=...
func (h *HTTPFlowHandler) ClearProject(c *gin.Context) {
	projectID := strings.TrimSpace(c.Query("project_id"))
	if projectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id 不能为空"})
		return
	}
	deleted, err := h.store.DeleteProject(projectID)
	if err != nil {
		h.logger.Error("清理项目流量失败", zap.String("project_id", projectID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

// strictIntQuery 解析整型查询参数：缺省返回 def，非数字报错（不静默回退）。
func strictIntQuery(c *gin.Context, key string, def int) (int, error) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return def, nil
	}
	return strconv.Atoi(raw)
}
