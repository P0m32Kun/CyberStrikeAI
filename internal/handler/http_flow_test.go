package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/traffic"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newHTTPFlowRouter(t *testing.T, withAuth bool) (*gin.Engine, *database.DB, *traffic.Store, *security.AuthManager) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "http-flows.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := traffic.Open(filepath.Join(t.TempDir(), "traffic"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	auth := security.NewAuthManager(1)
	h := NewHTTPFlowHandler(store, db, zap.NewNop())
	router := gin.New()
	if withAuth {
		router.Use(security.AuthMiddleware(auth))
	}
	api := router.Group("/api")
	api.POST("/http-flows", h.Import)
	api.GET("/http-flows", h.List)
	api.GET("/http-flows/:id", h.Get)
	api.POST("/http-flows/:id/tags", h.SetTags)
	api.DELETE("/http-flows", h.ClearProject)
	return router, db, store, auth
}

func doJSON(t *testing.T, router *gin.Engine, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHTTPFlowAPIRequiresAuth(t *testing.T) {
	router, _, _, _ := newHTTPFlowRouter(t, true)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/http-flows"},
		{http.MethodGet, "/api/http-flows"},
		{http.MethodGet, "/api/http-flows/some-id"},
		{http.MethodPost, "/api/http-flows/some-id/tags"},
		{http.MethodDelete, "/api/http-flows"},
	} {
		w := doJSON(t, router, tc.method, tc.path, gin.H{}, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without token = %d, want 401", tc.method, tc.path, w.Code)
		}
	}
}

func TestHTTPFlowAPIImportListGetTagsDelete(t *testing.T) {
	router, db, store, _ := newHTTPFlowRouter(t, false)

	project, err := db.CreateProject(&database.Project{Name: "Flow 项目", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}

	// 1. 导入：2 条新流量 + 1 条重复
	importBody := gin.H{
		"project_id": project.ID,
		"source":     "burp",
		"flows": []gin.H{
			{
				"ts": 1697000000000, "method": "GET", "url": "https://h.example/api/user?id=7", "status": 200,
				"content_type": "application/json", "req_headers": "GET /api/user?id=7 HTTP/1.1",
				"req_body": "", "resp_headers": "HTTP/1.1 200 OK", "resp_body": `{"token":"abc"}`,
			},
			{
				"ts": 1697000000001, "method": "POST", "url": "https://h.example/api/login", "status": 401,
				"content_type": "application/json", "req_headers": "POST /api/login HTTP/1.1",
				"req_body": `{"user":"admin"}`, "resp_headers": "HTTP/1.1 401", "resp_body": "unauthorized",
			},
			{
				"ts": 1697000000002, "method": "GET", "url": "https://h.example/api/user?id=7", "status": 200,
				"content_type": "application/json", "req_headers": "GET /api/user?id=7 HTTP/1.1",
				"req_body": "", "resp_headers": "HTTP/1.1 200 OK", "resp_body": `{"token":"abc"}`,
			},
		},
	}
	w := doJSON(t, router, http.MethodPost, "/api/http-flows", importBody, "")
	if w.Code != http.StatusOK {
		t.Fatalf("import status = %d: %s", w.Code, w.Body.String())
	}
	var importResp struct {
		Imported   int      `json:"imported"`
		Duplicates int      `json:"duplicates"`
		Errors     []string `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &importResp); err != nil {
		t.Fatal(err)
	}
	if importResp.Imported != 2 || importResp.Duplicates != 1 || len(importResp.Errors) != 0 {
		t.Fatalf("import resp = %+v", importResp)
	}

	// 导入到不存在的项目要被拒绝
	w = doJSON(t, router, http.MethodPost, "/api/http-flows", gin.H{
		"project_id": "no-such-project", "source": "manual",
		"flows": []gin.H{{"ts": 1, "method": "GET", "url": "https://x/y", "status": 200}},
	}, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("import into missing project = %d, want 400", w.Code)
	}

	// 2. 列表：过滤 + 分页字段
	w = doJSON(t, router, http.MethodGet, "/api/http-flows?project_id="+project.ID+"&host=h.example&method=POST", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d: %s", w.Code, w.Body.String())
	}
	var listResp struct {
		Total int               `json:"total"`
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.Total != 1 || len(listResp.Items) != 1 {
		t.Fatalf("list resp total=%d items=%d", listResp.Total, len(listResp.Items))
	}
	var item struct {
		ID          string   `json:"id"`
		TS          int64    `json:"ts"`
		Method      string   `json:"method"`
		URL         string   `json:"url"`
		URLTemplate string   `json:"url_template"`
		Host        string   `json:"host"`
		Status      int      `json:"status"`
		ContentType string   `json:"content_type"`
		ReqLen      int      `json:"req_len"`
		RespLen     int      `json:"resp_len"`
		Tags        []string `json:"tags"`
		Source      string   `json:"source"`
		ProjectID   string   `json:"project_id"`
	}
	if err := json.Unmarshal(listResp.Items[0], &item); err != nil {
		t.Fatal(err)
	}
	if item.Method != "POST" || item.Host != "h.example" || item.URLTemplate != "/api/login" ||
		item.Status != 401 || item.Source != "burp" || item.ProjectID != project.ID ||
		item.Tags == nil || item.ReqLen != len(`{"user":"admin"}`) {
		t.Fatalf("list item = %+v", item)
	}

	// 3. 详情：含四个预览字段
	w = doJSON(t, router, http.MethodGet, "/api/http-flows/"+item.ID, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d: %s", w.Code, w.Body.String())
	}
	var detail struct {
		ReqHeaders    string `json:"req_headers"`
		ReqBody       string `json:"req_body"`
		RespHeaders   string `json:"resp_headers"`
		RespBody      string `json:"resp_body"`
		BodyTruncated bool   `json:"body_truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.ReqBody != `{"user":"admin"}` || detail.RespBody != "unauthorized" || detail.BodyTruncated {
		t.Fatalf("detail = %+v", detail)
	}

	// 4. 打标签
	w = doJSON(t, router, http.MethodPost, "/api/http-flows/"+item.ID+"/tags", gin.H{"tags": []string{"auth-bypass", "retest"}}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("tags status = %d: %s", w.Code, w.Body.String())
	}
	var tagResp struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tagResp); err != nil || !tagResp.OK {
		t.Fatalf("tags resp = %s", w.Body.String())
	}
	// 标签过滤生效
	w = doJSON(t, router, http.MethodGet, "/api/http-flows?project_id="+project.ID+"&tag=auth-bypass", nil, "")
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.Total != 1 {
		t.Fatalf("tag filter total = %d", listResp.Total)
	}
	// 打在不存在流量上 → 404
	w = doJSON(t, router, http.MethodPost, "/api/http-flows/missing/tags", gin.H{"tags": []string{"x"}}, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("tags on missing flow = %d, want 404", w.Code)
	}

	// 5. 按项目清理
	w = doJSON(t, router, http.MethodDelete, "/api/http-flows?project_id="+project.ID, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d: %s", w.Code, w.Body.String())
	}
	var deleteResp struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &deleteResp); err != nil {
		t.Fatal(err)
	}
	if deleteResp.Deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleteResp.Deleted)
	}
	_, total, err := store.Query(traffic.QueryFilter{ProjectID: project.ID})
	if err != nil || total != 0 {
		t.Fatalf("store should be empty after cleanup, total=%d err=%v", total, err)
	}
	// 缺 project_id → 400
	w = doJSON(t, router, http.MethodDelete, "/api/http-flows", nil, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("delete without project_id = %d, want 400", w.Code)
	}

	// 非数字 limit/offset 与 status 同口径 → 400
	for _, bad := range []string{"limit=abc", "offset=xyz"} {
		w = doJSON(t, router, http.MethodGet, "/api/http-flows?"+bad, nil, "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", bad, w.Code)
		}
	}
}

func TestHTTPFlowAPIListSearchFallbackMatchesURL(t *testing.T) {
	router, db, _, _ := newHTTPFlowRouter(t, false)
	project, err := db.CreateProject(&database.Project{Name: "搜索项目", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, router, http.MethodPost, "/api/http-flows", gin.H{
		"project_id": project.ID, "source": "browser",
		"flows": []gin.H{{"ts": 1, "method": "GET", "url": "https://s.example/search?kw=needle123", "status": 200, "resp_body": "body"}},
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("import status = %d: %s", w.Code, w.Body.String())
	}
	w = doJSON(t, router, http.MethodGet, "/api/http-flows?project_id="+project.ID+"&q="+strings.TrimSpace("needle123"), nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("search status = %d", w.Code)
	}
	var listResp struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.Total != 1 {
		t.Fatalf("q search total = %d, want 1", listResp.Total)
	}
}
