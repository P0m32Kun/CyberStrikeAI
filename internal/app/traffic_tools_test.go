package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/traffic"

	"go.uber.org/zap"
)

func newTrafficToolEnv(t *testing.T) (*mcp.Server, *traffic.Store, *database.DB) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "traffic-tools.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := traffic.Open(filepath.Join(t.TempDir(), "traffic"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerTrafficTools(server, store, db, zap.NewNop())
	return server, store, db
}

func trafficToolResult(t *testing.T, server *mcp.Server, ctx context.Context, tool string, args map[string]interface{}) string {
	t.Helper()
	result, _, err := server.CallTool(ctx, tool, args)
	if err != nil {
		t.Fatalf("%s err=%v", tool, err)
	}
	if result == nil || len(result.Content) == 0 {
		t.Fatalf("%s returned empty result", tool)
	}
	return result.Content[0].Text
}

func TestTrafficToolsRegistered(t *testing.T) {
	server, _, _ := newTrafficToolEnv(t)
	want := map[string]bool{
		builtin.ToolQueryHTTPFlows: false, builtin.ToolGetHTTPFlow: false,
		builtin.ToolTagHTTPFlow: false, builtin.ToolStartChatFromFlow: false,
	}
	for _, tool := range server.GetAllTools() {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("traffic tool not registered: %s", name)
		}
	}
}

func trafficPrincipalCtx(t *testing.T, db *database.DB) context.Context {
	t.Helper()
	user, err := db.CreateRBACUser("traffic-agent", "Traffic Agent", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAssigned, map[string]bool{
		"httpflow:read": true, "httpflow:write": true,
	})
	return authctx.WithPrincipal(context.Background(), principal)
}

func TestTrafficToolsQueryGetTagAndChat(t *testing.T) {
	server, store, db := newTrafficToolEnv(t)
	ctx := trafficPrincipalCtx(t, db)

	flows := []traffic.Flow{
		{TS: 1697000000000, Method: "GET", URL: "https://api.example/v1/user?id=7", Status: 200, ContentType: "application/json",
			ReqHeaders: "GET /v1/user?id=7 HTTP/1.1\nHost: api.example", RespHeaders: "HTTP/1.1 200 OK\nContent-Type: application/json",
			RespBody: `{"token":"abc123"}`},
		{TS: 1697000000001, Method: "POST", URL: "https://api.example/v1/login", Status: 401, ContentType: "application/json",
			ReqHeaders: "POST /v1/login HTTP/1.1", ReqBody: `{"user":"admin","password":"guess"}`,
			RespHeaders: "HTTP/1.1 401", RespBody: "unauthorized"},
	}
	if result := store.ImportFlows("proj-A", "burp", flows); result.Imported != 2 {
		t.Fatalf("import = %+v", result)
	}

	// query：host 过滤 + 分页文本
	text := trafficToolResult(t, server, ctx, builtin.ToolQueryHTTPFlows, map[string]interface{}{
		"project_id": "proj-A", "host": "api.example", "limit": 10, "offset": 0,
	})
	if !strings.Contains(text, "api.example") || !strings.Contains(text, "/v1/login") {
		t.Fatalf("query text missing flow info: %s", text)
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) != 3 { // 1 摘要行 + 2 条流量
		t.Fatalf("query should return 2 items + summary, got %d lines:\n%s", len(lines), text)
	}

	// get：单条详情
	items, _, err := store.Query(traffic.QueryFilter{ProjectID: "proj-A", Method: "POST"})
	if err != nil || len(items) != 1 {
		t.Fatalf("store query err=%v len=%d", err, len(items))
	}
	detailText := trafficToolResult(t, server, ctx, builtin.ToolGetHTTPFlow, map[string]interface{}{"id": items[0].ID})
	if !strings.Contains(detailText, items[0].ID) || !strings.Contains(detailText, "admin") || !strings.Contains(detailText, "req_body") {
		t.Fatalf("get detail missing content: %s", detailText)
	}

	// tag：更新后可按标签过滤
	if text := trafficToolResult(t, server, ctx, builtin.ToolTagHTTPFlow, map[string]interface{}{"id": items[0].ID, "tags": []interface{}{"auth-bypass"}}); !strings.Contains(text, "已更新") {
		t.Fatalf("tag result: %s", text)
	}
	tagged, total, err := store.Query(traffic.QueryFilter{ProjectID: "proj-A", Tag: "auth-bypass"})
	if err != nil || total != 1 || len(tagged) != 1 {
		t.Fatalf("tag not persisted, total=%d err=%v", total, err)
	}

	// start_chat_from_flow：插件兼容格式
	chatText := trafficToolResult(t, server, ctx, builtin.ToolStartChatFromFlow, map[string]interface{}{"id": items[0].ID})
	for _, want := range []string{"[Target]", "[Request]", "POST https://api.example/v1/login", `{"user":"admin"`, "[Optional: Response (truncated)]", "unauthorized"} {
		if !strings.Contains(chatText, want) {
			t.Fatalf("chat text missing %q:\n%s", want, chatText)
		}
	}

	// 不存在的流量
	result, _, err := server.CallTool(ctx, builtin.ToolGetHTTPFlow, map[string]interface{}{"id": "missing"})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("get missing flow should be error result: %#v err=%v", result, err)
	}
}

func TestTrafficToolsProjectScopeFromConversation(t *testing.T) {
	server, store, db := newTrafficToolEnv(t)

	projectA, err := db.CreateProject(&database.Project{Name: "流量项目 A", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := db.CreateProject(&database.Project{Name: "流量项目 B", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if result := store.ImportFlows(projectA.ID, "burp", []traffic.Flow{{TS: 1, Method: "GET", URL: "https://a.example/x", Status: 200}}); result.Imported != 1 {
		t.Fatalf("import A = %+v", result)
	}
	if result := store.ImportFlows(projectB.ID, "burp", []traffic.Flow{{TS: 2, Method: "GET", URL: "https://b.example/y", Status: 200}}); result.Imported != 1 {
		t.Fatalf("import B = %+v", result)
	}
	conv, err := db.CreateConversation("scoped", database.ConversationCreateMeta{ProjectID: projectA.ID})
	if err != nil {
		t.Fatal(err)
	}
	ctx := mcp.WithMCPConversationID(trafficPrincipalCtx(t, db), conv.ID)

	// 显式请求 proj-B 也必须被会话项目边界覆盖
	text := trafficToolResult(t, server, ctx, builtin.ToolQueryHTTPFlows, map[string]interface{}{"project_id": projectB.ID})
	if strings.Contains(text, "b.example") {
		t.Fatalf("conversation bound to proj-A leaked proj-B flows: %s", text)
	}
	if !strings.Contains(text, "a.example") {
		t.Fatalf("conversation project flows missing: %s", text)
	}

	// get 其他项目流量 → 报不存在
	items, _, err := store.Query(traffic.QueryFilter{ProjectID: projectB.ID})
	if err != nil || len(items) != 1 {
		t.Fatalf("proj-B query err=%v", err)
	}
	result, _, err := server.CallTool(ctx, builtin.ToolGetHTTPFlow, map[string]interface{}{"id": items[0].ID})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("cross-project get must be rejected: %#v err=%v", result, err)
	}
}

// TestTrafficToolsFailClosedWhenScopeUnresolvable 删除会话使项目边界查询出错：
// get/tag/chat 三处必须 fail-closed 报错，不得跳过项目校验放行。
func TestTrafficToolsFailClosedWhenScopeUnresolvable(t *testing.T) {
	server, store, db := newTrafficToolEnv(t)
	project, err := db.CreateProject(&database.Project{Name: "边界项目", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if result := store.ImportFlows(project.ID, "burp", []traffic.Flow{{TS: 1, Method: "GET", URL: "https://s.example/a", Status: 200}}); result.Imported != 1 {
		t.Fatalf("import = %+v", result)
	}
	items, _, err := store.Query(traffic.QueryFilter{ProjectID: project.ID})
	if err != nil || len(items) != 1 {
		t.Fatalf("query err=%v len=%d", err, len(items))
	}
	conv, err := db.CreateConversation("to-be-deleted", database.ConversationCreateMeta{ProjectID: project.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteConversation(conv.ID); err != nil {
		t.Fatal(err)
	}
	ctx := mcp.WithMCPConversationID(trafficPrincipalCtx(t, db), conv.ID)

	cases := []struct {
		tool string
		args map[string]interface{}
	}{
		{builtin.ToolGetHTTPFlow, map[string]interface{}{"id": items[0].ID}},
		{builtin.ToolTagHTTPFlow, map[string]interface{}{"id": items[0].ID, "tags": []interface{}{"x"}}},
		{builtin.ToolStartChatFromFlow, map[string]interface{}{"id": items[0].ID}},
		{builtin.ToolQueryHTTPFlows, map[string]interface{}{}},
	}
	for _, tc := range cases {
		result, _, err := server.CallTool(ctx, tc.tool, tc.args)
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("%s with unresolvable scope must fail closed: result=%#v err=%v", tc.tool, result, err)
		}
		if !strings.Contains(result.Content[0].Text, "项目范围") {
			t.Fatalf("%s error should mention scope failure, got: %s", tc.tool, result.Content[0].Text)
		}
	}
}
