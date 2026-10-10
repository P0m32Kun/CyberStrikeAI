package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

const appTestNmapXML = `<?xml version="1.0"?><nmaprun args="nmap -sT -sV 192.0.2.30">
<host><status state="up"/><address addr="192.0.2.30" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0"/></port>
</ports></host></nmaprun>`

func countAllAssets(t *testing.T, db *database.DB) int {
	t.Helper()
	_, total, err := db.ListAssets(100, 0, database.AssetListFilter{}, database.RBACListAccess{})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	return total
}

func setupNmapIngestTest(t *testing.T) (*database.DB, *authctx.Principal, *database.Project, *database.Conversation, context.Context) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "nmap-ingest.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("nmap-agent", "Nmap Agent", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	project, err := db.CreateProject(&database.Project{Name: "lab", Description: "nmap ingest test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "project", project.ID); err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("nmap ingest", database.ConversationCreateMeta{ProjectID: project.ID})
	if err != nil {
		t.Fatal(err)
	}
	principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAssigned, map[string]bool{
		"asset:read": true, "asset:write": true,
	})
	ctx := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), principal), conv.ID)
	return db, &principal, project, conv, ctx
}

func countAssetsInProject(t *testing.T, db *database.DB, projectID string) (int, []*database.Asset) {
	t.Helper()
	assets, total, err := db.ListAssets(100, 0, database.AssetListFilter{ProjectID: projectID}, database.RBACListAccess{})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	return total, assets
}

// 挂载点 A：nmap 执行成功回调自动入库，带对话的项目绑定 + 审计日志 + 重复扫描去重。
func TestNmapAutoIngestHookWritesProjectBoundAssets(t *testing.T) {
	db, principal, project, _, ctx := setupNmapIngestTest(t)
	xmlPath := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(xmlPath, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	auditSvc := audit.NewService(db, &config.Config{}, zap.NewNop())
	hook := nmapAutoIngestHook(db, auditSvc, zap.NewNop())

	note := hook(ctx, "nmap", map[string]interface{}{"target": "192.0.2.30"}, xmlPath)
	if !strings.Contains(note, "新增 2") {
		t.Fatalf("first ingest note should report 2 created, got: %q", note)
	}
	total, assets := countAssetsInProject(t, db, project.ID)
	if total != 2 {
		t.Fatalf("want 2 assets in project, got %d", total)
	}
	for _, asset := range assets {
		if asset.ProjectID != project.ID {
			t.Fatalf("asset not project-bound: %+v", asset)
		}
		if asset.Source != "nmap" {
			t.Fatalf("asset source: got %s want nmap", asset.Source)
		}
	}
	_ = principal

	// 审计日志应有自动入库记录。
	logs, err := db.ListAuditLogs(database.ListAuditLogsFilter{Action: "nmap_auto_ingest", ResourceType: "project", ResourceID: project.ID})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("want 1 auto-ingest audit row, got %d", len(logs))
	}

	// 重复扫描同一目标：不产生重复行。
	note2 := hook(ctx, "nmap", map[string]interface{}{"target": "192.0.2.30"}, xmlPath)
	if !strings.Contains(note2, "更新 2") || strings.Contains(note2, "新增 2") {
		t.Fatalf("repeated ingest note should report updates, got: %q", note2)
	}
	total2, _ := countAssetsInProject(t, db, project.ID)
	if total2 != 2 {
		t.Fatalf("repeated scan must not duplicate rows, got %d", total2)
	}
}

// 挂载点 A：无项目绑定的执行不写库。
func TestNmapAutoIngestHookSkipsWithoutProject(t *testing.T) {
	db, user, _, _, ctx := setupNmapIngestTest(t)
	unbound, err := db.CreateConversation("unbound", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	_ = user
	ctx = mcp.WithMCPConversationID(ctx, unbound.ID)
	xmlPath := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(xmlPath, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	hook := nmapAutoIngestHook(db, nil, zap.NewNop())

	note := hook(ctx, "nmap", nil, xmlPath)
	if note == "" || !strings.Contains(note, "未") {
		t.Fatalf("unprojected run should return skip note, got: %q", note)
	}
	if count := countAllAssets(t, db); count != 0 {
		t.Fatalf("no asset should be written without project binding, got %d", count)
	}
}

// 挂载点 A：非 nmap 工具不触发。
func TestNmapAutoIngestHookIgnoresOtherTools(t *testing.T) {
	db, _, project, _, ctx := setupNmapIngestTest(t)
	xmlPath := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(xmlPath, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	hook := nmapAutoIngestHook(db, nil, zap.NewNop())
	if note := hook(ctx, "subfinder", nil, xmlPath); note != "" {
		t.Fatalf("non-nmap tool should be ignored, got note: %q", note)
	}
	total, _ := countAssetsInProject(t, db, project.ID)
	if total != 0 {
		t.Fatalf("non-nmap tool must not write assets, got %d", total)
	}
}

// 挂载点 B：内置工具 ingest_nmap_xml 可注册并可调用（xml_content / xml_file / project 绑定）。
func TestIngestNmapXMLToolRegisteredAndCallable(t *testing.T) {
	db, _, project, conv, ctx := setupNmapIngestTest(t)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNmapIngestTools(server, db, nil, zap.NewNop())

	found := false
	for _, tool := range server.GetAllTools() {
		if tool.Name == builtin.ToolIngestNmapXML {
			found = true
		}
	}
	if !found {
		t.Fatalf("tool %s not registered", builtin.ToolIngestNmapXML)
	}

	// 1) xml_content + 显式 project_id。
	result, _, err := server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{
		"xml_content": appTestNmapXML, "project_id": project.ID,
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("ingest via content: result=%#v err=%v", result, err)
	}
	total, _ := countAssetsInProject(t, db, project.ID)
	if total != 2 {
		t.Fatalf("want 2 assets after tool ingest, got %d", total)
	}

	// 2) xml_file 路径导入 + 对话隐式项目绑定（不传 project_id）。
	xmlPath := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(xmlPath, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_file": xmlPath})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("ingest via file: result=%#v err=%v", result, err)
	}
	total, _ = countAssetsInProject(t, db, project.ID)
	if total != 2 {
		t.Fatalf("re-import via tool must dedup, got %d", total)
	}
	if !strings.Contains(result.Content[0].Text, "更新 2") {
		t.Fatalf("re-import should report updates, got: %q", result.Content[0].Text)
	}
	_ = conv

	// 3) 参数缺失报错。
	result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("missing input should be an error result: result=%#v err=%v", result, err)
	}

	// 4) 非法 XML 报错。
	result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{
		"xml_content": "not-xml", "project_id": project.ID,
	})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("invalid XML should be an error result: result=%#v err=%v", result, err)
	}
}

// 挂载点 B：无项目可解析（未绑定对话且未传 project_id）时拒绝入库。
func TestIngestNmapXMLToolRequiresProject(t *testing.T) {
	db, _, _, _, ctx := setupNmapIngestTest(t)
	unbound, err := db.CreateConversation("unbound", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := authctx.PrincipalFromContext(ctx)
	unboundCtx := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), principal), unbound.ID)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNmapIngestTools(server, db, nil, zap.NewNop())

	result, _, err := server.CallTool(unboundCtx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_content": appTestNmapXML})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("unprojected import should fail: result=%#v err=%v", result, err)
	}
	if count := countAllAssets(t, db); count != 0 {
		t.Fatalf("no asset should be written, got %d", count)
	}
}

// 挂载点 B：缺 asset:write 权限的用户被授权器拦截。
func TestIngestNmapXMLToolRequiresAssetWritePermission(t *testing.T) {
	db, principal, project, _, _ := setupNmapIngestTest(t)
	noPerm := authctx.NewPrincipal(principal.UserID, principal.Username, database.RBACScopeAssigned, map[string]bool{})
	ctx := authctx.WithPrincipal(context.Background(), noPerm)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNmapIngestTools(server, db, nil, zap.NewNop())

	_, _, err := server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{
		"xml_content": appTestNmapXML, "project_id": project.ID,
	})
	if err == nil || !strings.Contains(err.Error(), "asset:write") {
		t.Fatalf("expected asset:write authorization error, got: %v", err)
	}
}

// 挂载点 B：xml_file 路径白名单——仅允许系统临时目录内文件（执行器 -oX 临时产物）。
func TestIngestNmapXMLToolFilePathWhitelist(t *testing.T) {
	db, _, project, _, ctx := setupNmapIngestTest(t)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNmapIngestTools(server, db, nil, zap.NewNop())

	// 1) 系统临时目录内合法路径可读（t.TempDir() 位于 os.TempDir() 之下）。
	allowed := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(allowed, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	result, _, err := server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_file": allowed})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("tmp-internal file should be readable: result=%#v err=%v", result, err)
	}
	if total, _ := countAssetsInProject(t, db, project.ID); total != 2 {
		t.Fatalf("tmp-internal import should write 2 assets, got %d", total)
	}

	// 2) 系统敏感路径被拒，且错误信息说明约束（不回显文件内容）。
	for name, path := range map[string]string{
		"etc passwd":    "/etc/passwd",
		"home absolute": "/root/scan.xml",
	} {
		result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_file": path})
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("%s should be rejected: result=%#v err=%v", name, result, err)
		}
		if !strings.Contains(result.Content[0].Text, "xml_file") {
			t.Fatalf("%s rejection should explain the xml_file constraint, got: %q", name, result.Content[0].Text)
		}
	}

	// 3) 含 .. 的路径即使规范化后仍落在临时目录内也被拒。
	tmpBase := filepath.Base(strings.TrimRight(t.TempDir(), string(filepath.Separator)))
	dotdot := filepath.Join(t.TempDir(), "sub", "..", "..", tmpBase, "escape.xml")
	result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_file": dotdot})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("dotdot path should be rejected: result=%#v err=%v", result, err)
	}

	// 4) 与临时目录同前缀但不在其内的路径（/tmp-evil 型）不绕过。
	evilPrefix := strings.TrimRight(os.TempDir(), string(filepath.Separator)) + "-evil/scan.xml"
	result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_file": evilPrefix})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("sibling-prefix path must not bypass whitelist: result=%#v err=%v", result, err)
	}

	// 5) 临时目录内的符号链接指向临时目录外的实体文件：解析后复检，拒绝。
	targetDir := strings.TrimRight(os.TempDir(), string(filepath.Separator)) + "-nmap-symlink-target"
	target := filepath.Join(targetDir, "scan.xml")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(targetDir) })
	evilLink := filepath.Join(t.TempDir(), "evil-link.xml")
	if err := os.Symlink(target, evilLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_file": evilLink})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("symlink escaping tmp must be rejected: result=%#v err=%v", result, err)
	}

	// 6) 临时目录内的符号链接指向临时目录内文件：允许（解析后仍在白名单内）。
	realFile := filepath.Join(t.TempDir(), "real.xml")
	if err := os.WriteFile(realFile, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	okLink := filepath.Join(t.TempDir(), "ok-link.xml")
	if err := os.Symlink(realFile, okLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result, _, err = server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{"xml_file": okLink})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("symlink inside tmp should be allowed: result=%#v err=%v", result, err)
	}
}

// 应修1：挂载 A 跨项目隔离——同目标在两个项目各存一行，旧项目资产不迁移。
func TestNmapAutoIngestCrossProjectIsolation(t *testing.T) {
	db, principal, projectA, convA, ctxA := setupNmapIngestTest(t)
	projectB, err := db.CreateProject(&database.Project{Name: "engagement-b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(principal.UserID, "project", projectB.ID); err != nil {
		t.Fatal(err)
	}
	convB, err := db.CreateConversation("nmap ingest b", database.ConversationCreateMeta{ProjectID: projectB.ID})
	if err != nil {
		t.Fatal(err)
	}
	ctxB := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), *principal), convB.ID)
	xmlPath := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(xmlPath, []byte(appTestNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	hook := nmapAutoIngestHook(db, nil, zap.NewNop())

	if note := hook(ctxA, "nmap", nil, xmlPath); !strings.Contains(note, "新增 2") {
		t.Fatalf("project A ingest: %q", note)
	}
	_ = convA
	if note := hook(ctxB, "nmap", nil, xmlPath); !strings.Contains(note, "新增 2") {
		t.Fatalf("project B ingest should create its own rows, got: %q", note)
	}
	totalA, _ := countAssetsInProject(t, db, projectA.ID)
	totalB, _ := countAssetsInProject(t, db, projectB.ID)
	if totalA != 2 || totalB != 2 {
		t.Fatalf("cross-project isolation broken: projectA=%d projectB=%d", totalA, totalB)
	}
	// 同项目重复扫描仍去重（更新，不新增）。
	if note := hook(ctxA, "nmap", nil, xmlPath); !strings.Contains(note, "更新 2") {
		t.Fatalf("same-project rescan should update: %q", note)
	}
	totalA2, _ := countAssetsInProject(t, db, projectA.ID)
	if totalA2 != 2 {
		t.Fatalf("same-project rescan must not add rows, got %d", totalA2)
	}
}

// 应修2：全局 scope 走挂载 B 可更新他人 owner 的同键行（与 create_asset 同构）。
func TestIngestNmapXMLToolGlobalScopeUpdatesForeignRow(t *testing.T) {
	db, principal, project, _, _ := setupNmapIngestTest(t)
	// 他人 owner 先在同项目建同键行。
	other, err := db.CreateRBACUser("other-owner", "Other Owner", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign := &database.Asset{IP: "192.0.2.30", Port: 22, Protocol: "tcp", Source: "nmap", ProjectID: project.ID, Title: "foreign"}
	if _, err := db.UpsertAssetsInProject([]*database.Asset{foreign}, other.ID, project.ID); err != nil {
		t.Fatal(err)
	}
	// 管理员 scope=all：应更新该行而非 skip。
	admin := authctx.NewPrincipal(principal.UserID, principal.Username, database.RBACScopeAll, map[string]bool{"asset:read": true, "asset:write": true})
	adminCtx := authctx.WithPrincipal(context.Background(), admin)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNmapIngestTools(server, db, nil, zap.NewNop())

	result, _, err := server.CallTool(adminCtx, builtin.ToolIngestNmapXML, map[string]interface{}{
		"xml_content": appTestNmapXML, "project_id": project.ID,
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("global-scope ingest should succeed: result=%#v err=%v", result, err)
	}
	if !strings.Contains(result.Content[0].Text, "更新 1") || !strings.Contains(result.Content[0].Text, "新增 1") {
		t.Fatalf("global scope should update the foreign row and create the missing one, got: %q", result.Content[0].Text)
	}
	// 非 scope=all 的普通用户面对他人 owner 行应 skip（既有语义保持）。
	plainCtx := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), authctx.NewPrincipal(principal.UserID, principal.Username, database.RBACScopeAssigned, map[string]bool{"asset:write": true})), "")
	result2, _, err := server.CallTool(plainCtx, builtin.ToolIngestNmapXML, map[string]interface{}{
		"xml_content": appTestNmapXML, "project_id": project.ID,
	})
	if err != nil || result2 == nil || result2.IsError {
		t.Fatalf("assigned-scope ingest should still succeed for owned rows: result=%#v err=%v", result2, err)
	}
	if !strings.Contains(result2.Content[0].Text, "跳过 1") {
		t.Fatalf("assigned scope should skip the foreign-owned row, got: %q", result2.Content[0].Text)
	}
}

// nit4：xml_content 与 xml_file 同时提供报错（不静默忽略）。
func TestIngestNmapXMLToolRejectsBothInputs(t *testing.T) {
	db, _, _, _, ctx := setupNmapIngestTest(t)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerNmapIngestTools(server, db, nil, zap.NewNop())

	result, _, err := server.CallTool(ctx, builtin.ToolIngestNmapXML, map[string]interface{}{
		"xml_content": appTestNmapXML, "xml_file": "/tmp/whatever.xml",
	})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("both inputs should be rejected: result=%#v err=%v", result, err)
	}
	if !strings.Contains(result.Content[0].Text, "二选一") {
		t.Fatalf("rejection should say pick one, got: %q", result.Content[0].Text)
	}
}
