package security

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

const fakeNmapXML = `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`

// writeFakeNmapScript 生成一个假的 nmap 可执行脚本：解析 -oX 参数，
// 把 fixture XML 拷到该路径（模拟 nmap -oX 行为），并输出一段 stdout。
// mode=exit1 时脚本以退出码 1 结束，模拟执行失败。
func writeFakeNmapScript(t *testing.T, fixturePath string, mode string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-nmap.sh")
	body := `#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-oX" ]; then out="$a"; fi
  prev="$a"
done
if [ -n "$out" ]; then cp "` + fixturePath + `" "$out"; fi
echo "fake nmap scan output"
`
	if mode == "exit1" {
		body += "exit 1\n"
	}
	if err := os.WriteFile(script, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return script
}

func newNmapCaptureExecutor(t *testing.T, command string) *Executor {
	t.Helper()
	cfg := &config.SecurityConfig{Tools: []config.ToolConfig{
		{Name: "nmap", Command: command, Enabled: true, ShortDescription: "fake nmap"},
	}}
	return NewExecutor(cfg, mcp.NewServer(zap.NewNop()), zap.NewNop())
}

func TestExecuteToolNmapSuccessInvokesHookWithXML(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "fixture.xml")
	if err := os.WriteFile(fixture, []byte(fakeNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	executor := newNmapCaptureExecutor(t, writeFakeNmapScript(t, fixture, ""))

	var mu sync.Mutex
	var calls []struct {
		toolName string
		path     string
		content  string
	}
	executor.SetToolSuccessHook(func(ctx context.Context, toolName string, args map[string]interface{}, xmlOutputPath string) string {
		data, _ := os.ReadFile(xmlOutputPath)
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, struct {
			toolName string
			path     string
			content  string
		}{toolName, xmlOutputPath, string(data)})
		return "[test] ingested"
	})

	result, err := executor.ExecuteTool(context.Background(), "nmap", map[string]interface{}{"target": "127.0.0.1"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("ExecuteTool nmap: result=%#v err=%v", result, err)
	}
	if len(calls) != 1 {
		t.Fatalf("success hook calls: got %d want 1", len(calls))
	}
	if calls[0].toolName != "nmap" {
		t.Fatalf("hook toolName: got %s want nmap", calls[0].toolName)
	}
	if calls[0].content != fakeNmapXML {
		t.Fatalf("hook XML content mismatch: got %q", calls[0].content)
	}
	if !strings.Contains(result.Content[0].Text, "[test] ingested") {
		t.Fatalf("tool result should append hook note, got: %q", result.Content[0].Text)
	}
	// 临时文件在执行结束后必须被删除。
	if _, statErr := os.Stat(calls[0].path); !os.IsNotExist(statErr) {
		t.Fatalf("temp XML should be removed after execution, path=%s statErr=%v", calls[0].path, statErr)
	}
}

func TestExecuteToolNmapFailureSkipsHook(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "fixture.xml")
	if err := os.WriteFile(fixture, []byte(fakeNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	executor := newNmapCaptureExecutor(t, writeFakeNmapScript(t, fixture, "exit1"))

	hookCalled := false
	executor.SetToolSuccessHook(func(ctx context.Context, toolName string, args map[string]interface{}, xmlOutputPath string) string {
		hookCalled = true
		return ""
	})
	result, err := executor.ExecuteTool(context.Background(), "nmap", map[string]interface{}{"target": "127.0.0.1"})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("exit-1 run should be an error result: %#v", result)
	}
	if hookCalled {
		t.Fatal("success hook must not fire for failed execution")
	}
}

func TestExecuteToolNonNmapDoesNotInvokeHook(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "fixture.xml")
	if err := os.WriteFile(fixture, []byte(fakeNmapXML), 0644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-other.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho other\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.SecurityConfig{Tools: []config.ToolConfig{
		{Name: "otherscan", Command: script, Enabled: true},
	}}
	executor := NewExecutor(cfg, mcp.NewServer(zap.NewNop()), zap.NewNop())
	hookCalled := false
	executor.SetToolSuccessHook(func(ctx context.Context, toolName string, args map[string]interface{}, xmlOutputPath string) string {
		hookCalled = true
		return ""
	})
	result, err := executor.ExecuteTool(context.Background(), "otherscan", map[string]interface{}{"target": "127.0.0.1"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("ExecuteTool otherscan: result=%#v err=%v", result, err)
	}
	if hookCalled {
		t.Fatal("hook must only fire for nmap XML capture")
	}
}
