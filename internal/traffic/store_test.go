package traffic

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"go.uber.org/zap"
)

func openTestStore(t *testing.T, opts ...Option) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "traffic"), zap.NewNop(), opts...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleFlow(url string) Flow {
	return Flow{
		TS:          1697000000000,
		Method:      "GET",
		URL:         url,
		Status:      200,
		ReqHeaders:  "GET /p?x=1 HTTP/1.1\nHost: h.example",
		RespHeaders: "HTTP/1.1 200 OK\nContent-Type: text/html",
		RespBody:    "<html>secret-token-body</html>",
	}
}

func TestImportDedupsSameContentPerProject(t *testing.T) {
	store := openTestStore(t)
	flow := sampleFlow("https://h.example/p?x=1")

	first := store.ImportFlows("proj-1", "burp", []Flow{flow})
	if first.Imported != 1 || first.Duplicates != 0 || len(first.Errors) != 0 {
		t.Fatalf("first import = %+v", first)
	}
	again := store.ImportFlows("proj-1", "browser", []Flow{flow})
	if again.Imported != 0 || again.Duplicates != 1 {
		t.Fatalf("re-import should count duplicate, got %+v", again)
	}
	other := store.ImportFlows("proj-2", "burp", []Flow{flow})
	if other.Imported != 1 || other.Duplicates != 0 {
		t.Fatalf("same content in another project is a new row, got %+v", other)
	}

	items, total, err := store.Query(QueryFilter{ProjectID: "proj-1"})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("proj-1 total=%d items=%d err=%v", total, len(items), err)
	}
	if items[0].Source != "burp" {
		t.Fatalf("duplicate re-import must not overwrite source, got %q", items[0].Source)
	}
	items, total, err = store.Query(QueryFilter{ProjectID: "proj-2"})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("proj-2 total=%d err=%v", total, err)
	}
}

func TestImportNormalizesURLTemplateAndHost(t *testing.T) {
	store := openTestStore(t)
	result := store.ImportFlows("p", "manual", []Flow{sampleFlow("https://H.example:8443/p?x=1&y=2")})
	if result.Imported != 1 {
		t.Fatalf("import = %+v", result)
	}
	items, _, err := store.Query(QueryFilter{})
	if err != nil || len(items) != 1 {
		t.Fatalf("query err=%v items=%d", err, len(items))
	}
	if items[0].URLTemplate != "/p" {
		t.Fatalf("url_template = %q, want /p", items[0].URLTemplate)
	}
	if items[0].Host != "h.example" {
		t.Fatalf("host = %q, want h.example", items[0].Host)
	}
	if items[0].URL != "https://H.example:8443/p?x=1&y=2" {
		t.Fatalf("url must keep original value, got %q", items[0].URL)
	}
}

func TestQueryFiltersPaginationAndTotal(t *testing.T) {
	store := openTestStore(t)
	flows := []Flow{
		sampleFlow("https://a.example/one"),
		sampleFlow("https://a.example/two"),
		sampleFlow("https://b.example/three"),
		{TS: 1697000000001, Method: "POST", URL: "https://a.example/four", Status: 500, RespBody: "boom"},
	}
	if result := store.ImportFlows("p1", "burp", flows); result.Imported != 4 {
		t.Fatalf("import = %+v", result)
	}
	if result := store.ImportFlows("p2", "burp", []Flow{sampleFlow("https://a.example/other")}); result.Imported != 1 {
		t.Fatalf("import p2 = %+v", result)
	}

	status500 := 500
	cases := []struct {
		name   string
		filter QueryFilter
		want   int
	}{
		{"project", QueryFilter{ProjectID: "p1"}, 4},
		{"host", QueryFilter{ProjectID: "p1", Host: "a.example"}, 3},
		{"method", QueryFilter{ProjectID: "p1", Method: "POST"}, 1},
		{"status", QueryFilter{ProjectID: "p1", Status: &status500}, 1},
		{"limit", QueryFilter{ProjectID: "p1", Limit: 2}, 4},
	}
	for _, tc := range cases {
		items, total, err := store.Query(tc.filter)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want {
			t.Fatalf("%s: total=%d want %d", tc.name, total, tc.want)
		}
		if tc.filter.Limit > 0 && len(items) > tc.filter.Limit {
			t.Fatalf("%s: page returned %d > limit %d", tc.name, len(items), tc.filter.Limit)
		}
	}

	firstPage, _, err := store.Query(QueryFilter{ProjectID: "p1", Limit: 2})
	if err != nil || len(firstPage) != 2 {
		t.Fatalf("first page err=%v len=%d", err, len(firstPage))
	}
	if firstPage[0].Method != "POST" || firstPage[0].Status != 500 {
		t.Fatalf("default order should be ts desc, got %+v", firstPage[0])
	}
	items, _, err := store.Query(QueryFilter{ProjectID: "p1", Limit: 2, Offset: 2})
	if err != nil || len(items) != 2 {
		t.Fatalf("offset page err=%v len=%d", err, len(items))
	}
	if items[0].Method != "GET" {
		t.Fatalf("offset page should start after POST, got %+v", items[0])
	}
}

func TestSetTagsThenFilterByTag(t *testing.T) {
	store := openTestStore(t)
	result := store.ImportFlows("p", "manual", []Flow{sampleFlow("https://h.example/p")})
	if result.Imported != 1 {
		t.Fatalf("import = %+v", result)
	}
	items, _, err := store.Query(QueryFilter{})
	if err != nil || len(items) != 1 {
		t.Fatalf("query err=%v", err)
	}
	if err := store.SetTags(items[0].ID, []string{"revisit", "auth"}); err != nil {
		t.Fatalf("SetTags: %v", err)
	}
	tagged, total, err := store.Query(QueryFilter{Tag: "revisit"})
	if err != nil || total != 1 || len(tagged) != 1 {
		t.Fatalf("tag filter total=%d err=%v", total, err)
	}
	if len(tagged[0].Tags) != 2 {
		t.Fatalf("tags = %v", tagged[0].Tags)
	}
	if err := store.SetTags("missing-id", []string{"x"}); err != ErrNotFound {
		t.Fatalf("SetTags on missing id = %v, want ErrNotFound", err)
	}
}

func TestGetReturnsPreviewAndTruncationFlag(t *testing.T) {
	store := openTestStore(t)
	small := sampleFlow("https://h.example/small")
	big := sampleFlow("https://h.example/big")
	big.RespBody = "<html>" + strings.Repeat("A", 20*1024) + "secret-token-body</html>"
	if result := store.ImportFlows("p", "manual", []Flow{small, big}); result.Imported != 2 {
		t.Fatalf("import = %+v", result)
	}
	items, _, err := store.Query(QueryFilter{Host: "h.example"})
	if err != nil || len(items) != 2 {
		t.Fatalf("query err=%v", err)
	}
	var smallDetail, bigDetail *FlowDetail
	for _, item := range items {
		detail, err := store.Get(item.ID)
		if err != nil {
			t.Fatalf("Get %s: %v", item.ID, err)
		}
		switch detail.URL {
		case small.URL:
			smallDetail = detail
		case big.URL:
			bigDetail = detail
		}
	}
	if smallDetail == nil || bigDetail == nil {
		t.Fatalf("details not found: %+v %+v", smallDetail, bigDetail)
	}
	if smallDetail.RespBody != small.RespBody || smallDetail.BodyTruncated {
		t.Fatalf("small body must be returned in full without truncation flag")
	}
	if bigDetail.RespLen != len(big.RespBody) {
		t.Fatalf("resp_len = %d want %d", bigDetail.RespLen, len(big.RespBody))
	}
	if len(bigDetail.RespBody) > previewCap {
		t.Fatalf("preview len = %d > cap %d", len(bigDetail.RespBody), previewCap)
	}
	if !bigDetail.BodyTruncated {
		t.Fatalf("big body must set body_truncated")
	}

	// CJK 大正文：预览按字节封顶且不切半个字符
	cjk := sampleFlow("https://h.example/cjk")
	cjk.RespBody = strings.Repeat("密", 12*1024) // 36KB 字节
	if result := store.ImportFlows("p", "manual", []Flow{cjk}); result.Imported != 1 {
		t.Fatalf("import cjk = %+v", result)
	}
	items, _, err = store.Query(QueryFilter{Host: "h.example", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.URL == cjk.URL {
			detail, err := store.Get(item.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(detail.RespBody) > previewCap {
				t.Fatalf("cjk preview bytes = %d > cap %d", len(detail.RespBody), previewCap)
			}
			for _, r := range detail.RespBody {
				if r == utf8.RuneError {
					t.Fatalf("cjk preview contains broken rune boundary")
				}
			}
			if !detail.BodyTruncated {
				t.Fatalf("cjk body must set body_truncated")
			}
		}
	}
	if _, err := store.Get("missing"); err != ErrNotFound {
		t.Fatalf("Get missing = %v want ErrNotFound", err)
	}
}

func TestLargeBodySpillsToContentAddressedBlob(t *testing.T) {
	store := openTestStore(t)
	blobDir := filepath.Join(store.Dir(), "blobs")

	large := strings.Repeat("Z", 300*1024) // > 256KB inline cutoff
	flowA := sampleFlow("https://h.example/download-a")
	flowA.RespBody = large
	flowB := sampleFlow("https://h.example/download-b")
	flowB.RespBody = large

	result := store.ImportFlows("p", "burp", []Flow{flowA, flowB})
	if result.Imported != 2 || len(result.Errors) != 0 {
		t.Fatalf("import = %+v", result)
	}

	sum := sha256.Sum256([]byte(large))
	wantPath := filepath.Join(blobDir, hex.EncodeToString(sum[:])[:2], hex.EncodeToString(sum[:]))
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected deduped blob at %s: %v", wantPath, err)
	}
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	blobFiles := 0
	var firstDir string
	for _, e := range entries {
		firstDir = e.Name()
		inner, err := os.ReadDir(filepath.Join(blobDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		blobFiles += len(inner)
	}
	_ = firstDir
	if blobFiles != 1 {
		t.Fatalf("two identical large bodies must share one blob file, found %d", blobFiles)
	}

	items, _, err := store.Query(QueryFilter{ProjectID: "p"})
	if err != nil || len(items) != 2 {
		t.Fatalf("query err=%v len=%d", err, len(items))
	}
	for _, item := range items {
		if item.RespLen != len(large) {
			t.Fatalf("resp_len = %d want full length %d", item.RespLen, len(large))
		}
		detail, err := store.Get(item.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(detail.RespBody) != previewCap || !detail.BodyTruncated {
			t.Fatalf("spilled body must return %d-byte preview with truncation flag", previewCap)
		}
	}
}

func TestDeleteProjectCleansFlowsBodiesAndBlobs(t *testing.T) {
	store := openTestStore(t)
	large := strings.Repeat("Q", 260*1024)
	keep := sampleFlow("https://keep.example/api")
	keep.RespBody = large
	doom := sampleFlow("https://doom.example/api")
	doom.RespBody = large // 同一大正文，blob 被两个项目的流量共享
	doom2 := sampleFlow("https://doom.example/other")
	doom2.RespBody = strings.Repeat("W", 300*1024)

	if result := store.ImportFlows("keep-proj", "burp", []Flow{keep}); result.Imported != 1 {
		t.Fatalf("import keep = %+v", result)
	}
	if result := store.ImportFlows("doom-proj", "burp", []Flow{doom, doom2}); result.Imported != 2 {
		t.Fatalf("import doom = %+v", result)
	}

	deleted, err := store.DeleteProject("doom-proj")
	if err != nil || deleted != 2 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	_, total, err := store.Query(QueryFilter{ProjectID: "doom-proj"})
	if err != nil || total != 0 {
		t.Fatalf("doom-proj should be empty, total=%d err=%v", total, err)
	}
	_, total, err = store.Query(QueryFilter{ProjectID: "keep-proj"})
	if err != nil || total != 1 {
		t.Fatalf("keep-proj must survive, total=%d err=%v", total, err)
	}

	blobDir := filepath.Join(store.Dir(), "blobs")
	blobFiles := 0
	var survived string
	_ = filepath.Walk(blobDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			blobFiles++
			survived = path
		}
		return nil
	})
	if blobFiles != 1 {
		t.Fatalf("only the still-referenced blob must survive, found %d", blobFiles)
	}
	sum := sha256.Sum256([]byte(large))
	if !strings.HasSuffix(survived, hex.EncodeToString(sum[:])) {
		t.Fatalf("surviving blob %s is not the shared one", survived)
	}
}

// TestImportRemovesMainRowWhenBodiesFail 用 DROP TABLE 注入正文写入失败：
// 主表行必须被补偿删除，否则留下「列表可见、详情 404、重试永远算
// duplicates」的幽灵行（content_hash 已占用）。
func TestImportRemovesMainRowWhenBodiesFail(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.db.Exec(`DROP TABLE http_flow_bodies`); err != nil {
		t.Fatal(err)
	}
	flow := sampleFlow("https://h.example/ghost")
	result := store.ImportFlows("p", "burp", []Flow{flow})
	if result.Imported != 0 || result.Duplicates != 0 || len(result.Errors) != 1 {
		t.Fatalf("import result = %+v", result)
	}
	items, total, err := store.Query(QueryFilter{ProjectID: "p"})
	if err != nil || total != 0 || len(items) != 0 {
		t.Fatalf("ghost main row leaked: total=%d items=%d err=%v", total, len(items), err)
	}

	// 表恢复后同内容重导必须成功（若幽灵行残留，这里会报 duplicates）
	if _, err := store.db.Exec(`CREATE TABLE IF NOT EXISTS http_flow_bodies (
		id           TEXT PRIMARY KEY REFERENCES http_flows(id) ON DELETE CASCADE,
		req_headers  TEXT NOT NULL DEFAULT '',
		req_body     TEXT,
		req_blob     TEXT,
		resp_headers TEXT NOT NULL DEFAULT '',
		resp_body    TEXT,
		resp_blob    TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	retry := store.ImportFlows("p", "burp", []Flow{flow})
	if retry.Imported != 1 || retry.Duplicates != 0 {
		t.Fatalf("retry after transient bodies failure = %+v, want imported=1", retry)
	}
}

// TestImportRemovesMainRowWhenBlobRefsFail 同上，注入 blob_refs 写入失败。
func TestImportRemovesMainRowWhenBlobRefsFail(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.db.Exec(`DROP TABLE blob_refs`); err != nil {
		t.Fatal(err)
	}
	flow := sampleFlow("https://h.example/ghost-blob")
	flow.RespBody = strings.Repeat("B", 300*1024) // 触发溢出，必写 blob_refs
	result := store.ImportFlows("p", "burp", []Flow{flow})
	if result.Imported != 0 || result.Duplicates != 0 || len(result.Errors) != 1 {
		t.Fatalf("import result = %+v", result)
	}
	_, total, err := store.Query(QueryFilter{ProjectID: "p"})
	if err != nil || total != 0 {
		t.Fatalf("ghost main row leaked: total=%d err=%v", total, err)
	}

	if _, err := store.db.Exec(`CREATE TABLE IF NOT EXISTS blob_refs (
		hash    TEXT NOT NULL,
		flow_id TEXT NOT NULL,
		PRIMARY KEY (hash, flow_id)
	)`); err != nil {
		t.Fatal(err)
	}
	retry := store.ImportFlows("p", "burp", []Flow{flow})
	if retry.Imported != 1 || retry.Duplicates != 0 {
		t.Fatalf("retry after transient blob_refs failure = %+v, want imported=1", retry)
	}
}

// TestIndexTextIncludesContentType 白盒断言：FTS 索引文本必须覆盖降级 LIKE
// 模式可命中的元数据（content_type），否则启用 FTS 反而缩小搜索面。
func TestIndexTextIncludesContentType(t *testing.T) {
	flow := sampleFlow("https://h.example/ct")
	flow.ContentType = "application/vnd.api+custom"
	if got := indexText(flow); !strings.Contains(got, "application/vnd.api+custom") {
		t.Fatalf("indexText missing content_type: %q", got)
	}
	if got := indexText(flow); !strings.Contains(got, "h.example") {
		t.Fatalf("indexText missing host: %q", got)
	}
}

// TestFTSSearchMatchesContentType FTS 模式下仅出现在 content_type 的检索词要能命中。
func TestFTSSearchMatchesContentType(t *testing.T) {
	store := openTestStore(t)
	if !store.FTSAvailable() {
		t.Skip("构建未启用 sqlite_fts5，FTS 路径由降级测试覆盖")
	}
	flow := sampleFlow("https://h.example/api/export")
	flow.ContentType = "application/x-unique-ct"
	if result := store.ImportFlows("p", "burp", []Flow{flow}); result.Imported != 1 {
		t.Fatalf("import = %+v", result)
	}
	_, total, err := store.Query(QueryFilter{Q: "x-unique-ct"})
	if err != nil || total != 1 {
		t.Fatalf("FTS must match content_type-only term, total=%d err=%v", total, err)
	}
}

// TestSetTagsLimitsByRuneCount 标签长度上限按字符（rune）计。
func TestSetTagsLimitsByRuneCount(t *testing.T) {
	store := openTestStore(t)
	if result := store.ImportFlows("p", "manual", []Flow{sampleFlow("https://h.example/tags")}); result.Imported != 1 {
		t.Fatalf("import = %+v", result)
	}
	items, _, err := store.Query(QueryFilter{})
	if err != nil || len(items) != 1 {
		t.Fatalf("query err=%v", err)
	}
	if err := store.SetTags(items[0].ID, []string{strings.Repeat("密", 100)}); err != nil {
		t.Fatalf("100 个 CJK 字符的标签必须通过: %v", err)
	}
	if err := store.SetTags(items[0].ID, []string{strings.Repeat("密", 101)}); err == nil {
		t.Fatalf("101 个 CJK 字符的标签必须被拒绝")
	}
}

func TestSearchFallsBackToMetadataWithoutFTS(t *testing.T) {
	store := openTestStore(t, WithDisableFTS())
	if store.FTSAvailable() {
		t.Fatalf("FTS must be disabled by option")
	}
	flow := sampleFlow("https://h.example/search?kw=needle")
	if result := store.ImportFlows("p", "burp", []Flow{flow}); result.Imported != 1 {
		t.Fatalf("import = %+v", result)
	}
	items, total, err := store.Query(QueryFilter{Q: "needle"})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("metadata LIKE search failed: total=%d err=%v", total, err)
	}
	// 降级模式下正文不被全文索引，检索仅覆盖元数据
	_, total, err = store.Query(QueryFilter{Q: "secret-token-body"})
	if err != nil || total != 0 {
		t.Fatalf("degraded search must not match body-only terms, total=%d err=%v", total, err)
	}
}

func TestFullTextSearchWhenFTSAvailable(t *testing.T) {
	store := openTestStore(t)
	if !store.FTSAvailable() {
		t.Skip("构建未启用 sqlite_fts5，FTS 路径由降级测试覆盖")
	}
	flow := sampleFlow("https://h.example/login")
	flow.RespBody = "<html>token=P@ssw0rd-leaked in body</html>"
	if result := store.ImportFlows("p", "burp", []Flow{flow}); result.Imported != 1 {
		t.Fatalf("import = %+v", result)
	}
	items, total, err := store.Query(QueryFilter{Q: "ssw0rd-lea"}) // trigram 子串
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("FTS substring search failed: total=%d err=%v", total, err)
	}

	// 清理后 FTS 行必须同步删除，避免命中已删内容
	if _, err := store.DeleteProject("p"); err != nil {
		t.Fatal(err)
	}
	_, total, err = store.Query(QueryFilter{Q: "ssw0rd-lea"})
	if err != nil || total != 0 {
		t.Fatalf("FTS rows must be removed with project cleanup, total=%d err=%v", total, err)
	}
}

func TestImportRejectsFlowWithoutMethodOrURL(t *testing.T) {
	store := openTestStore(t)
	result := store.ImportFlows("p", "manual", []Flow{{TS: 1, URL: "https://h/x"}, {TS: 2, Method: "GET"}})
	if result.Imported != 0 || result.Duplicates != 0 || len(result.Errors) != 2 {
		t.Fatalf("result = %+v", result)
	}
}
