// Package traffic 提供通用 HTTP 流量的存储与检索：独立 SQLite 索引库
// （index.sqlite）+ 内容寻址 blob 文件树（blobs/），不进主业务库。
// 设计要点（干净重写，未参考第三方实现代码）：
//   - 元数据与正文分表；正文 ≤256KB inline，超出溢出到 sha256 寻址 blob
//   - 同项目内按内容哈希去重，重复导入只计数不翻倍
//   - FTS5 trigram 全文索引单独应用；驱动不含 FTS5 时降级为仅元数据 LIKE 搜索
//   - url_template 剥 query 归一，(host, url_template) 聚合索引
package traffic

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

const (
	// maxInlineBody 是正文 inline 存储与溢出 blob 的分界。
	maxInlineBody = 256 * 1024
	// previewCap 是 Get 详情接口返回的每个正文字段的截断预览上限；
	// 溢出到 blob 的正文保留该长度的 inline 预览，便于识别内容形态。
	previewCap = 8 * 1024
	// maxIndexBody 限制单个正文对全文索引的贡献，防止超大正文拖垮索引。
	maxIndexBody = 4 * 1024 * 1024
	// minFTSTermRunes 是 trigram 分词器可匹配的最短词长，更短的查询走元数据 LIKE。
	minFTSTermRunes = 3
	// maxTagsPerFlow 限制单条流量的标签数。
	maxTagsPerFlow = 50
)

// ErrNotFound 表示按 ID 未命中。
var ErrNotFound = errors.New("http flow not found")

// indexSchema 是基础 schema；FTS schema 单独应用以便优雅降级。
const indexSchema = `
CREATE TABLE IF NOT EXISTS http_flows (
  id           TEXT PRIMARY KEY,
  ts           INTEGER NOT NULL DEFAULT 0,
  method       TEXT NOT NULL DEFAULT '',
  url          TEXT NOT NULL DEFAULT '',
  url_template TEXT NOT NULL DEFAULT '',
  host         TEXT NOT NULL DEFAULT '',
  status       INTEGER NOT NULL DEFAULT 0,
  content_type TEXT NOT NULL DEFAULT '',
  req_len      INTEGER NOT NULL DEFAULT 0,
  resp_len     INTEGER NOT NULL DEFAULT 0,
  path         TEXT NOT NULL DEFAULT '',
  project_id   TEXT NOT NULL DEFAULT '',
  source       TEXT NOT NULL DEFAULT '',
  tags         TEXT NOT NULL DEFAULT '[]',
  content_hash TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  UNIQUE(project_id, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_http_flows_host_tmpl ON http_flows(host, url_template);
CREATE INDEX IF NOT EXISTS idx_http_flows_host ON http_flows(host);
CREATE INDEX IF NOT EXISTS idx_http_flows_ts ON http_flows(ts);
CREATE INDEX IF NOT EXISTS idx_http_flows_status ON http_flows(status);
CREATE INDEX IF NOT EXISTS idx_http_flows_project ON http_flows(project_id);

CREATE TABLE IF NOT EXISTS http_flow_bodies (
  id          TEXT PRIMARY KEY REFERENCES http_flows(id) ON DELETE CASCADE,
  req_headers TEXT NOT NULL DEFAULT '',
  req_body    TEXT,
  req_blob    TEXT,
  resp_headers TEXT NOT NULL DEFAULT '',
  resp_body   TEXT,
  resp_blob   TEXT
);

CREATE TABLE IF NOT EXISTS blob_refs (
  hash    TEXT NOT NULL,
  flow_id TEXT NOT NULL,
  PRIMARY KEY (hash, flow_id)
);
CREATE INDEX IF NOT EXISTS idx_blob_refs_hash ON blob_refs(hash);
`

// ftsSchema 独立于 indexSchema 应用：无 FTS5 的驱动构建必须降级为
// “无全文检索”，而不是拖垮整个子系统。trigram 支持任意子串与 CJK。
const ftsSchema = `CREATE VIRTUAL TABLE IF NOT EXISTS http_flow_fts USING fts5(text, tokenize='trigram');`

// Store 是流量库的访问入口。并发安全靠 SQLite 自身：WAL 模式 + busy_timeout
// 5s（见 DSN）+ 连接池；并发写最坏情况是逐条报 SQLITE_BUSY 类错误，不会损坏库。
type Store struct {
	db           *sql.DB
	dir          string
	blobsDir     string
	logger       *zap.Logger
	ftsAvailable bool
	disableFTS   bool
}

// Option 定制 Open 行为。
type Option func(*Store)

// WithDisableFTS 显式关闭全文索引（测试降级路径 / 运维降级用）。
func WithDisableFTS() Option {
	return func(s *Store) { s.disableFTS = true }
}

// Open 打开（必要时创建）dir 下的流量库：index.sqlite + blobs/。
func Open(dir string, logger *zap.Logger, opts ...Option) (*Store, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	blobsDir := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return nil, fmt.Errorf("创建流量库目录失败: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(filepath.Join(dir, "index.sqlite")) +
		"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开流量索引库失败: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	s := &Store{db: db, dir: dir, blobsDir: blobsDir, logger: logger}
	for _, opt := range opts {
		opt(s)
	}
	if _, err := db.Exec(indexSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化流量库 schema 失败: %w", err)
	}
	s.applyFTS()
	return s, nil
}

// applyFTS 单独应用 FTS schema；失败只记日志并降级，不 panic 不报错。
func (s *Store) applyFTS() {
	if s.disableFTS {
		s.logger.Info("流量库 FTS 已被显式关闭，仅元数据搜索可用")
		return
	}
	if _, err := s.db.Exec(ftsSchema); err != nil {
		s.ftsAvailable = false
		s.logger.Warn("流量库 FTS5 不可用，全文检索降级为仅元数据 LIKE 搜索（如需启用请以 -tags sqlite_fts5 构建）", zap.Error(err))
		return
	}
	s.ftsAvailable = true
}

// FTSAvailable 报告全文索引当前是否可用。
func (s *Store) FTSAvailable() bool { return s.ftsAvailable }

// Dir 返回流量库根目录（data/traffic）。
func (s *Store) Dir() string { return s.dir }

// Close 关闭索引库连接。
func (s *Store) Close() error { return s.db.Close() }

// Flow 是导入时的单条流量输入。
type Flow struct {
	TS          int64  `json:"ts"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	ReqHeaders  string `json:"req_headers"`
	ReqBody     string `json:"req_body"`
	RespHeaders string `json:"resp_headers"`
	RespBody    string `json:"resp_body"`
}

// ImportResult 汇总一次批量导入的计数与逐条错误。
type ImportResult struct {
	Imported   int      `json:"imported"`
	Duplicates int      `json:"duplicates"`
	Errors     []string `json:"errors"`
}

// FlowItem 是列表/详情共用的元数据形态，字段与 REST 合同一致。
type FlowItem struct {
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
	Path        string   `json:"-"`
	Tags        []string `json:"tags"`
	Source      string   `json:"source"`
	ProjectID   string   `json:"project_id"`
}

// FlowDetail 在元数据之上附带四个截断预览字段。
type FlowDetail struct {
	FlowItem
	ReqHeaders    string `json:"req_headers"`
	ReqBody       string `json:"req_body"`
	RespHeaders   string `json:"resp_headers"`
	RespBody      string `json:"resp_body"`
	BodyTruncated bool   `json:"body_truncated"`
}

// QueryFilter 是列表查询条件；Status 为 nil 表示不过滤。
type QueryFilter struct {
	ProjectID string
	Q         string
	Host      string
	Method    string
	Status    *int
	Tag       string
	Limit     int
	Offset    int
}

// ImportFlows 批量导入：同项目内内容哈希重复的流量只计 duplicates。
func (s *Store) ImportFlows(projectID, source string, flows []Flow) ImportResult {
	result := ImportResult{Errors: []string{}}
	tx, err := s.db.Begin()
	if err != nil {
		result.Errors = append(result.Errors, "开启事务失败: "+err.Error())
		return result
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)
flowLoop:
	for i, flow := range flows {
		if strings.TrimSpace(flow.Method) == "" || strings.TrimSpace(flow.URL) == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("flows[%d]: method 与 url 必填", i))
			continue
		}
		id := uuid.NewString()
		host, template, path := normalizeURL(flow.URL)
		contentHash := contentHash(flow)
		reqInline, reqBlob := splitBody(flow.ReqBody)
		respInline, respBlob := splitBody(flow.RespBody)

		if reqBlob != "" {
			if err := s.writeBlob(tx, reqBlob, []byte(flow.ReqBody)); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("flows[%d]: 写入请求 blob 失败: %v", i, err))
				continue
			}
		}
		if respBlob != "" {
			if err := s.writeBlob(tx, respBlob, []byte(flow.RespBody)); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("flows[%d]: 写入响应 blob 失败: %v", i, err))
				continue
			}
		}

		res, err := tx.Exec(`INSERT OR IGNORE INTO http_flows
			(id, ts, method, url, url_template, host, status, content_type, req_len, resp_len, path, project_id, source, tags, content_hash, created_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, flow.TS, strings.TrimSpace(flow.Method), flow.URL, template, host, flow.Status,
			flow.ContentType, len(flow.ReqBody), len(flow.RespBody), path,
			strings.TrimSpace(projectID), strings.TrimSpace(source), "[]", contentHash, now)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("flows[%d]: %v", i, err))
			continue
		}
		inserted, err := res.RowsAffected()
		if err != nil || inserted == 0 {
			result.Duplicates++
			continue
		}
		if _, err := tx.Exec(`INSERT INTO http_flow_bodies (id, req_headers, req_body, req_blob, resp_headers, resp_body, resp_blob)
			VALUES (?,?,?,?,?,?,?)`,
			id, flow.ReqHeaders, reqInline, nullableString(reqBlob), flow.RespHeaders, respInline, nullableString(respBlob)); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("flows[%d]: 写入正文失败: %v", i, err))
			// 主表行必须一并撤销，否则留下「列表可见、详情 404、重试永远算
			// duplicates」的幽灵行（content_hash 已占用且无法修复）
			s.deleteInsertedFlow(tx, id)
			continue
		}
		for _, hash := range []string{reqBlob, respBlob} {
			if hash == "" {
				continue
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs (hash, flow_id) VALUES (?,?)`, hash, id); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("flows[%d]: 记录 blob 引用失败: %v", i, err))
				s.deleteInsertedFlow(tx, id)
				// 必须跳过整条流量（外层循环）：只 continue 内层会把已撤销
				// 的行又计入 Imported 并写入 FTS
				continue flowLoop
			}
		}
		if s.ftsAvailable {
			rowID, err := res.LastInsertId()
			if err == nil {
				if _, err := tx.Exec(`INSERT INTO http_flow_fts (rowid, text) VALUES (?,?)`, rowID, indexText(flow)); err != nil {
					s.logger.Warn("写入流量全文索引失败", zap.Error(err))
				}
			}
		}
		result.Imported++
	}
	if err := tx.Commit(); err != nil {
		return ImportResult{Errors: []string{"提交事务失败: " + err.Error()}}
	}
	return result
}

// Query 按过滤条件分页返回（ts 倒序）列表与总数。
func (s *Store) Query(filter QueryFilter) ([]FlowItem, int, error) {
	where, args := s.queryWhere(filter)

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM http_flows`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []FlowItem{}, 0, nil
	}
	limit, offset := filter.Limit, filter.Offset
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT id, ts, method, url, url_template, host, status, content_type, req_len, resp_len, path, project_id, source, tags
		FROM http_flows`+where+` ORDER BY ts DESC, id LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := []FlowItem{}
	for rows.Next() {
		var item FlowItem
		var tagsJSON string
		if err := rows.Scan(&item.ID, &item.TS, &item.Method, &item.URL, &item.URLTemplate, &item.Host,
			&item.Status, &item.ContentType, &item.ReqLen, &item.RespLen, &item.Path,
			&item.ProjectID, &item.Source, &tagsJSON); err != nil {
			return nil, 0, err
		}
		item.Tags = decodeTags(tagsJSON)
		items = append(items, item)
	}
	return items, total, rows.Err()
}

// Get 返回单条流量详情，正文各字段截断为 ≤8KB 预览。
func (s *Store) Get(id string) (*FlowDetail, error) {
	detail := &FlowDetail{}
	var tagsJSON string
	err := s.db.QueryRow(`SELECT id, ts, method, url, url_template, host, status, content_type, req_len, resp_len, path, project_id, source, tags
		FROM http_flows WHERE id = ?`, id).
		Scan(&detail.ID, &detail.TS, &detail.Method, &detail.URL, &detail.URLTemplate, &detail.Host,
			&detail.Status, &detail.ContentType, &detail.ReqLen, &detail.RespLen, &detail.Path,
			&detail.ProjectID, &detail.Source, &tagsJSON)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	detail.Tags = decodeTags(tagsJSON)

	var reqBody, respBody, reqBlob, respBlob sql.NullString
	if err := s.db.QueryRow(`SELECT req_headers, req_body, req_blob, resp_headers, resp_body, resp_blob
		FROM http_flow_bodies WHERE id = ?`, id).
		Scan(&detail.ReqHeaders, &reqBody, &reqBlob, &detail.RespHeaders, &respBody, &respBlob); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	detail.ReqBody = truncateRunes(reqBody.String, previewCap)
	detail.RespBody = truncateRunes(respBody.String, previewCap)
	detail.RespHeaders = truncateRunes(detail.RespHeaders, previewCap)
	detail.ReqHeaders = truncateRunes(detail.ReqHeaders, previewCap)
	detail.BodyTruncated = reqBlob.Valid || respBlob.Valid ||
		len(reqBody.String) > previewCap || len(respBody.String) > previewCap ||
		len(detail.RespHeaders) > previewCap || len(detail.ReqHeaders) > previewCap
	return detail, nil
}

// SetTags 整体替换单条流量的标签。
func (s *Store) SetTags(id string, tags []string) error {
	if len(tags) > maxTagsPerFlow {
		return fmt.Errorf("标签最多 %d 个", maxTagsPerFlow)
	}
	for _, tag := range tags {
		// 上限按字符数（rune）计，与文档口径一致；按字节计会误拒 CJK 标签
		if utf8.RuneCountInString(tag) > 100 {
			return fmt.Errorf("单个标签最长 100 字符")
		}
	}
	encoded, err := encodeTags(tags)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE http_flows SET tags = ? WHERE id = ?`, encoded, id)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteProject 删除项目下全部流量，并回收不再被引用的 blob 文件。
func (s *Store) DeleteProject(projectID string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// 无论当前构建是否带 FTS5 都尝试清理 FTS 行：无 FTS 构建打开旧库
	// （FTS 表由带 tag 构建创建过）时也能同步清理；表不存在则忽略。
	if _, err := tx.Exec(`DELETE FROM http_flow_fts WHERE rowid IN (SELECT rowid FROM http_flows WHERE project_id = ?)`, projectID); err != nil && s.ftsAvailable {
		return 0, err
	}
	orphanCandidates := []string{}
	rows, err := tx.Query(`SELECT DISTINCT br.hash FROM blob_refs br
		JOIN http_flows f ON f.id = br.flow_id WHERE f.project_id = ?`, projectID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			rows.Close()
			return 0, err
		}
		orphanCandidates = append(orphanCandidates, hash)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if _, err := tx.Exec(`DELETE FROM blob_refs WHERE flow_id IN (SELECT id FROM http_flows WHERE project_id = ?)`, projectID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM http_flow_bodies WHERE id IN (SELECT id FROM http_flows WHERE project_id = ?)`, projectID); err != nil {
		return 0, err
	}
	res, err := tx.Exec(`DELETE FROM http_flows WHERE project_id = ?`, projectID)
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	s.garbageCollectBlobs(orphanCandidates)
	return deleted, nil
}

// garbageCollectBlobs 删除候选哈希中已无引用的 blob 文件。
func (s *Store) garbageCollectBlobs(hashes []string) {
	for _, hash := range hashes {
		var refs int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM blob_refs WHERE hash = ?`, hash).Scan(&refs); err != nil {
			s.logger.Warn("流量 blob 回收检查失败", zap.String("hash", hash), zap.Error(err))
			continue
		}
		if refs > 0 {
			continue
		}
		if err := os.Remove(s.blobPath(hash)); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("流量 blob 删除失败", zap.String("hash", hash), zap.Error(err))
		}
	}
}

func (s *Store) blobPath(hash string) string {
	return filepath.Join(s.blobsDir, hash[:2], hash)
}

// deleteInsertedFlow 撤销本事务内刚插入的流量行（含级联正文与引用），
// 用于导入中途失败时的补偿删除，防止留下只有主表行的幽灵数据。
func (s *Store) deleteInsertedFlow(tx *sql.Tx, id string) {
	if _, err := tx.Exec(`DELETE FROM blob_refs WHERE flow_id = ?`, id); err != nil {
		s.logger.Warn("撤销流量 blob 引用失败", zap.String("id", id), zap.Error(err))
	}
	if _, err := tx.Exec(`DELETE FROM http_flow_bodies WHERE id = ?`, id); err != nil {
		s.logger.Warn("撤销流量正文失败", zap.String("id", id), zap.Error(err))
	}
	if _, err := tx.Exec(`DELETE FROM http_flows WHERE id = ?`, id); err != nil {
		s.logger.Warn("撤销流量主表行失败", zap.String("id", id), zap.Error(err))
	}
}

// writeBlob 以 sha256 内容寻址落盘（已存在则跳过，实现同内容去重）。
// 事务失败时可能留下无引用的孤儿文件，只影响磁盘占用不影响正确性。
func (s *Store) writeBlob(tx *sql.Tx, hash string, body []byte) error {
	// 同事务内已写过该 blob（同批两条相同大正文）时直接跳过
	// 已存在文件的重复写盘，靠路径不可变保证一致性。
	path := s.blobPath(hash)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0644)
}

// splitBody 决定正文的存储形态：≤maxInlineBody 全量 inline；
// 超出则溢出 blob，inline 仅保留 previewCap 预览。
func splitBody(body string) (inline string, blobHash string) {
	if len(body) <= maxInlineBody {
		return body, ""
	}
	sum := sha256.Sum256([]byte(body))
	return truncateRunes(body, previewCap), hex.EncodeToString(sum[:])
}

// contentHash 计算流量的内容身份：同一项目内同内容重复导入计 duplicate。
// 时间戳不参与（重复同步时时间往往不同），状态参与（同请求不同状态是不同事实）。
func contentHash(flow Flow) string {
	h := sha256.New()
	for _, part := range []string{
		strings.TrimSpace(flow.Method), flow.URL, flow.ReqHeaders, flow.ReqBody,
		fmt.Sprintf("%d", flow.Status), flow.RespHeaders, flow.RespBody,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// indexText 汇总进入全文索引的文本，各正文截断到 maxIndexBody。
// content_type 与 URL 同行拼接：FTS 模式的搜索面必须覆盖降级 LIKE 模式
// 能命中的元数据（url_template 是 url 的子串，天然被覆盖），否则启用
// FTS 反而缩小搜索面。
func indexText(flow Flow) string {
	host, _, _ := normalizeURL(flow.URL)
	var b strings.Builder
	b.WriteString(flow.URL)
	if flow.ContentType != "" {
		b.WriteString(" ")
		b.WriteString(flow.ContentType)
	}
	b.WriteString("\n")
	b.WriteString(host)
	b.WriteString("\n")
	b.WriteString(truncateRunes(flow.ReqBody, maxIndexBody))
	b.WriteString("\n")
	b.WriteString(truncateRunes(flow.RespBody, maxIndexBody))
	return b.String()
}

// normalizeURL 解析 host 与剥 query 的 url 模板；解析失败时模板回落为原串。
func normalizeURL(raw string) (host, template, path string) {
	template = strings.TrimSpace(raw)
	host = ""
	path = ""
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return
	}
	host = strings.ToLower(u.Hostname())
	path = u.EscapedPath()
	if path == "" {
		path = "/"
	}
	template = path
	return
}

// queryWhere 组装查询条件，含 FTS/LIKE 降级选择。
func (s *Store) queryWhere(filter QueryFilter) (string, []interface{}) {
	conds := []string{}
	args := []interface{}{}
	if v := strings.TrimSpace(filter.ProjectID); v != "" {
		conds = append(conds, "project_id = ?")
		args = append(args, v)
	}
	if v := strings.TrimSpace(filter.Host); v != "" {
		conds = append(conds, "host = ?")
		args = append(args, strings.ToLower(v))
	}
	if v := strings.ToUpper(strings.TrimSpace(filter.Method)); v != "" {
		conds = append(conds, "method = ?")
		args = append(args, v)
	}
	if filter.Status != nil {
		conds = append(conds, "status = ?")
		args = append(args, *filter.Status)
	}
	if v := strings.TrimSpace(filter.Tag); v != "" {
		conds = append(conds, "tags LIKE ? ESCAPE '\\'")
		args = append(args, `%"`+escapeLike(v)+`"%`)
	}
	if q := strings.TrimSpace(filter.Q); q != "" {
		conds = append(conds, s.searchCondition(q))
		args = append(args, s.searchArgs(q)...)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}
