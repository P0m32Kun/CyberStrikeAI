package traffic

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// nullableString 把空哈希转为 SQL NULL。
func nullableString(hash string) interface{} {
	if hash == "" {
		return nil
	}
	return hash
}

// encodeTags 将标签序列化为 JSON 文本存储。
func encodeTags(tags []string) (string, error) {
	if tags == nil {
		tags = []string{}
	}
	encoded, err := json.Marshal(tags)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// decodeTags 反序列化标签列，坏数据回落为空标签。
func decodeTags(raw string) []string {
	tags := []string{}
	if strings.TrimSpace(raw) == "" {
		return tags
	}
	_ = json.Unmarshal([]byte(raw), &tags)
	if tags == nil {
		tags = []string{}
	}
	return tags
}

// truncateRunes 按字节封顶截断，且不切出半个 UTF-8 字符
// （CJK 文本若按 rune 数截断，8K rune 可达 3 倍字节，超出预览上限）。
func truncateRunes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := 0
	for cut < len(s) {
		_, size := utf8.DecodeRuneInString(s[cut:])
		if cut+size > max {
			break
		}
		cut += size
	}
	return s[:cut]
}

// escapeLike 转义 LIKE 通配符，配合 ESCAPE '\' 使用。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// searchCondition 返回 q 条件的 SQL 片段：FTS 可用且词长够 trigram 时走
// MATCH，否则降级为元数据 LIKE（url/host/url_template/content_type）。
func (s *Store) searchCondition(q string) string {
	if s.useFTSMatch(q) {
		return "rowid IN (SELECT rowid FROM http_flow_fts WHERE http_flow_fts MATCH ?)"
	}
	return "(url LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR url_template LIKE ? ESCAPE '\\' OR content_type LIKE ? ESCAPE '\\')"
}

// searchArgs 与 searchCondition 配套返回占位参数。
func (s *Store) searchArgs(q string) []interface{} {
	if s.useFTSMatch(q) {
		// 引号包裹成短语，避免用户输入被解释为 FTS 查询语法
		return []interface{}{`"` + strings.ReplaceAll(q, `"`, `""`) + `"`}
	}
	like := "%" + escapeLike(q) + "%"
	return []interface{}{like, like, like, like}
}

// useFTSMatch 判定一次查询能否走 FTS：索引可用且词长不低于 trigram 最短匹配。
func (s *Store) useFTSMatch(q string) bool {
	return s.ftsAvailable && utf8.RuneCountInString(q) >= minFTSTermRunes
}
