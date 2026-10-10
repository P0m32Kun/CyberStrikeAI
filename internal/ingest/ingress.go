// Package ingest 定义扫描器输出 → 资产入库的解析器扩展位（fork Phase 2，计划 §5.3.6）。
// 本阶段仅接入 nmap；后续 masscan/httpx 实现同一接口即可插到相同挂载点上。
package ingest

import "cyberstrike-ai/internal/database"

// IngressParser 把外部扫描器的原始输出解析为资产草案。
type IngressParser interface {
	// Name 返回来源标识，写入 Asset.Source。
	Name() string
	// Parse 解析原始输出。返回的资产只填内容字段；ProjectID 等
	// 上下文信息由挂载方（自动回调或手动导入工具）填充。
	Parse(data []byte) ([]*database.Asset, error)
}
