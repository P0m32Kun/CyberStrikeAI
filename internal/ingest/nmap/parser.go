// Package nmap 解析 nmap -oX XML 输出为资产草案（fork Phase 2，计划 §5.3.2）。
// 仅使用 Go 标准库 encoding/xml，不引入第三方依赖。
package nmap

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/ingest"
)

// Parser 实现 ingest.IngressParser。
type Parser struct{}

var _ ingest.IngressParser = Parser{}

// New 返回 nmap 解析器。
func New() *Parser { return &Parser{} }

// Name 返回来源标识 "nmap"。
func (Parser) Name() string { return "nmap" }

// 字段截断上限对齐 internal/database/asset.go validateAsset 的校验限制，
// 避免单条超长指纹/标题让整批入库失败。
const (
	maxServerRunes   = 255
	maxTitleRunes    = 500
	maxHostRunes     = 500
	maxTagRunes      = 64
	maxSourceQueryB  = 2000
	maxTagsPerAsset  = 30
	nmapTagPrefixSvc = "nmap-service:"
	nmapTagPrefixOS  = "nmap-os:"
)

type runXML struct {
	Args  string    `xml:"args,attr"`
	Hosts []hostXML `xml:"host"`
}

type hostXML struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames struct {
		Names []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []portXML `xml:"port"`
	} `xml:"ports"`
	OS struct {
		Matches []struct {
			Name string `xml:"name,attr"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

type portXML struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name      string `xml:"name,attr"`
		Product   string `xml:"product,attr"`
		Version   string `xml:"version,attr"`
		ExtraInfo string `xml:"extrainfo,attr"`
	} `xml:"service"`
	Scripts []struct {
		ID     string `xml:"id,attr"`
		Output string `xml:"output,attr"`
	} `xml:"script"`
}

// Parse 解析 nmap XML，每个 state=open 的端口产出一条资产草案。
// 映射关系（不改 assets 表结构）：
//   - address[ipv4|ipv6] → IP；主机名（任意 type，取第一个非空）→ Host（不写 Domain，保持去重键稳定落在 IP）
//   - port protocol → Protocol（tcp/udp）；product/version/service → Server 服务指纹
//   - http-title 脚本输出 → Title；多余信息（服务名、OS 猜测）→ Tags
//   - nmaprun args → SourceQuery
//
// state != "open"（closed/filtered/open|filtered）的端口不产出资产。
func (Parser) Parse(data []byte) ([]*database.Asset, error) {
	var run runXML
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("解析 nmap XML 失败: %w", err)
	}
	sourceQuery := truncateRunes(strings.TrimSpace(run.Args), maxSourceQueryB)
	assets := make([]*database.Asset, 0, 8)
	for _, host := range run.Hosts {
		if strings.TrimSpace(host.Status.State) != "" && strings.TrimSpace(host.Status.State) != "up" {
			continue
		}
		ip := hostPrimaryIP(host)
		hostname := hostPrimaryHostname(host)
		if ip == "" && hostname == "" {
			continue
		}
		hostLabel := hostname
		if hostLabel == "" {
			hostLabel = ip
		}
		osTag := ""
		if osName := hostOSGuess(host); osName != "" {
			osTag = truncateRunes(nmapTagPrefixOS+osName, maxTagRunes)
		}
		for _, port := range host.Ports.Ports {
			if strings.TrimSpace(port.State.State) != "open" {
				continue
			}
			portNum, err := strconv.Atoi(strings.TrimSpace(port.PortID))
			if err != nil || portNum <= 0 || portNum > 65535 {
				continue
			}
			asset := &database.Asset{
				Host:        truncateRunes(hostLabel, maxHostRunes),
				IP:          ip,
				Port:        portNum,
				Protocol:    strings.ToLower(strings.TrimSpace(port.Protocol)),
				Server:      portFingerprint(port),
				Source:      "nmap",
				SourceQuery: sourceQuery,
			}
			if title := scriptOutput(port, "http-title"); title != "" {
				asset.Title = truncateRunes(title, maxTitleRunes)
			}
			// 标签顺序固定：nmap → 端口级服务名 → 主机级 OS 猜测（截断到 30 个以内）。
			asset.Tags = append([]string{"nmap"}, portTags(port)...)
			if osTag != "" && len(asset.Tags) < maxTagsPerAsset {
				asset.Tags = append(asset.Tags, osTag)
			}
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func hostPrimaryIP(host hostXML) string {
	ipv6 := ""
	for _, addr := range host.Addresses {
		switch strings.ToLower(strings.TrimSpace(addr.AddrType)) {
		case "ipv4":
			return strings.TrimSpace(addr.Addr)
		case "ipv6":
			if ipv6 == "" {
				ipv6 = strings.TrimSpace(addr.Addr)
			}
		}
	}
	return ipv6
}

func hostPrimaryHostname(host hostXML) string {
	for _, name := range host.Hostnames.Names {
		if trimmed := strings.TrimSuffix(strings.TrimSpace(name.Name), "."); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func hostOSGuess(host hostXML) string {
	for _, match := range host.OS.Matches {
		if name := strings.TrimSpace(match.Name); name != "" {
			return name
		}
	}
	return ""
}

// portFingerprint 组合服务指纹：优先 product version，缺省退回服务名。
func portFingerprint(port portXML) string {
	product := strings.TrimSpace(port.Service.Product)
	version := strings.TrimSpace(port.Service.Version)
	fingerprint := strings.TrimSpace(product + " " + version)
	service := strings.TrimSpace(port.Service.Name)
	if fingerprint == "" {
		fingerprint = service
	} else if service != "" && !strings.Contains(fingerprint, service) {
		fingerprint += " · " + service
	}
	return truncateRunes(fingerprint, maxServerRunes)
}

func portTags(port portXML) []string {
	service := strings.TrimSpace(port.Service.Name)
	if service == "" {
		return nil
	}
	return []string{truncateRunes(nmapTagPrefixSvc+service, maxTagRunes)}
}

func scriptOutput(port portXML, scriptID string) string {
	for _, script := range port.Scripts {
		if strings.TrimSpace(script.ID) == scriptID {
			return strings.TrimSpace(script.Output)
		}
	}
	return ""
}

func truncateRunes(value string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	return string(runes[:limit])
}
