package nmap_test

import (
	"reflect"
	"testing"

	"cyberstrike-ai/internal/database"
	ingestnmap "cyberstrike-ai/internal/ingest/nmap"
)

// fixtureNmapXML 是一份典型的 nmap -oX 输出（本地假数据，非真实扫描）：
// 两个主机、开放/关闭/open|filtered 端口混排、服务指纹与 http-title 脚本输出。
const fixtureNmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -sC -p 22,80,443 192.0.2.10 2001:db8::1" start="1699999999" version="7.94" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="3" services="22,80,443"/>
<host starttime="1699999999" endtime="1700000100">
	<status state="up" reason="reset" reason_ttl="63"/>
	<address addr="192.0.2.10" addrtype="ipv4"/>
	<address addr="52:54:00:aa:bb:cc" addrtype="mac" vendor="QEMU"/>
	<hostnames>
		<hostname name="web01.example.com" type="PTR"/>
	</hostnames>
	<ports>
		<extraports state="closed" count="1">
			<extrareasons reason="reset" count="1"/>
		</extraports>
		<port protocol="tcp" portid="22">
			<state state="open" reason="syn-ack" reason_ttl="63"/>
			<service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="protocol 2.0" method="probed" conf="10"/>
		</port>
		<port protocol="tcp" portid="80">
			<state state="open" reason="syn-ack" reason_ttl="63"/>
			<service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/>
			<script id="http-title" output="Welcome to nginx!"/>
		</port>
		<port protocol="tcp" portid="443">
			<state state="closed" reason="reset" reason_ttl="63"/>
			<service name="https" method="table" conf="3"/>
		</port>
		<port protocol="udp" portid="161">
			<state state="open|filtered" reason="no-response" reason_ttl="0"/>
			<service name="snmp" method="table" conf="3"/>
		</port>
	</ports>
	<os>
		<osmatch name="Linux 5.x" accuracy="98" line="line"/>
	</os>
</host>
<host starttime="1699999999" endtime="1700000100">
	<status state="up" reason="unknown" reason_ttl="0"/>
	<address addr="2001:db8::1" addrtype="ipv6"/>
	<ports>
		<port protocol="tcp" portid="443">
			<state state="open" reason="syn-ack" reason_ttl="57"/>
			<service name="https" tunnel="ssl" method="probed" conf="10"/>
		</port>
	</ports>
</host>
<runstats>
	<finished time="1700000100" elapsed="101" summary="Nmap done"/>
</runstats>
</nmaprun>
`

func TestParseFixtureToAssets(t *testing.T) {
	parser := ingestnmap.New()
	assets, err := parser.Parse([]byte(fixtureNmapXML))
	if err != nil {
		t.Fatalf("Parse fixture: %v", err)
	}
	host1SSHTags := []string{"nmap", "nmap-service:ssh", "nmap-os:Linux 5.x"}
	host1HTTPTags := []string{"nmap", "nmap-service:http", "nmap-os:Linux 5.x"}
	host2Tags := []string{"nmap", "nmap-service:https"}
	want := []*database.Asset{
		{
			Host: "web01.example.com", IP: "192.0.2.10", Port: 22, Protocol: "tcp",
			Server: "OpenSSH 8.9p1 · ssh", Source: "nmap",
			SourceQuery: "nmap -sT -sV -sC -p 22,80,443 192.0.2.10 2001:db8::1",
			Tags:        host1SSHTags,
		},
		{
			Host: "web01.example.com", IP: "192.0.2.10", Port: 80, Protocol: "tcp",
			Server: "nginx 1.18.0 · http", Title: "Welcome to nginx!", Source: "nmap",
			SourceQuery: "nmap -sT -sV -sC -p 22,80,443 192.0.2.10 2001:db8::1",
			Tags:        host1HTTPTags,
		},
		{
			Host: "2001:db8::1", IP: "2001:db8::1", Port: 443, Protocol: "tcp",
			Server: "https", Source: "nmap",
			SourceQuery: "nmap -sT -sV -sC -p 22,80,443 192.0.2.10 2001:db8::1",
			Tags:        host2Tags,
		},
	}
	if len(assets) != len(want) {
		t.Fatalf("asset count: got %d want %d\nassets=%+v", len(assets), len(want), assets)
	}
	for i := range want {
		got := assets[i]
		if got.Host != want[i].Host || got.IP != want[i].IP || got.Port != want[i].Port ||
			got.Protocol != want[i].Protocol || got.Server != want[i].Server ||
			got.Title != want[i].Title || got.Source != want[i].Source ||
			got.SourceQuery != want[i].SourceQuery || got.Domain != "" || got.ProjectID != "" {
			t.Fatalf("asset[%d] mismatch:\ngot  %+v\nwant %+v", i, got, want[i])
		}
		if !reflect.DeepEqual(got.Tags, want[i].Tags) {
			t.Fatalf("asset[%d] tags: got %v want %v", i, got.Tags, want[i].Tags)
		}
	}
}

func TestParseRejectsInvalidXML(t *testing.T) {
	if _, err := ingestnmap.New().Parse([]byte("not xml at all")); err == nil {
		t.Fatal("invalid XML should return an error")
	}
}

func TestParseEmptyRunYieldsNoAssets(t *testing.T) {
	assets, err := ingestnmap.New().Parse([]byte(`<?xml version="1.0"?><nmaprun></nmaprun>`))
	if err != nil {
		t.Fatalf("empty run should parse: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("empty run should yield no assets, got %d", len(assets))
	}
}

func TestParseTruncatesOverlongFields(t *testing.T) {
	longTitle := ""
	for i := 0; i < 80; i++ {
		longTitle += "标题块"
	} // 320 字符 ×3 字节，超过页面标题 500 字上限也超 255
	xml := `<?xml version="1.0"?><nmaprun><host><status state="up"/>
	<address addr="192.0.2.20" addrtype="ipv4"/>
	<ports><port protocol="tcp" portid="8080"><state state="open"/>
	<service name="http"/>
	<script id="http-title" output="` + longTitle + `"/>
	</port></ports></host></nmaprun>`
	assets, err := ingestnmap.New().Parse([]byte(xml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("want 1 asset, got %d", len(assets))
	}
	if got := len([]rune(assets[0].Title)); got > 500 {
		t.Fatalf("title should be truncated to <=500 runes, got %d", got)
	}
}
