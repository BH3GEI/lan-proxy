package engine

import (
	"net/netip"
	"strings"
	"testing"

	"lanproxy/internal/core"
)

const secretURL = "https://sub.example.com/psub/qX9SecretToken0123?x=1"

func TestBuildConfigWithSub(t *testing.T) {
	c := core.DefaultConfig()
	c.SubURL = secretURL
	txt := BuildConfig(c, netip.MustParseAddrPort("172.20.0.5:31234"), []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")}, "lpabc", "pw'x", "/d/run/mihomo.sock", true)
	for _, want := range []string{
		"bind-address: '172.20.0.5'",
		"lan-allowed-ips: ['172.20.0.0/16']",
		"external-controller: ''",
		"external-controller-unix: '/d/run/mihomo.sock'",
		"listen: '172.20.0.5', port: 31234",
		"users: [{username: 'lpabc', password: 'pw''x'}]",
		"type: file",
		"path: ./providers/sub.yaml",
		"- {name: 节点选择, type: select, proxies: [自动选择], use: [sub]}",
		"type: url-test",
		"- RULE-SET,cn_site,DIRECT",
		"- MATCH,节点选择",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("config missing %q\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "qX9SecretToken") || strings.Contains(txt, "sub.example.com") {
		t.Error("subscription URL in mihomo config")
	}
	for _, bad := range []string{"'0.0.0.0'", "mixed-port", "external-controller: ':", "'*'"} {
		if strings.Contains(txt, bad) {
			t.Errorf("config contains %q", bad)
		}
	}
	// Reject rules come before any DIRECT rule.
	iReject := strings.Index(txt, "IP-CIDR,192.168.0.0/16,REJECT")
	iDirect := strings.Index(txt, ",DIRECT")
	for _, cidr := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16", "224.0.0.0/4", "100.64.0.0/10"} {
		i := strings.Index(txt, "IP-CIDR,"+cidr+",REJECT")
		if i < 0 || i > iDirect {
			t.Errorf("%s reject missing or after DIRECT", cidr)
		}
	}
	if iReject < 0 || iReject > iDirect {
		t.Fatal("reject rules not first")
	}
}

func TestBuildConfigNoSubRejects(t *testing.T) {
	c := core.DefaultConfig()
	txt := BuildConfig(c, netip.MustParseAddrPort("172.20.0.5:31234"), nil, "u", "p", "/s", false)
	if !strings.Contains(txt, "- {name: 节点选择, type: select, proxies: [REJECT]}") || strings.Contains(txt, "proxy-providers") {
		t.Fatalf("no-sub config:\n%s", txt)
	}
}

func TestParseRoute(t *testing.T) {
	cases := []struct{ line, src, dst, rule, out string }{
		{`time="2026-11-22T00:00:00Z" level=info msg="[TCP] 172.20.0.1:40000 --> www.baidu.com:443 match RuleSet(cn_site) using DIRECT"`, "172.20.0.1:40000", "www.baidu.com:443", "RuleSet(cn_site)", "DIRECT"},
		{`time="x" level=info msg="[TCP] 172.20.0.1:40001(lanproxy) --> www.google.com:443 match Match using 节点选择[自动选择[62-de-fra-hy2]]"`, "172.20.0.1:40001", "www.google.com:443", "Match", "62-de-fra-hy2"},
		{`time="x" level=info msg="[TCP] 172.20.0.1:40002 --> 10.0.0.1:80 match IPCIDR(10.0.0.0/8) using REJECT"`, "172.20.0.1:40002", "10.0.0.1:80", "IPCIDR(10.0.0.0/8)", "REJECT"},
		{`time="x" level=info msg="[TCP] 172.20.0.1:40003 --> a.b:80 doesn't match any rule using DIRECT"`, "172.20.0.1:40003", "a.b:80", "无匹配", "DIRECT"},
		{`time="x" level=warning msg="[TCP] dial 节点选择 (match Match/) 192.168.3.91:65003 --> www.google.com:443 error: context deadline exceeded"`, "192.168.3.91:65003", "www.google.com:443", "Match", "节点选择（连接失败）"},
	}
	for _, c := range cases {
		r, ok := ParseRoute(c.line)
		if !ok || r.Src != c.src || r.Dst != c.dst || r.Rule != c.rule || r.Outbound != c.out {
			t.Errorf("%s\n => %+v ok=%v", c.line, r, ok)
		}
	}
	if _, ok := ParseRoute(`time="x" level=warning msg="something else"`); ok {
		t.Error("non-route line parsed")
	}
}

func TestScrub(t *testing.T) {
	line := `level=error msg="initial proxy provider sub error: Get "` + secretURL + `": dial tcp: timeout; token qX9SecretToken0123"`
	out := Scrub(line, secretURL)
	if strings.Contains(out, "qX9SecretToken0123") || strings.Contains(out, "/psub/qX9") {
		t.Fatalf("token leaked: %s", out)
	}
	if !strings.Contains(out, "sub.example.com") {
		t.Fatalf("host removed: %s", out)
	}
}

func TestValidateSub(t *testing.T) {
	ok := []string{"proxies:\n  - {name: a, type: ss}", "dmxlc3M6Ly9hYmNAMS4yLjMuNDo0NDMjeA==", "hysteria2://x@h:1#a\nvless://y@h:2#b"}
	for _, s := range ok {
		if err := ValidateSub([]byte(s)); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "<html>blocked</html>", "   "} {
		if ValidateSub([]byte(s)) == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
