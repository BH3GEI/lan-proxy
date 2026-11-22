// Package engine runs the mihomo core in its own container: it generates the
// mihomo configuration from the shared config, keeps the process running,
// publishes the private listener address for the proxy service, and turns
// mihomo's log into routing statistics. The subscription URL is a secret: it
// only appears in the generated mihomo config (mode 600) and is scrubbed from
// every log line.
package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"lanproxy/internal/core"
)

const (
	GroupSelect = "节点选择"
	GroupAuto   = "自动选择"
	Provider    = "sub"
)

// Reserved and private ranges that the core refuses before any rule can send
// traffic direct. The frontend already checked its own resolution; this
// covers a second, different answer when mihomo resolves the name again.
var rejectCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}
var rejectCIDR6 = []string{"::/127", "::ffff:0:0/96", "64:ff9b::/96", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"}

const (
	ruleURLSite = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
	ruleURLIP   = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
)

// State is written to core-state.json for the admin page.
type State struct {
	Running    bool              `json:"running"`
	PID        int               `json:"pid"`
	Started    time.Time         `json:"started"`
	Updated    time.Time         `json:"updated"`
	Restarts   int               `json:"restarts"`
	Error      string            `json:"error,omitempty"`
	Listen     string            `json:"listen"`
	HasSub     bool              `json:"has_sub"`
	Sub        SubStatus         `json:"sub"`
	SubHost    string            `json:"sub_host"`
	Mode       string            `json:"mode"`
	ByOutbound map[string]int64  `json:"by_outbound"`
	ByRule     map[string]int64  `json:"by_rule"`
	Log        []string          `json:"log"`
	Version    string            `json:"version"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// Route is one line of route.jsonl, parsed from mihomo's log.
type Route struct {
	Time     time.Time `json:"t"`
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	Rule     string    `json:"rule"`
	Chain    string    `json:"chain"`
	Outbound string    `json:"outbound"` // DIRECT | REJECT | node name
}

type Engine struct {
	Paths  core.Paths
	Binary string // mihomo executable
	Assets string // bundled rule sets (*.mrs)

	mu      sync.Mutex
	state   State
	cmd     *exec.Cmd
	cfgText string
	secret  string // current subscription URL, for scrubbing
	logRing []string
	routeMu sync.Mutex
}

func New(dir, bin, assets string) *Engine {
	return &Engine{Paths: core.Paths{Dir: dir}, Binary: bin, Assets: assets,
		state: State{ByOutbound: map[string]int64{}, ByRule: map[string]int64{}}}
}

// containerAddr returns this container's IPv4 address and its subnet (the
// private network shared with the host side, where the proxy connects from).
func containerAddr() (netip.Addr, netip.Prefix, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() && ip.Unmap().IsPrivate() {
					ones, _ := ipn.Mask.Size()
					return ip.Unmap(), netip.PrefixFrom(ip.Unmap(), ones).Masked(), nil
				}
			}
		}
	}
	return netip.Addr{}, netip.Prefix{}, fmt.Errorf("no private container IPv4 address")
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randPort() int {
	k, _ := rand.Int(rand.Reader, big.NewInt(30000))
	return 20000 + int(k.Int64())
}

func yq(s string) string { // YAML single-quoted scalar
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// BuildConfig renders the mihomo configuration. listen is the private
// container address; allowFrom the only source allowed (the host side of the
// container network, where the proxy service connects from).
func BuildConfig(c core.Config, listen netip.AddrPort, allowFrom []netip.Prefix, user, pass, sock string, haveNodes bool) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("mode: rule")
	w("log-level: info")
	w("ipv6: false")
	w("allow-lan: true")
	w("bind-address: %s", yq(listen.Addr().String()))
	var allow []string
	for _, p := range allowFrom {
		allow = append(allow, yq(p.String()))
	}
	w("lan-allowed-ips: [%s]", strings.Join(allow, ", "))
	w("find-process-mode: 'off'")
	w("unified-delay: true")
	w("tcp-concurrent: true")
	w("geo-auto-update: false")
	w("profile: {store-selected: true, store-fake-ip: false}")
	w("external-controller: ''")
	w("external-controller-unix: %s", yq(sock))
	// Own DNS over HTTPS, so answers are real addresses even where the LAN's
	// DNS hands out fake IPs (198.18.0.0/15). The frontend asks the same
	// resolver through the controller socket, so both see one answer.
	w("dns:")
	w("  enable: true")
	w("  ipv6: false")
	w("  enhanced-mode: normal")
	w("  cache-algorithm: arc")
	w("  default-nameserver: ['223.5.5.5', '119.29.29.29']")
	w("  nameserver: ['https://223.5.5.5/dns-query', 'https://doh.pub/dns-query']")
	w("  proxy-server-nameserver: ['https://223.5.5.5/dns-query', 'https://doh.pub/dns-query']")
	w("listeners:")
	w("  - {name: frontend, type: socks, listen: %s, port: %d, udp: false, users: [{username: %s, password: %s}]}",
		yq(listen.Addr().String()), listen.Port(), yq(user), yq(pass))
	// The node list is fetched by the engine (see subfetch.go) and given to
	// mihomo as a file, so the subscription URL never enters mihomo's config.
	hasSub := haveNodes
	if hasSub {
		w("proxy-providers:")
		w("  %s:", Provider)
		w("    type: file")
		w("    path: ./providers/sub.yaml")
		w("    health-check: {enable: true, url: %s, interval: 300, timeout: 5000, lazy: false}", yq(c.TestURL))
	}
	w("proxy-groups:")
	if hasSub {
		w("  - {name: %s, type: select, proxies: [%s], use: [%s]}", GroupSelect, GroupAuto, Provider)
		w("  - {name: %s, type: url-test, use: [%s], url: %s, interval: 300, tolerance: 100, timeout: 5000, lazy: false}", GroupAuto, Provider, yq(c.TestURL))
	} else {
		// No subscription: non-China traffic is refused instead of leaking out direct.
		w("  - {name: %s, type: select, proxies: [REJECT]}", GroupSelect)
	}
	w("rule-providers:")
	ruleProxy := GroupSelect
	if !hasSub {
		ruleProxy = "DIRECT"
	}
	w("  cn_site: {type: http, behavior: domain, format: mrs, url: %s, path: ./rules/geosite_cn.mrs, interval: 86400, proxy: %s}", yq(ruleURLSite), ruleProxy)
	w("  cn_ip: {type: http, behavior: ipcidr, format: mrs, url: %s, path: ./rules/geoip_cn.mrs, interval: 86400, proxy: %s}", yq(ruleURLIP), ruleProxy)
	w("rules:")
	for _, cidr := range rejectCIDRs {
		w("  - IP-CIDR,%s,REJECT", cidr)
	}
	for _, cidr := range rejectCIDR6 {
		w("  - IP-CIDR6,%s,REJECT", cidr)
	}
	w("  - RULE-SET,cn_site,DIRECT")
	w("  - RULE-SET,cn_ip,DIRECT")
	w("  - MATCH,%s", GroupSelect)
	return b.String()
}

// mihomo log: msg="[TCP] 172.17.0.1:40000 --> www.baidu.com:443 match RuleSet(cn_site) using DIRECT"
var routeRe = regexp.MustCompile(`\[(TCP|UDP)\] (\S+?)(?:\([^)]*\))? --> (\S+) (?:match (.+?) using (.+?)|doesn't match any rule using (.+?))"?$`)

// mihomo log for a failed dial: msg="[TCP] dial 节点选择 (match Match/) 172.17.0.1:40000 --> www.google.com:443 error: ..."
var dialErrRe = regexp.MustCompile(`\[(?:TCP|UDP)\] dial (\S+) \(match ([^/)]*)/?[^)]*\) (\S+?)(?:\([^)]*\))? --> (\S+) error: (.+?)"?$`)

// ParseRoute extracts a routing decision from one mihomo log line.
func ParseRoute(line string) (Route, bool) {
	if m := dialErrRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
		return Route{Time: time.Now(), Src: m[3], Dst: m[4], Rule: m[2], Chain: m[1], Outbound: m[1] + "（连接失败）"}, true
	}
	m := routeRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Route{}, false
	}
	r := Route{Time: time.Now(), Src: m[2], Dst: m[3], Rule: m[4], Chain: m[5]}
	if m[6] != "" {
		r.Rule, r.Chain = "无匹配", m[6]
	}
	// Chain looks like "节点选择[自动选择[node]]" or "DIRECT"; the innermost name is the outbound.
	ob := r.Chain
	for {
		i := strings.LastIndex(ob, "[")
		if i < 0 {
			break
		}
		ob = strings.TrimRight(ob[i+1:], "]")
	}
	r.Outbound = ob
	return r, true
}

// Scrub removes the subscription URL and its path (the token) from s.
func Scrub(s, secret string) string {
	if secret == "" {
		return s
	}
	s = strings.ReplaceAll(s, secret, core.MaskURL(secret))
	if u, err := url.Parse(secret); err == nil {
		for _, part := range []string{u.RawQuery, u.Path} {
			for _, seg := range strings.FieldsFunc(part, func(r rune) bool { return r == '/' || r == '&' || r == '=' }) {
				if len(seg) >= 8 {
					s = strings.ReplaceAll(s, seg, "***")
				}
			}
		}
	}
	return s
}

// Run keeps mihomo in line with the config until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	os.MkdirAll(e.Paths.CoreDir(), 0o700)
	os.MkdirAll(filepath.Join(e.Paths.CoreDir(), "rules"), 0o700)
	os.MkdirAll(filepath.Dir(e.Paths.ControllerSock()), 0o700)
	os.MkdirAll(filepath.Dir(e.subFile()), 0o700)
	e.seedRules()
	e.state.Started = time.Now()
	e.state.Version = core.Version
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	exited := make(chan struct{}, 1)
	var backoff time.Time
	for {
		cfg, err := core.LoadConfig(e.Paths.Config())
		if err != nil {
			e.setErr("读取配置失败")
		} else {
			e.reconcile(cfg, exited, &backoff)
			e.maybeFetch(cfg)
		}
		e.writeState()
		select {
		case <-ctx.Done():
			e.stop()
			return
		case <-exited:
			e.mu.Lock()
			e.cmd = nil
			e.state.Running = false
			e.state.Restarts++
			e.mu.Unlock()
			os.Remove(e.Paths.CoreEndpoint())
			backoff = time.Now().Add(5 * time.Second)
		case <-tick.C:
		}
	}
}

func (e *Engine) seedRules() {
	for _, n := range []string{"geosite_cn.mrs", "geoip_cn.mrs"} {
		dst := filepath.Join(e.Paths.CoreDir(), "rules", n)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(e.Assets, n))
		if err != nil {
			log.Printf("seed %s: %v", n, err)
			continue
		}
		os.WriteFile(dst, b, 0o600)
	}
}

func (e *Engine) setErr(s string) {
	e.mu.Lock()
	e.state.Error = s
	e.mu.Unlock()
}

// configKey is the part of the config that requires a mihomo restart.
func (e *Engine) configKey(c core.Config) string {
	return strings.Join([]string{fmt.Sprint(e.haveNodes()), c.TestURL}, "\x00")
}

func (e *Engine) subFile() string { return filepath.Join(e.Paths.CoreDir(), "providers", "sub.yaml") }

func (e *Engine) haveNodes() bool {
	st, err := os.Stat(e.subFile())
	return err == nil && st.Size() > 0
}

func (e *Engine) reconcile(c core.Config, exited chan struct{}, backoff *time.Time) {
	e.mu.Lock()
	running := e.cmd != nil
	sameKey := e.cfgText == e.configKey(c)
	e.state.HasSub = c.SubURL != ""
	e.state.SubHost = core.MaskURL(c.SubURL)
	e.state.Mode = c.EgressMode
	e.mu.Unlock()
	if running && sameKey {
		return
	}
	if running {
		e.stop()
	}
	if time.Now().Before(*backoff) {
		return
	}
	if err := e.start(c, exited); err != nil {
		e.setErr(Scrub(err.Error(), c.SubURL))
		*backoff = time.Now().Add(10 * time.Second)
	}
}

func (e *Engine) start(c core.Config, exited chan struct{}) error {
	ip, subnet, err := containerAddr()
	if err != nil {
		return err
	}
	allow := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), subnet}
	listen := netip.AddrPortFrom(ip, uint16(randPort()))
	user, pass := "lp"+randHex(4), randHex(16)
	sock := e.Paths.ControllerSock()
	os.Remove(sock)
	text := BuildConfig(c, listen, allow, user, pass, sock, e.haveNodes())
	cfgPath := filepath.Join(e.Paths.CoreDir(), "config.yaml")
	if err := os.WriteFile(cfgPath+".tmp", []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Rename(cfgPath+".tmp", cfgPath); err != nil {
		return err
	}
	cmd := exec.Command(e.Binary, "-d", e.Paths.CoreDir(), "-f", cfgPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return err
	}
	e.mu.Lock()
	e.cmd, e.cfgText, e.secret = cmd, e.configKey(c), c.SubURL
	e.state.Running, e.state.PID, e.state.Listen, e.state.Error = true, cmd.Process.Pid, listen.String(), ""
	e.mu.Unlock()
	go e.readLog(pr, c.SubURL)
	go func() {
		err := cmd.Wait()
		pw.Close()
		if err != nil {
			e.addLog("mihomo 退出：" + err.Error())
		}
		e.mu.Lock()
		mine := e.cmd == cmd
		e.mu.Unlock()
		if mine {
			exited <- struct{}{}
		}
	}()
	// Publish the endpoint once the listener accepts connections.
	go func() {
		for i := 0; i < 100; i++ {
			e.mu.Lock()
			mine := e.cmd == cmd
			e.mu.Unlock()
			if !mine {
				return
			}
			if conn, err := net.DialTimeout("tcp", listen.String(), 300*time.Millisecond); err == nil {
				conn.Close()
				core.WriteJSONAtomic(e.Paths.CoreEndpoint(), core.CoreEndpoint{Addr: listen.String(), User: user, Pass: pass, Started: time.Now()})
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		e.setErr("mihomo 未能在 20 秒内开始监听")
	}()
	return nil
}

func (e *Engine) stop() {
	e.mu.Lock()
	cmd := e.cmd
	e.cmd = nil
	e.state.Running = false
	e.mu.Unlock()
	os.Remove(e.Paths.CoreEndpoint())
	if cmd == nil || cmd.Process == nil {
		return
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
	}
}

func (e *Engine) addLog(line string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logRing = append(e.logRing, time.Now().Format("01-02 15:04:05 ")+line)
	if len(e.logRing) > 80 {
		e.logRing = e.logRing[len(e.logRing)-80:]
	}
}

var msgRe = regexp.MustCompile(`level=(\w+) msg="(.*)"$`)

func (e *Engine) readLog(r io.Reader, secret string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := Scrub(sc.Text(), secret)
		if rt, ok := ParseRoute(line); ok {
			e.mu.Lock()
			e.state.ByOutbound[rt.Outbound]++
			e.state.ByRule[rt.Rule]++
			e.mu.Unlock()
			e.writeRoute(rt)
			continue
		}
		if m := msgRe.FindStringSubmatch(line); m != nil {
			e.addLog(m[1] + " " + m[2])
		} else {
			e.addLog(line)
		}
	}
}

const maxRouteBytes = 2 << 20

func (e *Engine) writeRoute(r Route) {
	b, _ := json.Marshal(r)
	e.routeMu.Lock()
	defer e.routeMu.Unlock()
	p := e.Paths.RouteLog()
	if st, err := os.Stat(p); err == nil && st.Size() > maxRouteBytes {
		os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

func (e *Engine) writeState() {
	e.mu.Lock()
	st := e.state
	st.Updated = time.Now()
	st.Log = append([]string(nil), e.logRing...)
	st.ByOutbound = copyMap(e.state.ByOutbound)
	st.ByRule = copyMap(e.state.ByRule)
	e.mu.Unlock()
	core.WriteJSONAtomic(e.Paths.CoreState(), st)
}

func copyMap(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}
