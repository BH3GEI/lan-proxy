package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits that keep a misbehaving client from exhausting the NAS.
type Limits struct {
	MaxConns         int           // concurrent client connections, all sources
	MaxPerSource     int           // concurrent client connections per source IP
	HandshakeTimeout time.Duration // from accept until the tunnel is established
	DialTimeout      time.Duration
	IdleTimeout      time.Duration // tunnel closed after no traffic in either direction
	AuthFailMax      int           // failures per source within AuthWindow before blocking
	AuthWindow       time.Duration
	AuthBlock        time.Duration
	AuthFailDelay    time.Duration
	MaxHeaderBytes   int
}

func DefaultLimits() Limits {
	return Limits{
		MaxConns:         1024,
		MaxPerSource:     256,
		HandshakeTimeout: 20 * time.Second,
		DialTimeout:      10 * time.Second,
		IdleTimeout:      15 * time.Minute,
		AuthFailMax:      10,
		AuthWindow:       10 * time.Minute,
		AuthBlock:        15 * time.Minute,
		AuthFailDelay:    300 * time.Millisecond,
		MaxHeaderBytes:   16 << 10,
	}
}

type Server struct {
	Paths       Paths
	Limits      Limits
	Resolve     func(ctx context.Context, host string) ([]netip.Addr, error)
	Scan        func() (*NetView, error)
	Dial        func(ctx context.Context, addr string) (net.Conn, error)
	CoreDial    func(ctx context.Context, addr string) (net.Conn, error)
	MakePolicy  func(Config, *NetView) (*Policy, error)
	ConfPoll    time.Duration
	ARP         func() (map[string]string, error) // source IP -> MAC; nil = unknown
	MergeWindow time.Duration

	merge map[string]*mergeEntry // guarded by logMu
	arp   arpCache

	mu         sync.Mutex
	cfg        Config
	core       *CoreEndpoint
	coreSum    [32]byte
	cfgSum     [32]byte
	cfgSeen    bool
	pol        *Policy
	users      map[string]User
	authCache  map[[32]byte]string
	ln         net.Listener
	listenAddr string
	ln6        net.Listener // LazyCat network listener
	listenMesh string
	lastErr    string
	conns      map[uint64]*tracked
	perSrc     map[netip.Addr]int
	fails      map[netip.Addr]*failState
	started    time.Time

	nextID                            atomic.Uint64
	active, total, denied, authFailed atomic.Int64
	bytesUp, bytesDown                atomic.Int64
	logMu                             sync.Mutex
}

type tracked struct {
	conn net.Conn
	user atomic.Value // string
	anon atomic.Bool  // accepted without credentials
	up   net.Conn     // upstream, if any
	mu   sync.Mutex
}

type failState struct {
	times        []time.Time
	blockedUntil time.Time
}

func NewServer(dir string) *Server {
	return &Server{
		Paths:  Paths{Dir: dir},
		Limits: DefaultLimits(),
		Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		Scan: ScanNetwork,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{KeepAlive: 60 * time.Second}
			return d.DialContext(ctx, "tcp", addr)
		},
		CoreDial: func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{KeepAlive: 60 * time.Second}
			return d.DialContext(ctx, "tcp", addr)
		},
		MakePolicy:  BuildPolicy,
		ConfPoll:    time.Second,
		ARP:         readProcARP,
		MergeWindow: DefaultMergeWindow,
		users:       map[string]User{},
		authCache:   map[[32]byte]string{},
		conns:       map[uint64]*tracked{},
		perSrc:      map[netip.Addr]int{},
		fails:       map[netip.Addr]*failState{},
	}
}

// NewServerDefault returns a server whose resolver asks the core's DNS (over
// its controller socket) and falls back to the system resolver.
func NewServerDefault(dir string) *Server {
	s := NewServer(dir)
	s.Resolve = s.resolveDefault
	return s
}

func (s *Server) resolveDefault(ctx context.Context, host string) ([]netip.Addr, error) {
	if ips, err := coreResolve(ctx, s.Paths.ControllerSock(), host); err == nil && len(ips) > 0 {
		return ips, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// coreResolve queries mihomo's /dns/query (A records) over its unix socket.
func coreResolve(ctx context.Context, sock, host string) ([]netip.Addr, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://mihomo/dns/query?type=A&name="+url.QueryEscape(host), nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for _, a := range out.Answer {
		if a.Type != 1 {
			continue
		}
		if ip, err := netip.ParseAddr(a.Data); err == nil {
			ips = append(ips, ip.Unmap())
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records (status %d)", out.Status)
	}
	return ips, nil
}

// Run applies the config file and keeps re-reading it until ctx ends.
func (s *Server) Run(ctx context.Context) {
	s.started = time.Now()
	tick := time.NewTicker(s.ConfPoll)
	defer tick.Stop()
	var lastScan, lastStatus time.Time
	var view *NetView
	for {
		changed := s.reloadConfigIfChanged()
		s.reloadCore()
		if view == nil || time.Since(lastScan) > 30*time.Second {
			v, err := s.Scan()
			if err != nil {
				s.setErr("读取网卡失败：" + err.Error())
			} else {
				changed = changed || view == nil || !sameView(view, v)
				view = v
			}
			lastScan = time.Now()
		}
		if changed && view != nil {
			s.apply(view)
		}
		if time.Since(lastStatus) > 3*time.Second || changed {
			s.writeStatus(view)
			lastStatus = time.Now()
		}
		s.flushMerge(false)
		select {
		case <-ctx.Done():
			s.mu.Lock()
			if s.ln != nil {
				s.ln.Close()
			}
			if s.ln6 != nil {
				s.ln6.Close()
			}
			s.mu.Unlock()
			s.flushMerge(true)
			return
		case <-tick.C:
		}
	}
}

func sameView(a, b *NetView) bool {
	x, _ := json.Marshal([]any{a.DefaultIf, a.DefaultIP, a.DefaultNet, a.IfaceList(), a.Routes})
	y, _ := json.Marshal([]any{b.DefaultIf, b.DefaultIP, b.DefaultNet, b.IfaceList(), b.Routes})
	return string(x) == string(y)
}

func (s *Server) reloadConfigIfChanged() bool {
	raw, err := os.ReadFile(s.Paths.Config())
	if err != nil {
		s.mu.Lock()
		first := !s.cfgSeen
		if first {
			s.cfg = DefaultConfig()
			s.cfgSeen = true
		}
		s.mu.Unlock()
		return first
	}
	sum := sha256.Sum256(raw)
	s.mu.Lock()
	same := s.cfgSeen && sum == s.cfgSum
	s.mu.Unlock()
	if same {
		return false
	}
	var cfg Config
	cfg, err = LoadConfig(s.Paths.Config())
	if err == nil {
		err = cfg.Validate()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfgSum, s.cfgSeen = sum, true
	if err != nil {
		s.lastErr = "配置文件无效，继续使用上一份配置：" + err.Error()
		return false
	}
	s.cfg = cfg
	return true
}

// reloadCore re-reads the core's endpoint file when it changes.
func (s *Server) reloadCore() {
	raw, err := os.ReadFile(s.Paths.CoreEndpoint())
	if err != nil {
		s.mu.Lock()
		s.core = nil
		s.mu.Unlock()
		return
	}
	sum := sha256.Sum256(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core != nil && sum == s.coreSum {
		return
	}
	var ep CoreEndpoint
	if json.Unmarshal(raw, &ep) != nil {
		return
	}
	// The core must sit on a private container network, never on the LAN or loopback of other hosts.
	if ap, err := netip.ParseAddrPort(ep.Addr); err != nil || !(ap.Addr().IsPrivate() || ap.Addr().IsLoopback()) {
		s.core = nil
		return
	}
	s.core, s.coreSum = &ep, sum
}

func (s *Server) setErr(e string) {
	s.mu.Lock()
	s.lastErr = e
	s.mu.Unlock()
}

// apply rebuilds policy and users and (re)opens or closes the listener.
func (s *Server) apply(view *NetView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.cfg
	s.users = map[string]User{}
	for _, u := range cfg.Users {
		if u.Enabled {
			s.users[u.Name] = u
		}
	}
	s.authCache = map[[32]byte]string{}
	// Close connections of accounts that were removed or disabled, and
	// credential-less connections once authentication becomes mandatory.
	for _, t := range s.conns {
		if cfg.RequireAuth && t.anon.Load() {
			t.close()
			continue
		}
		if u, _ := t.user.Load().(string); u != "" {
			if _, ok := s.users[u]; !ok {
				t.close()
			}
		}
	}
	pol, err := s.MakePolicy(cfg, view)
	if err != nil {
		s.lastErr = err.Error()
		s.stopLocked(true)
		return
	}
	s.pol = pol
	s.lastErr = ""
	if !cfg.Enabled {
		s.stopLocked(true)
		return
	}
	// Drop connections that the new policy would not accept (for example
	// LazyCat-network clients after that listener is switched off).
	for _, t := range s.conns {
		if pol.CheckSourceAt(addrOf(t.conn.RemoteAddr()), addrOf(t.conn.LocalAddr())) != "" {
			t.close()
		}
	}
	addr := net.JoinHostPort(pol.ListenIP.String(), strconv.Itoa(cfg.Port))
	if s.ln == nil || s.listenAddr != addr {
		if s.ln != nil {
			s.ln.Close()
			s.ln, s.listenAddr = nil, ""
		}
		// tcp4 + an explicit LAN address: never 0.0.0.0, ::, docker or LazyCat interfaces.
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			s.lastErr = "监听失败：" + err.Error()
		} else {
			s.ln, s.listenAddr = ln, addr
			go s.acceptLoop(ln)
		}
	}
	mesh := ""
	if pol.MeshIP.IsValid() {
		mesh = net.JoinHostPort(pol.MeshIP.String(), strconv.Itoa(cfg.Port))
	}
	if s.ln6 != nil && s.listenMesh != mesh {
		s.ln6.Close()
		s.ln6, s.listenMesh = nil, ""
	}
	if mesh != "" && s.ln6 == nil {
		// tcp6 on the single LazyCat-network address only.
		ln, err := net.Listen("tcp6", mesh)
		if err != nil {
			pol.MeshNote = "组网地址监听失败：" + err.Error()
		} else {
			s.ln6, s.listenMesh = ln, mesh
			go s.acceptLoop(ln)
		}
	}
}

func (s *Server) stopLocked(closeConns bool) {
	if s.ln != nil {
		s.ln.Close()
		s.ln, s.listenAddr = nil, ""
	}
	if s.ln6 != nil {
		s.ln6.Close()
		s.ln6, s.listenMesh = nil, ""
	}
	if closeConns {
		for _, t := range s.conns {
			t.close()
		}
	}
}

func (t *tracked) close() {
	t.conn.Close()
	t.mu.Lock()
	if t.up != nil {
		t.up.Close()
	}
	t.mu.Unlock()
}

// ListenAddr returns the current listen address ("" when stopped).
func (s *Server) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listenAddr
}

// MeshListenAddr returns the LazyCat-network listen address ("" when off).
func (s *Server) MeshListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listenMesh
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		go s.handle(c)
	}
}

func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

func (s *Server) handle(c net.Conn) {
	id := s.nextID.Add(1)
	src := addrOf(c.RemoteAddr())
	rec := ConnRecord{Time: time.Now(), ID: id, Src: c.RemoteAddr().String()}
	s.mu.Lock()
	pol := s.pol
	s.mu.Unlock()
	if pol == nil {
		c.Close()
		return
	}
	if r := pol.CheckSourceAt(src, addrOf(c.LocalAddr())); r != "" {
		c.Close()
		rec.Result, rec.Reason = "src_denied", r
		s.denied.Add(1)
		s.logRecord(rec)
		return
	}
	s.mu.Lock()
	if len(s.conns) >= s.Limits.MaxConns || s.perSrc[src] >= s.Limits.MaxPerSource {
		s.mu.Unlock()
		c.Close()
		rec.Result, rec.Reason = "busy", "并发连接数已达上限"
		s.logRecord(rec)
		return
	}
	t := &tracked{conn: c}
	t.user.Store("")
	s.conns[id] = t
	s.perSrc[src]++
	s.mu.Unlock()
	s.active.Add(1)
	s.total.Add(1)
	defer func() {
		c.Close()
		t.mu.Lock()
		if t.up != nil {
			t.up.Close()
		}
		t.mu.Unlock()
		s.mu.Lock()
		delete(s.conns, id)
		if s.perSrc[src]--; s.perSrc[src] <= 0 {
			delete(s.perSrc, src)
		}
		s.mu.Unlock()
		s.active.Add(-1)
	}()

	c.SetDeadline(time.Now().Add(s.Limits.HandshakeTimeout))
	br := bufio.NewReaderSize(c, s.Limits.MaxHeaderBytes)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	switch first[0] {
	case 0x05:
		s.serveSOCKS5(c, br, t, src, rec)
	case 0x04:
		rec.Result, rec.Reason = "bad_request", "不支持 SOCKS4"
		s.logRecord(rec)
	default:
		s.serveHTTP(c, br, t, src, rec)
	}
}

// ---- authentication -------------------------------------------------------

// noAuthAllowed reports whether src may connect without credentials: the
// switch is on and the source is inside the LAN (checked again here, on top
// of the source check every connection already passed).
func (s *Server) noAuthAllowed(t *tracked, src netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.cfg.RequireAuth && s.pol != nil && s.pol.CheckSourceAt(src, addrOf(t.conn.LocalAddr())) == ""
}

func (s *Server) markAnon(t *tracked, rec *ConnRecord, src netip.Addr) {
	t.anon.Store(true)
	rec.NoAuth = true
	rec.MAC = s.macOf(src)
}

var dummyUser = func() User {
	salt, hash, _ := HashPassword("dummy-password-for-timing")
	return User{Salt: salt, Hash: hash}
}()

// authenticate returns "" on success, otherwise a result code (auth_failed / auth_blocked).
func (s *Server) authenticate(src netip.Addr, name, pass string) (string, string) {
	now := time.Now()
	s.mu.Lock()
	fs := s.fails[src]
	if fs != nil && now.Before(fs.blockedUntil) {
		s.mu.Unlock()
		return "auth_blocked", "认证失败次数过多，暂时封禁到 " + fs.blockedUntil.Format("15:04:05")
	}
	key := sha256.Sum256([]byte(name + "\x00" + pass))
	if s.authCache[key] == name {
		if _, ok := s.users[name]; ok {
			s.mu.Unlock()
			return "", ""
		}
	}
	u, ok := s.users[name]
	s.mu.Unlock()
	if !ok {
		dummyUser.Check(pass)
	} else if u.Check(pass) {
		s.mu.Lock()
		if cur, still := s.users[name]; still && cur.Hash == u.Hash {
			s.authCache[key] = name
		}
		s.mu.Unlock()
		return "", ""
	}
	s.authFailed.Add(1)
	s.mu.Lock()
	if fs == nil {
		fs = &failState{}
		s.fails[src] = fs
	}
	keep := fs.times[:0]
	for _, t := range fs.times {
		if now.Sub(t) < s.Limits.AuthWindow {
			keep = append(keep, t)
		}
	}
	fs.times = append(keep, now)
	reason := "用户名或密码错误"
	if !ok {
		reason = "用户不存在或已停用"
	}
	if len(fs.times) >= s.Limits.AuthFailMax {
		fs.blockedUntil = now.Add(s.Limits.AuthBlock)
		fs.times = nil
		reason += "；该来源已被暂时封禁"
	}
	// Bound memory: drop stale entries.
	if len(s.fails) > 4096 {
		for k, v := range s.fails {
			if now.After(v.blockedUntil) && len(v.times) == 0 {
				delete(s.fails, k)
			}
		}
	}
	s.mu.Unlock()
	time.Sleep(s.Limits.AuthFailDelay)
	return "auth_failed", reason
}

// ---- destinations ---------------------------------------------------------

type dialResult struct {
	conn    net.Conn
	ip      string
	via     string // direct | core
	coreSrc string
	result  string // "" on success
	reason  string
}

func (d dialResult) fill(r *ConnRecord) {
	r.IP, r.Via, r.CoreSrc = d.ip, d.via, d.coreSrc
}

// dialTarget resolves host, checks every resulting address and connects.
// If any resolved address is refused the whole request is refused. LAN
// destinations (and everything in direct mode) are dialed directly at the
// checked IP; other destinations go through the mihomo core.
func (s *Server) dialTarget(ctx context.Context, host string, port int) dialResult {
	s.mu.Lock()
	pol, mode, core := s.pol, s.cfg.EgressMode, s.core
	s.mu.Unlock()
	if port <= 0 || port > 65535 {
		return dialResult{result: "bad_request", reason: "端口无效"}
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	var ips []netip.Addr
	isDomain := false
	resolveFailed := false
	if a, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{a.Unmap()}
	} else {
		if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\\x00") {
			return dialResult{result: "bad_request", reason: "主机名无效"}
		}
		isDomain = true
		rctx, cancel := context.WithTimeout(ctx, s.Limits.DialTimeout)
		res, err := s.Resolve(rctx, host)
		cancel()
		if err != nil || len(res) == 0 {
			resolveFailed = true
		}
		for _, a := range res {
			ips = append(ips, a.Unmap())
		}
	}
	for _, a := range ips {
		if r := pol.CheckDest(a); r != "" {
			s.denied.Add(1)
			return dialResult{ip: a.String(), result: "dst_denied", reason: r}
		}
	}
	allLAN := len(ips) > 0
	for _, a := range ips {
		if !inAny(a, pol.LAN) {
			allLAN = false
		}
	}
	if mode != EgressDirect && !allLAN {
		// Through the core. A domain that did not resolve locally is still
		// passed on by name: the core rejects private and reserved addresses
		// itself before any direct connection, and nodes resolve remotely.
		ipStr := ""
		if len(ips) > 0 {
			ipStr = ips[0].String()
		}
		target := host
		if !isDomain {
			target = ips[0].String()
		}
		return s.dialCore(ctx, core, target, port, ipStr)
	}
	if resolveFailed {
		return dialResult{result: "dial_failed", reason: "域名解析失败"}
	}
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].Is4() && !ips[j].Is4() })
	dctx, cancel := context.WithTimeout(ctx, s.Limits.DialTimeout)
	defer cancel()
	var lastErr error
	for _, a := range ips {
		c, err := s.Dial(dctx, net.JoinHostPort(a.String(), strconv.Itoa(port)))
		if err == nil {
			// Defense in depth: confirm the connected peer is the checked address.
			if got := addrOf(c.RemoteAddr()); got.IsValid() && got != a {
				c.Close()
				return dialResult{ip: got.String(), via: "direct", result: "dst_denied", reason: "实际连接地址与检查地址不一致"}
			}
			return dialResult{conn: c, ip: a.String(), via: "direct"}
		}
		lastErr = err
	}
	return dialResult{ip: ips[0].String(), via: "direct", result: "dial_failed", reason: shortErr(lastErr)}
}

// dialCore opens a SOCKS5 CONNECT through the core's private listener.
func (s *Server) dialCore(ctx context.Context, core *CoreEndpoint, host string, port int, ip string) dialResult {
	res := dialResult{ip: ip, via: "core"}
	if core == nil || core.Addr == "" {
		res.result, res.reason = "dial_failed", "分流内核未就绪"
		return res
	}
	dctx, cancel := context.WithTimeout(ctx, s.Limits.DialTimeout)
	defer cancel()
	c, err := s.CoreDial(dctx, core.Addr)
	if err != nil {
		res.result, res.reason = "dial_failed", "无法连接分流内核："+shortErr(err)
		return res
	}
	res.coreSrc = c.LocalAddr().String()
	// The core may need a while to reach a remote node; allow the handshake timeout.
	c.SetDeadline(time.Now().Add(s.Limits.HandshakeTimeout))
	code, err := socks5ClientConnect(c, core.User, core.Pass, host, port)
	if err != nil {
		c.Close()
		res.result, res.reason = "dial_failed", "分流内核握手失败："+err.Error()
		return res
	}
	switch code {
	case 0x00:
		c.SetDeadline(time.Time{})
		res.conn = c
		return res
	case 0x02:
		c.Close()
		s.denied.Add(1)
		res.result, res.reason = "dst_denied", "分流内核拒绝（私有或保留地址）"
		return res
	default:
		c.Close()
		res.result, res.reason = "dial_failed", fmt.Sprintf("经分流内核连接失败（SOCKS 代码 %d）", code)
		return res
	}
}

// socks5ClientConnect performs a SOCKS5 user/password handshake and CONNECT,
// returning the server's reply code.
func socks5ClientConnect(c net.Conn, user, pass, host string, port int) (byte, error) {
	if len(user) > 255 || len(pass) > 255 || len(host) > 255 {
		return 0, errors.New("参数过长")
	}
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		return 0, err
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil {
		return 0, err
	}
	if b[0] != 5 || b[1] != 2 {
		return 0, fmt.Errorf("认证方式不符（%d）", b[1])
	}
	msg := []byte{1, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	if _, err := c.Write(msg); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(c, b); err != nil {
		return 0, err
	}
	if b[1] != 0 {
		return 0, errors.New("认证被拒")
	}
	req := []byte{5, 1, 0}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.Is4() {
			req = append(req, 1)
		} else {
			req = append(req, 4)
		}
		req = append(req, a.AsSlice()...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return 0, err
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return 0, err
	}
	var skip int
	switch h[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return 0, err
		}
		skip = int(l[0])
	default:
		return h[1], nil
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return 0, err
	}
	return h[1], nil
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

// ---- relaying -------------------------------------------------------------

type countConn struct {
	net.Conn
	up, down *int64
	last     *atomic.Int64
}

func (c countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		atomic.AddInt64(c.down, int64(n))
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		atomic.AddInt64(c.up, int64(n))
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

// relay copies both ways until either side closes or the tunnel is idle too long.
func (s *Server) relay(client net.Conn, clientR io.Reader, up net.Conn, upR io.Reader, last *atomic.Int64) {
	client.SetDeadline(time.Time{})
	up.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, clientR)
		if tc, ok := up.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else if cc, ok := up.(countConn); ok {
			if tc, ok := cc.Conn.(interface{ CloseWrite() error }); ok {
				tc.CloseWrite()
			}
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upR)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	watch := time.NewTicker(s.Limits.IdleTimeout / 10)
	defer watch.Stop()
	n := 0
	for n < 2 {
		select {
		case <-done:
			n++
			if n == 1 {
				// One side finished; give the other a bounded time to drain.
				client.SetReadDeadline(time.Now().Add(s.Limits.IdleTimeout))
				up.SetReadDeadline(time.Now().Add(s.Limits.IdleTimeout))
			}
		case <-watch.C:
			if time.Since(time.Unix(0, last.Load())) > s.Limits.IdleTimeout {
				client.Close()
				up.Close()
			}
		}
	}
}

// ---- SOCKS5 ---------------------------------------------------------------

func (s *Server) serveSOCKS5(c net.Conn, br *bufio.Reader, t *tracked, src netip.Addr, rec ConnRecord) {
	rec.Proto = "socks5"
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	hasUP, hasNone := false, false
	for _, m := range methods {
		switch m {
		case 0x02:
			hasUP = true
		case 0x00:
			hasNone = true
		}
	}
	switch {
	case hasUP:
		c.Write([]byte{0x05, 0x02})
		// RFC 1929
		v := make([]byte, 2)
		if _, err := io.ReadFull(br, v); err != nil || v[0] != 0x01 {
			return
		}
		uname := make([]byte, v[1])
		if _, err := io.ReadFull(br, uname); err != nil {
			return
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(br, pl); err != nil {
			return
		}
		pass := make([]byte, pl[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		if len(uname) == 0 && len(pass) == 0 && s.noAuthAllowed(t, src) {
			// Some clients pick username/password even with no account
			// configured and send it empty: that is "no credentials".
			c.Write([]byte{0x01, 0x00})
			s.markAnon(t, &rec, src)
			break
		}
		rec.User = string(uname)
		if res, reason := s.authenticate(src, string(uname), string(pass)); res != "" {
			c.Write([]byte{0x01, 0x01})
			rec.Result, rec.Reason = res, reason
			s.logRecord(rec)
			return
		}
		c.Write([]byte{0x01, 0x00})
		t.user.Store(string(uname))
	case hasNone && s.noAuthAllowed(t, src):
		c.Write([]byte{0x05, 0x00})
		s.markAnon(t, &rec, src)
	default:
		c.Write([]byte{0x05, 0xFF})
		rec.Result, rec.Reason = "auth_failed", "客户端未提供用户名密码认证"
		s.authFailed.Add(1)
		s.logRecord(rec)
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = netip.AddrFrom4([4]byte(b)).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = netip.AddrFrom16([16]byte(b)).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	default:
		socksReply(c, 0x08, nil)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))
	rec.Target = net.JoinHostPort(host, strconv.Itoa(port))
	if req[1] != 0x01 {
		socksReply(c, 0x07, nil)
		rec.Result, rec.Reason = "bad_request", "只支持 CONNECT 命令"
		s.logRecord(rec)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.Limits.HandshakeTimeout)
	d := s.dialTarget(ctx, host, port)
	cancel()
	up, res, reason := d.conn, d.result, d.reason
	d.fill(&rec)
	if res != "" {
		code := byte(0x01)
		switch res {
		case "dst_denied":
			code = 0x02
		case "dial_failed":
			code = 0x05
			if strings.Contains(reason, "解析") {
				code = 0x04
			}
		}
		socksReply(c, code, nil)
		rec.Result, rec.Reason = res, reason
		s.logRecord(rec)
		return
	}
	t.mu.Lock()
	t.up = up
	t.mu.Unlock()
	socksReply(c, 0x00, up.LocalAddr())
	s.tunnel(c, br, up, nil, rec)
}

func socksReply(c net.Conn, code byte, bind net.Addr) {
	b := []byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if ta, ok := bind.(*net.TCPAddr); ok {
		if ip4 := ta.IP.To4(); ip4 != nil {
			copy(b[4:8], ip4)
			binary.BigEndian.PutUint16(b[8:], uint16(ta.Port))
		}
	}
	c.Write(b)
}

// tunnel relays bytes and writes one log record with the totals.
func (s *Server) tunnel(c net.Conn, br *bufio.Reader, up net.Conn, upBuffered []byte, rec ConnRecord) {
	var nUp, nDown int64
	last := &atomic.Int64{}
	last.Store(time.Now().UnixNano())
	cu := countConn{Conn: up, up: &nUp, down: &nDown, last: last}
	var upR io.Reader = cu
	if len(upBuffered) > 0 {
		c.Write(upBuffered)
	}
	start := time.Now()
	s.relay(c, br, cu, upR, last)
	rec.Result = "ok"
	rec.Up, rec.Down = nUp, nDown
	rec.DurMS = time.Since(start).Milliseconds()
	s.bytesUp.Add(nUp)
	s.bytesDown.Add(nDown)
	s.logRecord(rec)
}

// ---- HTTP proxy -----------------------------------------------------------

func proxyAuth(h http.Header) (string, string, bool) {
	v := h.Get("Proxy-Authorization")
	const p = "Basic "
	if len(v) < len(p) || !strings.EqualFold(v[:len(p)], p) {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(p):]))
	if err != nil {
		return "", "", false
	}
	u, pw, ok := strings.Cut(string(b), ":")
	return u, pw, ok
}

func httpError(c net.Conn, code int, extra string) {
	msg := http.StatusText(code)
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n%sContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n",
		code, msg, extra, len(msg)+1, msg)
}

const authChallenge = "Proxy-Authenticate: Basic realm=\"lan-proxy\"\r\n"

func (s *Server) serveHTTP(c net.Conn, br *bufio.Reader, t *tracked, src netip.Addr, rec ConnRecord) {
	var up net.Conn
	var upBr *bufio.Reader
	var upKey string
	var upRec ConnRecord
	var nUp, nDown int64
	var upStart time.Time
	last := &atomic.Int64{}
	var inflight atomic.Bool
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		// Idle watchdog while a request or upgraded stream is in flight.
		tk := time.NewTicker(s.Limits.IdleTimeout / 10)
		defer tk.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-tk.C:
				if inflight.Load() && time.Since(time.Unix(0, last.Load())) > s.Limits.IdleTimeout {
					t.close()
					return
				}
			}
		}
	}()
	closeUp := func() {
		if up == nil {
			return
		}
		up.Close()
		upRec.Result = "ok"
		upRec.Up, upRec.Down = nUp, nDown
		upRec.DurMS = time.Since(upStart).Milliseconds()
		s.bytesUp.Add(nUp)
		s.bytesDown.Add(nDown)
		s.logRecord(upRec)
		up = nil
	}
	defer closeUp()
	for {
		c.SetReadDeadline(time.Now().Add(s.Limits.HandshakeTimeout))
		if up != nil {
			// Keep-alive between requests: allow the normal idle time.
			c.SetReadDeadline(time.Now().Add(s.Limits.IdleTimeout))
		}
		req, err := readRequestLimited(br, s.Limits.MaxHeaderBytes)
		if err != nil {
			if up == nil && !errors.Is(err, io.EOF) {
				rec.Proto, rec.Result, rec.Reason = "http", "bad_request", "无法解析 HTTP 请求"
				s.logRecord(rec)
				httpError(c, http.StatusBadRequest, "")
			}
			return
		}
		r := rec
		r.Time = time.Now()
		if req.Method == http.MethodConnect {
			r.Proto = "connect"
			r.Target = req.Host
		} else {
			r.Proto = "http"
		}
		name, pass, ok := proxyAuth(req.Header)
		switch {
		case (!ok && req.Header.Get("Proxy-Authorization") == "" || ok && name == "" && pass == "") && s.noAuthAllowed(t, src):
			s.markAnon(t, &r, src)
		case !ok:
			httpError(c, http.StatusProxyAuthRequired, authChallenge)
			return
		default:
			r.User = name
			if res, reason := s.authenticate(src, name, pass); res != "" {
				r.Result, r.Reason = res, reason
				if r.Proto == "http" && req.URL != nil {
					r.Target = req.URL.Host
				}
				s.logRecord(r)
				if res == "auth_blocked" {
					httpError(c, http.StatusForbidden, "")
				} else {
					httpError(c, http.StatusProxyAuthRequired, authChallenge)
				}
				return
			}
			t.user.Store(name)
		}
		if req.Method == http.MethodConnect {
			closeUp()
			host, ps, err := net.SplitHostPort(req.Host)
			port, _ := strconv.Atoi(ps)
			if err != nil {
				r.Result, r.Reason = "bad_request", "CONNECT 目标格式无效"
				s.logRecord(r)
				httpError(c, http.StatusBadRequest, "")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), s.Limits.HandshakeTimeout)
			d := s.dialTarget(ctx, host, port)
			cancel()
			uc, res, reason := d.conn, d.result, d.reason
			d.fill(&r)
			if res != "" {
				r.Result, r.Reason = res, reason
				s.logRecord(r)
				code := http.StatusBadGateway
				if res == "dst_denied" {
					code = http.StatusForbidden
				} else if res == "bad_request" {
					code = http.StatusBadRequest
				}
				httpError(c, code, "")
				return
			}
			t.mu.Lock()
			t.up = uc
			t.mu.Unlock()
			io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
			s.tunnel(c, br, uc, nil, r)
			return
		}
		// Plain HTTP forward proxy (absolute-form request).
		if req.URL == nil || req.URL.Host == "" || !strings.EqualFold(req.URL.Scheme, "http") {
			r.Result, r.Reason = "bad_request", "只支持 http:// 绝对地址请求；HTTPS 请使用 CONNECT"
			s.logRecord(r)
			httpError(c, http.StatusBadRequest, "")
			return
		}
		host := req.URL.Hostname()
		port := 80
		if p := req.URL.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		r.Target = key
		if up == nil || upKey != key {
			closeUp()
			ctx, cancel := context.WithTimeout(context.Background(), s.Limits.HandshakeTimeout)
			d := s.dialTarget(ctx, host, port)
			cancel()
			uc, res, reason := d.conn, d.result, d.reason
			d.fill(&r)
			if res != "" {
				r.Result, r.Reason = res, reason
				s.logRecord(r)
				code := http.StatusBadGateway
				if res == "dst_denied" {
					code = http.StatusForbidden
				}
				httpError(c, code, "")
				return
			}
			nUp, nDown = 0, 0
			last.Store(time.Now().UnixNano())
			up = countConn{Conn: uc, up: &nUp, down: &nDown, last: last}
			upBr = bufio.NewReader(up)
			upKey, upRec, upStart = key, r, time.Now()
			t.mu.Lock()
			t.up = uc
			t.mu.Unlock()
		}
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")
		req.RequestURI = ""
		c.SetDeadline(time.Time{})
		last.Store(time.Now().UnixNano())
		inflight.Store(true)
		if err := req.Write(up); err != nil {
			return
		}
		resp, err := http.ReadResponse(upBr, req)
		if err != nil {
			httpError(c, http.StatusBadGateway, "")
			return
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			if err := resp.Write(c); err != nil {
				return
			}
			s.relay(c, br, up, upBr, last)
			return
		}
		werr := resp.Write(c)
		resp.Body.Close()
		inflight.Store(false)
		if werr != nil || resp.Close || req.Close {
			return
		}
	}
}

// readRequestLimited refuses requests whose header block does not fit in the reader's buffer.
func readRequestLimited(br *bufio.Reader, max int) (*http.Request, error) {
	for {
		n := br.Buffered()
		if n > 0 {
			b, _ := br.Peek(n)
			if bytes.Contains(b, []byte("\r\n\r\n")) || bytes.Contains(b, []byte("\n\n")) {
				break
			}
			if n >= max || n >= br.Size() {
				return nil, errHeaderTooLarge
			}
		}
		if _, err := br.Peek(n + 1); err != nil { // wait for more bytes
			return nil, err
		}
	}
	return http.ReadRequest(br)
}

var errHeaderTooLarge = errors.New("header too large")

// ---- logging and status ---------------------------------------------------

func (s *Server) writeLine(r ConnRecord) {
	b, _ := json.Marshal(r)
	if err := AppendRotating(s.Paths.ConnLog(), append(b, '\n'), LogFileBytes, LogFiles); err != nil {
		log.Printf("conn log: %v", err)
	}
}

// logRecord writes the first of a run of identical connections at once and
// folds repeats within s.MergeWindow into one record with a count (N).
func (s *Server) logRecord(r ConnRecord) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if s.merge == nil {
		s.merge = map[string]*mergeEntry{}
	}
	k := mergeKey(r)
	if e := s.merge[k]; e != nil && time.Since(e.start) < s.MergeWindow {
		if e.rec.N == 0 {
			e.rec = r
		} else {
			e.rec.Time, e.rec.Src, e.rec.ID, e.rec.CoreSrc, e.rec.IP = r.Time, r.Src, r.ID, r.CoreSrc, r.IP
			e.rec.Up += r.Up
			e.rec.Down += r.Down
			e.rec.DurMS += r.DurMS
			if r.MAC != "" {
				e.rec.MAC = r.MAC
			}
		}
		e.rec.N++
		return
	}
	if len(s.merge) >= mergeMax {
		s.flushMergeLocked(true)
	}
	s.writeLine(r)
	s.merge[k] = &mergeEntry{start: time.Now()}
}

// flushMerge writes folded records whose window has ended (all if force).
func (s *Server) flushMerge(force bool) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.flushMergeLocked(force)
}

func (s *Server) flushMergeLocked(force bool) {
	for k, e := range s.merge {
		if force || time.Since(e.start) >= s.MergeWindow {
			if e.rec.N > 0 {
				s.writeLine(e.rec)
			}
			delete(s.merge, k)
		}
	}
}

func (s *Server) macOf(ip netip.Addr) string {
	if s.ARP == nil {
		return ""
	}
	return s.arp.lookupWith(s.ARP, ip)
}

func (s *Server) writeStatus(view *NetView) {
	s.mu.Lock()
	st := Status{
		Version:    Version,
		PID:        os.Getpid(),
		Started:    s.started,
		Updated:    time.Now(),
		Enabled:    s.cfg.Enabled,
		Listening:  s.ln != nil,
		Listen:     s.listenAddr,
		ListenMesh: s.listenMesh,
		Error:      s.lastErr,
		Users:      len(s.users),
	}
	if s.pol != nil {
		for _, p := range s.pol.LAN {
			st.LANCIDRs = append(st.LANCIDRs, p.String())
		}
		if s.pol.Mesh.IsValid() {
			st.MeshCIDR = s.pol.Mesh.String()
		}
		st.MeshNote = s.pol.MeshNote
	}
	seen := map[string]bool{}
	for _, t := range s.conns {
		if u, _ := t.user.Load().(string); u != "" && !seen[u] {
			seen[u] = true
			st.ActiveIDs = append(st.ActiveIDs, u)
		}
	}
	s.mu.Unlock()
	sort.Strings(st.ActiveIDs)
	if view != nil {
		st.DefaultIf = view.DefaultIf
		st.Interfaces = view.IfaceList()
	}
	st.Active, st.Total, st.Denied = s.active.Load(), s.total.Load(), s.denied.Load()
	st.AuthFailed = s.authFailed.Load()
	st.BytesUp, st.BytesDown = s.bytesUp.Load(), s.bytesDown.Load()
	if err := WriteJSONAtomic(s.Paths.Status(), st); err != nil {
		log.Printf("status: %v", err)
	}
}
