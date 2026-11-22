package core

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test harness: the proxy listens on 127.0.0.1 and treats 127.0.0.0/8 as the
// LAN (BuildPolicy forbids this in production). Destinations use fake public
// addresses that the Dial hook maps to local test servers, so the real policy
// code decides every request.

const (
	pubEcho = "93.184.216.34" // fake public host running an echo server
	pubHTTP = "93.184.216.35" // fake public host running an HTTP server
)

type harness struct {
	mode   string
	t      *testing.T
	s      *Server
	dir    string
	addr   string
	dials  atomic.Int64
	cancel context.CancelFunc
}

type fakeAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeAddrConn) RemoteAddr() net.Addr { return c.remote }
func (c fakeAddrConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func startEcho(t *testing.T) string {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func startHTTP(t *testing.T) string {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s host=%s proxyauth=%q", r.URL.RequestURI(), r.Host, r.Header.Get("Proxy-Authorization"))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func newHarness(t *testing.T, lan string, tweak func(*Server)) *harness {
	return newHarnessMode(t, lan, EgressDirect, tweak)
}

func newHarnessMode(t *testing.T, lan, mode string, tweak func(*Server)) *harness {
	h := &harness{t: t, dir: t.TempDir(), mode: mode}
	echo, web := startEcho(t), startHTTP(t)
	view := fakeView()
	delete(view.LocalIPs, netip.MustParseAddr("127.0.0.1")) // the test client connects from here
	s := NewServer(h.dir)
	s.ConfPoll = 20 * time.Millisecond
	s.Limits.AuthFailDelay = 0
	s.Scan = func() (*NetView, error) { return view, nil }
	s.MakePolicy = func(c Config, v *NetView) (*Policy, error) {
		p, err := BuildPolicy(DefaultConfig(), v)
		if err != nil {
			return nil, err
		}
		p.ListenIP = netip.MustParseAddr("127.0.0.1")
		p.LAN = []netip.Prefix{netip.MustParsePrefix(lan)}
		for _, s := range c.ExtraDeny {
			pf, _ := ParsePrefix(s)
			p.ExtraDeny = append(p.ExtraDeny, pf)
		}
		return p, nil
	}
	s.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "public.test":
			return []netip.Addr{netip.MustParseAddr(pubEcho)}, nil
		case "web.test":
			return []netip.Addr{netip.MustParseAddr(pubHTTP)}, nil
		case "nas.test":
			return []netip.Addr{netip.MustParseAddr("192.168.3.89")}, nil
		case "rebind.test": // one public and one NAS address
			return []netip.Addr{netip.MustParseAddr(pubEcho), netip.MustParseAddr("::ffff:192.168.3.89")}, nil
		case "docker.test":
			return []netip.Addr{netip.MustParseAddr("172.17.0.2")}, nil
		case "localhost":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, nil
		}
		return nil, fmt.Errorf("no such host")
	}
	s.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		h.dials.Add(1)
		host, port, _ := net.SplitHostPort(addr)
		var real string
		switch host {
		case pubEcho:
			real = echo
		case pubHTTP:
			real = web
		case "192.168.3.50": // a LAN device
			real = echo
		default:
			return nil, fmt.Errorf("test dial to %s not expected", addr)
		}
		c, err := net.Dial("tcp4", real)
		if err != nil {
			return nil, err
		}
		pp, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
		return fakeAddrConn{c, pp}, nil
	}
	if tweak != nil {
		tweak(s)
	}
	h.s = s
	// Free port for the proxy.
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := DefaultConfig()
	cfg.Port = port
	cfg.EgressMode = h.mode
	h.addUser(&cfg, "alice", "alice-password", true)
	h.addUser(&cfg, "bob", "bob-password", false)
	h.writeConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		time.Sleep(50 * time.Millisecond) // let connection goroutines finish logging
	})
	deadline := time.Now().Add(3 * time.Second)
	for s.ListenAddr() == "" {
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %s", s.lastErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.addr = s.ListenAddr()
	return h
}

func (h *harness) addUser(c *Config, name, pw string, enabled bool) {
	salt, hash, _ := HashPassword(pw)
	c.Users = append(c.Users, User{Name: name, Salt: salt, Hash: hash, Enabled: enabled})
}

func (h *harness) writeConfig(c Config) {
	if err := WriteJSONAtomic(filepath.Join(h.dir, "config.json"), c); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) readConfig() Config {
	c, err := LoadConfig(filepath.Join(h.dir, "config.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

func (h *harness) logs() []ConnRecord {
	time.Sleep(30 * time.Millisecond)
	b, _ := os.ReadFile(filepath.Join(h.dir, "conn.jsonl"))
	var out []ConnRecord
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r ConnRecord
		if json.Unmarshal([]byte(l), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

func (h *harness) lastLog(result string) *ConnRecord {
	for i := 0; i < 50; i++ {
		ls := h.logs()
		for j := len(ls) - 1; j >= 0; j-- {
			if ls[j].Result == result {
				return &ls[j]
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("no log with result %s; logs: %+v", result, h.logs())
	return nil
}

// socks dials the proxy and performs a SOCKS5 handshake. It returns the
// connection, the auth status byte and the reply code (0xFF if not reached).
func (h *harness) socks(user, pass, host string, port int) (net.Conn, byte, byte) {
	c, err := net.Dial("tcp4", h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 2})
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil {
		return c, 0xEE, 0xFF
	}
	msg := []byte{1, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	c.Write(msg)
	if _, err := io.ReadFull(c, b); err != nil || b[1] != 0 {
		return c, b[1], 0xFF
	}
	req := []byte{5, 1, 0}
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		req = append(req, 1)
		req = append(req, a.AsSlice()...)
	} else if err == nil {
		req = append(req, 4)
		a16 := a.As16()
		req = append(req, a16[:]...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return c, 0, 0xFE
	}
	return c, 0, rep[1]
}

func basic(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

func (h *harness) connect(auth, target string) (net.Conn, *bufio.Reader, int) {
	c, err := net.Dial("tcp4", h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if auth != "" {
		fmt.Fprintf(c, "Proxy-Authorization: %s\r\n", auth)
	}
	io.WriteString(c, "\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return c, br, 0
	}
	return c, br, resp.StatusCode
}

func echoCheck(t *testing.T, c net.Conn, r io.Reader) {
	t.Helper()
	msg := "hello through the proxy"
	io.WriteString(c, msg)
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo got %q err %v", buf, err)
	}
}

// ---- positive controls ----------------------------------------------------

func TestSOCKS5OK(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	c, a, rep := h.socks("alice", "alice-password", "public.test", 7)
	if a != 0 || rep != 0 {
		t.Fatalf("auth %d rep %d", a, rep)
	}
	echoCheck(t, c, c)
	c.Close()
	r := h.lastLog("ok")
	if r.User != "alice" || r.Proto != "socks5" || r.Target != "public.test:7" || r.IP != pubEcho || r.Up == 0 || r.Down == 0 {
		t.Fatalf("log %+v", r)
	}
}

func TestHTTPConnectOK(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	c, br, code := h.connect(basic("alice", "alice-password"), "public.test:443")
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	echoCheck(t, c, br)
	c.Close()
	if r := h.lastLog("ok"); r.Proto != "connect" || r.User != "alice" {
		t.Fatalf("log %+v", r)
	}
}

func TestHTTPPlainOK(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	c, _ := net.Dial("tcp4", h.addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	for i := 0; i < 2; i++ { // two requests on one keep-alive connection
		fmt.Fprintf(c, "GET http://web.test/a?b=%d HTTP/1.1\r\nHost: web.test\r\nProxy-Authorization: %s\r\nProxy-Connection: keep-alive\r\n\r\n", i, basic("alice", "alice-password"))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		want := fmt.Sprintf(`path=/a?b=%d host=web.test proxyauth=""`, i)
		if resp.StatusCode != 200 || string(body) != want {
			t.Fatalf("got %d %q want %q", resp.StatusCode, body, want)
		}
	}
	if h.dials.Load() != 1 {
		t.Fatalf("upstream dials %d, want 1 (keep-alive reuse)", h.dials.Load())
	}
}

// ---- authentication -------------------------------------------------------

func TestWrongPasswordRejected(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	c, a, _ := h.socks("alice", "wrong", "public.test", 7)
	c.Close()
	if a != 1 {
		t.Fatalf("socks auth status %d, want 1", a)
	}
	c, _, code := h.connect(basic("alice", "wrong"), "public.test:443")
	c.Close()
	if code != 407 {
		t.Fatalf("connect code %d, want 407", code)
	}
	c, _, code = h.connect("", "public.test:443")
	c.Close()
	if code != 407 {
		t.Fatalf("no-auth connect code %d, want 407", code)
	}
	if r := h.lastLog("auth_failed"); r.User != "alice" {
		t.Fatalf("log %+v", r)
	}
	if h.dials.Load() != 0 {
		t.Fatal("dialed upstream without valid auth")
	}
}

func TestDisabledAndUnknownUserRejected(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	for _, u := range [][2]string{{"bob", "bob-password"}, {"mallory", "x"}} {
		c, a, _ := h.socks(u[0], u[1], "public.test", 7)
		c.Close()
		if a != 1 {
			t.Fatalf("%s: auth status %d", u[0], a)
		}
	}
}

func TestSOCKS5NoAuthMethodRejected(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	c, _ := net.Dial("tcp4", h.addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 0})
	b := make([]byte, 2)
	io.ReadFull(c, b)
	if b[1] != 0xFF {
		t.Fatalf("method reply %x, want ff", b[1])
	}
}

func TestAuthRateLimit(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", func(s *Server) { s.Limits.AuthFailMax = 3 })
	for i := 0; i < 3; i++ {
		c, a, _ := h.socks("alice", "wrong", "public.test", 7)
		c.Close()
		if a != 1 {
			t.Fatalf("attempt %d status %d", i, a)
		}
	}
	// Correct password is refused while the source is blocked.
	c, a, _ := h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 1 {
		t.Fatal("correct password accepted while blocked")
	}
	c, _, code := h.connect(basic("alice", "alice-password"), "public.test:443")
	c.Close()
	if code != 403 {
		t.Fatalf("http while blocked: %d, want 403", code)
	}
	h.lastLog("auth_blocked")
}

// ---- destinations ---------------------------------------------------------

func TestDestinationsDenied(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	targets := []string{
		"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost", // loopback
		"192.168.3.89", "::ffff:192.168.3.89", "nas.test", "2408:8000:1:2::89", "100.80.0.5", // NAS addresses
		"rebind.test",                                                             // mixed public + NAS answer
		"172.17.0.2", "docker.test", "100.80.0.9", "6.6.1.1", "fc03:1136:3800::9", // container / LazyCat networks
		"169.254.169.254", "fe80::1", "224.0.0.251", "255.255.255.255", "192.168.3.255", // link-local, multicast, broadcast
		"192.168.3.2", // extra deny
	}
	for _, tg := range targets {
		c, a, rep := h.socks("alice", "alice-password", tg, 80)
		c.Close()
		if a != 0 || rep != 0x02 {
			t.Errorf("socks %s: auth %d rep %d, want rep 2 (not allowed)", tg, a, rep)
		}
		hp := net.JoinHostPort(tg, "80")
		c, _, code := h.connect(basic("alice", "alice-password"), hp)
		c.Close()
		if code != 403 {
			t.Errorf("connect %s: %d, want 403", hp, code)
		}
	}
	if n := h.dials.Load(); n != 0 {
		t.Fatalf("%d upstream dials for denied targets", n)
	}
	r := h.lastLog("dst_denied")
	if r.Reason == "" || r.IP == "" {
		t.Fatalf("log %+v", r)
	}
	// Plain HTTP to the NAS.
	c, _ := net.Dial("tcp4", h.addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "GET http://192.168.3.89:5000/ HTTP/1.1\r\nHost: 192.168.3.89\r\nProxy-Authorization: %s\r\n\r\n", basic("alice", "alice-password"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 403 {
		t.Fatalf("plain http to NAS: %v %v", resp, err)
	}
}

// ---- sources --------------------------------------------------------------

func TestSourceOutsideLANRejected(t *testing.T) {
	h := newHarness(t, "10.0.0.0/8", nil) // 127.0.0.1 is now outside the LAN
	c, a, _ := h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 0xEE {
		t.Fatalf("got a handshake reply (%d) from a non-LAN source", a)
	}
	r := h.lastLog("src_denied")
	if !strings.HasPrefix(r.Src, "127.0.0.1:") || r.User != "" {
		t.Fatalf("log %+v", r)
	}
	if h.dials.Load() != 0 {
		t.Fatal("dialed upstream")
	}
}

func TestListenOnlyOnConfiguredIPv4(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	host, _, _ := net.SplitHostPort(h.addr)
	if host != "127.0.0.1" {
		t.Fatalf("listening on %s", h.addr)
	}
	h.s.mu.Lock()
	la := h.s.ln.Addr().String()
	h.s.mu.Unlock()
	if !strings.HasPrefix(la, "127.0.0.1:") {
		t.Fatalf("listener %s", la)
	}
	// Another local address on the same port must not be served.
	_, port, _ := net.SplitHostPort(h.addr)
	if c, err := net.DialTimeout("tcp4", "127.0.0.2:"+port, 500*time.Millisecond); err == nil {
		c.Close()
		t.Log("note: 127.0.0.2 not routable to a different socket on this OS; skipped")
	}
	if c, err := net.DialTimeout("tcp6", "[::1]:"+port, 500*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("proxy reachable over IPv6 ::1")
	}
}

// ---- hot reload, disable, stop --------------------------------------------

func TestHotReloadDisableUserKillsTunnel(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	c, _, rep := h.socks("alice", "alice-password", "public.test", 7)
	if rep != 0 {
		t.Fatal(rep)
	}
	echoCheck(t, c, c)
	cfg := h.readConfig()
	cfg.Users[0].Enabled = false
	h.writeConfig(cfg)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("tunnel still open after disabling the user")
	}
	c, a, _ := h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 1 {
		t.Fatal("disabled user still accepted")
	}
	// Re-enable and change password: old password refused, new accepted.
	cfg.Users[0].Enabled = true
	cfg.Users[0].Salt, cfg.Users[0].Hash, _ = HashPassword("new-password-1")
	h.writeConfig(cfg)
	time.Sleep(150 * time.Millisecond)
	c, a, _ = h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 1 {
		t.Fatal("old password accepted after change")
	}
	c, a, rep = h.socks("alice", "new-password-1", "public.test", 7)
	c.Close()
	if a != 0 || rep != 0 {
		t.Fatalf("new password: %d %d", a, rep)
	}
}

func TestStopClosesListener(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	cfg := h.readConfig()
	cfg.Enabled = false
	h.writeConfig(cfg)
	deadline := time.Now().Add(2 * time.Second)
	for h.s.ListenAddr() != "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c, err := net.DialTimeout("tcp4", h.addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("still accepting after stop")
	}
	var st Status
	for i := 0; i < 100; i++ {
		b, _ := os.ReadFile(filepath.Join(h.dir, "status.json"))
		json.Unmarshal(b, &st)
		if !st.Listening {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Listening || st.Enabled {
		t.Fatalf("status %+v", st)
	}
}

func TestInvalidConfigKeepsPrevious(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	os.WriteFile(filepath.Join(h.dir, "config.json"), []byte(`{"port": 80, "users": []}`), 0o600)
	time.Sleep(150 * time.Millisecond)
	c, a, rep := h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 0 || rep != 0 {
		t.Fatal("previous config not kept")
	}
}

// ---- resource limits ------------------------------------------------------

func TestMaxConnections(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", func(s *Server) { s.Limits.MaxConns = 2 })
	var open []net.Conn
	for i := 0; i < 2; i++ {
		c, _, rep := h.socks("alice", "alice-password", "public.test", 7)
		if rep != 0 {
			t.Fatal(rep)
		}
		open = append(open, c)
	}
	c, a, _ := h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 0xEE {
		t.Fatal("third connection served over the limit")
	}
	h.lastLog("busy")
	for _, c := range open {
		c.Close()
	}
}

func TestHandshakeTimeout(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", func(s *Server) { s.Limits.HandshakeTimeout = 200 * time.Millisecond })
	c, _ := net.Dial("tcp4", h.addr)
	defer c.Close()
	start := time.Now()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err := c.Read(make([]byte, 1))
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("idle handshake not closed: %v after %v", err, time.Since(start))
	}
}

func TestIdleTunnelClosed(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", func(s *Server) { s.Limits.IdleTimeout = 300 * time.Millisecond })
	c, _, rep := h.socks("alice", "alice-password", "public.test", 7)
	if rep != 0 {
		t.Fatal(rep)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("idle tunnel not closed: %v", err)
	}
}

func TestHeaderTooLarge(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	c, _ := net.Dial("tcp4", h.addr)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT public.test:443 HTTP/1.1\r\nX-Pad: %s\r\n", strings.Repeat("a", 20000))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 400 {
		t.Fatalf("got %v %v", resp, err)
	}
}

func TestConcurrentLoad(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	var wg sync.WaitGroup
	var fails atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, rep := h.socks("alice", "alice-password", "public.test", 7)
			defer c.Close()
			if rep != 0 {
				fails.Add(1)
				return
			}
			io.WriteString(c, "x")
			b := make([]byte, 1)
			if _, err := io.ReadFull(c, b); err != nil {
				fails.Add(1)
			}
		}()
	}
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d failures", fails.Load())
	}
}
