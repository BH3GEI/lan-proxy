package core

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeCore is a minimal SOCKS5 server standing in for mihomo. It records the
// requested targets and relays to an echo server (or replies with a fixed code).
type fakeCore struct {
	ln      net.Listener
	mu      sync.Mutex
	targets []string
	srcs    []string
	reply   byte
	echo    string
}

func startFakeCore(t *testing.T, user, pass string, reply byte) *fakeCore {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeCore{ln: ln, reply: reply, echo: startEcho(t)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fc.serve(c, user, pass)
		}
	}()
	return fc
}

func (fc *fakeCore) serve(c net.Conn, user, pass string) {
	defer c.Close()
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil {
		return
	}
	io.ReadFull(c, make([]byte, b[1]))
	c.Write([]byte{5, 2})
	io.ReadFull(c, b)
	u := make([]byte, b[1])
	io.ReadFull(c, u)
	l := make([]byte, 1)
	io.ReadFull(c, l)
	p := make([]byte, l[0])
	io.ReadFull(c, p)
	if string(u) != user || string(p) != pass {
		c.Write([]byte{1, 1})
		return
	}
	c.Write([]byte{1, 0})
	h := make([]byte, 4)
	io.ReadFull(c, h)
	var host string
	switch h[3] {
	case 1:
		a := make([]byte, 4)
		io.ReadFull(c, a)
		host = net.IP(a).String()
	case 4:
		a := make([]byte, 16)
		io.ReadFull(c, a)
		host = net.IP(a).String()
	case 3:
		io.ReadFull(c, l)
		a := make([]byte, l[0])
		io.ReadFull(c, a)
		host = string(a)
	}
	pb := make([]byte, 2)
	io.ReadFull(c, pb)
	fc.mu.Lock()
	fc.targets = append(fc.targets, net.JoinHostPort(host, itoa(int(binary.BigEndian.Uint16(pb)))))
	fc.srcs = append(fc.srcs, c.RemoteAddr().String())
	fc.mu.Unlock()
	c.Write([]byte{5, fc.reply, 0, 1, 0, 0, 0, 0, 0, 0})
	if fc.reply != 0 {
		return
	}
	up, err := net.Dial("tcp4", fc.echo)
	if err != nil {
		return
	}
	defer up.Close()
	go func() { io.Copy(up, c); up.(*net.TCPConn).CloseWrite() }()
	io.Copy(c, up)
}

func itoa(i int) string { return fmtInt(i) }

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func (fc *fakeCore) seen() []string {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return append([]string(nil), fc.targets...)
}

func publishCore(t *testing.T, h *harness, addr string) {
	if err := WriteJSONAtomic(filepath.Join(h.dir, "core.json"), CoreEndpoint{Addr: addr, User: "lpcore", Pass: "corepass", Started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestCorePublicDomainGoesThroughCoreByName(t *testing.T) {
	h := newHarnessMode(t, "127.0.0.0/8", EgressRules, nil)
	fc := startFakeCore(t, "lpcore", "corepass", 0)
	publishCore(t, h, fc.ln.Addr().String())
	c, a, rep := h.socks("alice", "alice-password", "public.test", 443)
	if a != 0 || rep != 0 {
		t.Fatalf("auth %d rep %d", a, rep)
	}
	echoCheck(t, c, c)
	c.Close()
	if got := fc.seen(); len(got) != 1 || got[0] != "public.test:443" {
		t.Fatalf("core saw %v, want the domain name", got)
	}
	r := h.lastLog("ok")
	if r.Via != "core" || r.CoreSrc == "" || r.IP != pubEcho {
		t.Fatalf("log %+v", r)
	}
	if fc.srcs[0] != r.CoreSrc {
		t.Fatalf("core_src %s != core-side source %s", r.CoreSrc, fc.srcs[0])
	}
	if h.dials.Load() != 0 {
		t.Fatal("public destination dialed directly in rules mode")
	}
}

func TestCoreHTTPConnectAndIPLiteral(t *testing.T) {
	h := newHarnessMode(t, "127.0.0.0/8", EgressRules, nil)
	fc := startFakeCore(t, "lpcore", "corepass", 0)
	publishCore(t, h, fc.ln.Addr().String())
	c, br, code := h.connect(basic("alice", "alice-password"), "1.1.1.1:443")
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	echoCheck(t, c, br)
	c.Close()
	if got := fc.seen(); len(got) != 1 || got[0] != "1.1.1.1:443" {
		t.Fatalf("core saw %v", got)
	}
}

func TestCoreLANDestinationDirect(t *testing.T) {
	h := newHarnessMode(t, "127.0.0.0/8", EgressRules, func(s *Server) {})
	// Make 192.168.3.0/24 part of the LAN for this test, as on the NAS.
	h.s.mu.Lock()
	h.s.pol.LAN = append(h.s.pol.LAN, mustPrefixes("192.168.3.0/24")...)
	h.s.mu.Unlock()
	fc := startFakeCore(t, "lpcore", "corepass", 0)
	publishCore(t, h, fc.ln.Addr().String())
	c, a, rep := h.socks("alice", "alice-password", "192.168.3.50", 22)
	if a != 0 || rep != 0 {
		t.Fatalf("auth %d rep %d", a, rep)
	}
	echoCheck(t, c, c)
	c.Close()
	if len(fc.seen()) != 0 || h.dials.Load() != 1 {
		t.Fatalf("LAN target: core saw %v, direct dials %d", fc.seen(), h.dials.Load())
	}
	if r := h.lastLog("ok"); r.Via != "direct" {
		t.Fatalf("log %+v", r)
	}
}

func TestCoreDeniedTargetsNeverReachCore(t *testing.T) {
	h := newHarnessMode(t, "127.0.0.0/8", EgressRules, nil)
	fc := startFakeCore(t, "lpcore", "corepass", 0)
	publishCore(t, h, fc.ln.Addr().String())
	for _, tg := range []string{"127.0.0.1", "::ffff:192.168.3.89", "nas.test", "rebind.test", "172.17.0.2", "100.80.0.9", "fe80::1", "192.168.3.2", "localhost"} {
		c, _, rep := h.socks("alice", "alice-password", tg, 80)
		c.Close()
		if rep != 0x02 {
			t.Errorf("%s: rep %d, want 2", tg, rep)
		}
	}
	if got := fc.seen(); len(got) != 0 {
		t.Fatalf("denied targets reached the core: %v", got)
	}
}

func TestCoreUnresolvableGoesByName(t *testing.T) {
	h := newHarnessMode(t, "127.0.0.0/8", EgressRules, nil)
	fc := startFakeCore(t, "lpcore", "corepass", 0)
	publishCore(t, h, fc.ln.Addr().String())
	c, _, rep := h.socks("alice", "alice-password", "blocked.example", 443)
	c.Close()
	if rep != 0 {
		t.Fatalf("rep %d", rep)
	}
	if got := fc.seen(); len(got) != 1 || got[0] != "blocked.example:443" {
		t.Fatalf("core saw %v", got)
	}
}

func TestCoreRejectAndUnavailable(t *testing.T) {
	h := newHarnessMode(t, "127.0.0.0/8", EgressRules, nil)
	// No core.json yet: refused, never direct.
	c, _, rep := h.socks("alice", "alice-password", "public.test", 443)
	c.Close()
	if rep == 0 || h.dials.Load() != 0 {
		t.Fatalf("no core: rep %d dials %d", rep, h.dials.Load())
	}
	if r := h.lastLog("dial_failed"); r.Via != "core" {
		t.Fatalf("log %+v", r)
	}
	// Core rejects (as mihomo does for private addresses): reported as denied.
	fc := startFakeCore(t, "lpcore", "corepass", 2)
	publishCore(t, h, fc.ln.Addr().String())
	c, _, rep = h.socks("alice", "alice-password", "public.test", 443)
	c.Close()
	if rep != 2 {
		t.Fatalf("core reject: rep %d", rep)
	}
	h.lastLog("dst_denied")
	// Wrong core credentials: failure, not direct.
	WriteJSONAtomic(filepath.Join(h.dir, "core.json"), CoreEndpoint{Addr: fc.ln.Addr().String(), User: "lpcore", Pass: "nope"})
	time.Sleep(100 * time.Millisecond)
	c, _, rep = h.socks("alice", "alice-password", "public.test", 443)
	c.Close()
	if rep == 0 || h.dials.Load() != 0 {
		t.Fatalf("bad core creds: rep %d dials %d", rep, h.dials.Load())
	}
}

func TestCoreEndpointMustBePrivate(t *testing.T) {
	h := newHarnessMode(t, "127.0.0.0/8", EgressRules, nil)
	WriteJSONAtomic(filepath.Join(h.dir, "core.json"), CoreEndpoint{Addr: "93.184.216.34:1080", User: "u", Pass: "p"})
	time.Sleep(100 * time.Millisecond)
	h.s.mu.Lock()
	core := h.s.core
	h.s.mu.Unlock()
	if core != nil {
		t.Fatalf("public core endpoint accepted: %+v", core)
	}
	os.Remove(filepath.Join(h.dir, "core.json"))
}

func TestCoreResolveViaSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lpsock")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns/query" || r.URL.Query().Get("name") != "example.com" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"Status":0,"Answer":[{"name":"example.com.","type":5,"data":"x."},{"name":"example.com.","type":1,"data":"93.184.216.34"}]}`)
	})}
	go srv.Serve(ln)
	defer srv.Close()
	ips, err := coreResolve(context.Background(), sock, "example.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("%v %v", ips, err)
	}
	if _, err := coreResolve(context.Background(), sock, "nope.test"); err == nil {
		t.Fatal("expected error")
	}
}
