package core

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (h *harness) setNoAuth(on bool) {
	cfg := h.readConfig()
	cfg.RequireAuth = !on
	h.writeConfig(cfg)
	time.Sleep(150 * time.Millisecond)
}

// socksAnon offers only the "no authentication" method.
func (h *harness) socksAnon(host string, port int) (net.Conn, byte, byte) {
	c, err := net.Dial("tcp4", h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil {
		return c, 0xEE, 0xFF
	}
	if b[1] != 0 {
		return c, b[1], 0xFF
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return c, 0, 0xFE
	}
	return c, 0, rep[1]
}

func TestNoAuthSOCKS5AndHTTP(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	h.setNoAuth(true)

	c, a, rep := h.socksAnon("public.test", 7)
	if a != 0 || rep != 0 {
		t.Fatalf("socks no-auth: method %x rep %x", a, rep)
	}
	echoCheck(t, c, c)
	c.Close()
	r := h.lastLog("ok")
	if !r.NoAuth || r.User != "" || r.MAC != "aa:bb:cc:dd:ee:01" || r.Target != "public.test:7" || r.IP != pubEcho || r.Up == 0 {
		t.Fatalf("socks log %+v", r)
	}

	c, br, code := h.connect("", "public.test:443")
	if code != 200 {
		t.Fatalf("CONNECT without auth: %d", code)
	}
	echoCheck(t, c, br)
	c.Close()

	c, _ = net.Dial("tcp4", h.addr)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET http://web.test/x HTTP/1.1\r\nHost: web.test\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("plain http without auth: %v %v", resp, err)
	}
	c.Close()

	// Clients with credentials still work, and wrong credentials are still refused.
	c, a, rep = h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 0 || rep != 0 {
		t.Fatalf("socks with password: %d %d", a, rep)
	}
	c, a, _ = h.socks("alice", "wrong", "public.test", 7)
	c.Close()
	if a != 1 {
		t.Fatalf("wrong password accepted in no-auth mode: %d", a)
	}
	c, _, code = h.connect(basic("alice", "wrong"), "public.test:443")
	c.Close()
	if code != 407 {
		t.Fatalf("wrong password over HTTP: %d", code)
	}
	c, _, code = h.connect("Bearer junk", "public.test:443")
	c.Close()
	if code != 407 {
		t.Fatalf("malformed Proxy-Authorization: %d", code)
	}
	c, _, code = h.connect(basic("alice", "alice-password"), "public.test:443")
	c.Close()
	if code != 200 {
		t.Fatalf("CONNECT with password: %d", code)
	}
}

func TestNoAuthDestinationsStillDenied(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	h.setNoAuth(true)
	for _, tg := range []string{"nas.test", "rebind.test", "docker.test", "localhost", "192.168.3.89", "127.0.0.1"} {
		c, a, rep := h.socksAnon(tg, 443)
		c.Close()
		if a != 0 || rep != 0x02 {
			t.Fatalf("socks %s: method %x rep %x, want refusal 02", tg, a, rep)
		}
		c, _, code := h.connect("", net.JoinHostPort(tg, "443"))
		c.Close()
		if code != 403 {
			t.Fatalf("CONNECT %s: %d, want 403", tg, code)
		}
	}
	if h.dials.Load() != 0 {
		t.Fatalf("dialed upstream %d times for denied targets", h.dials.Load())
	}
	if r := h.lastLog("dst_denied"); !r.NoAuth {
		t.Fatalf("log %+v", r)
	}
}

func TestNoAuthSourceOutsideLANRejected(t *testing.T) {
	h := newHarness(t, "10.0.0.0/8", nil)
	h.setNoAuth(true)
	c, a, _ := h.socksAnon("public.test", 7)
	c.Close()
	if a != 0xEE {
		t.Fatalf("non-LAN source got a reply %x", a)
	}
	c, _, code := h.connect("", "public.test:443")
	c.Close()
	if code != 0 {
		t.Fatalf("non-LAN source got HTTP %d", code)
	}
	if h.dials.Load() != 0 {
		t.Fatal("dialed upstream")
	}
}

func TestNoAuthOffByDefaultInTestsAndSwitchingOffKillsAnon(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", nil)
	// RequireAuth is on in the harness: no-auth is refused.
	c, a, _ := h.socksAnon("public.test", 7)
	c.Close()
	if a != 0xFF {
		t.Fatalf("no-auth accepted while authentication is required: %x", a)
	}
	h.setNoAuth(true)
	c, a, rep := h.socksAnon("public.test", 7)
	if a != 0 || rep != 0 {
		t.Fatal(a, rep)
	}
	echoCheck(t, c, c)
	pc, _, prep := h.socks("alice", "alice-password", "public.test", 7)
	if prep != 0 {
		t.Fatal(prep)
	}
	h.setNoAuth(false)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("anonymous tunnel still open after requiring authentication")
	}
	c.Close()
	echoCheck(t, pc, pc) // authenticated tunnel unaffected
	pc.Close()
	c, _, code := h.connect("", "public.test:443")
	c.Close()
	if code != 407 {
		t.Fatalf("CONNECT without auth after switching off: %d", code)
	}
}

func TestDefaultConfigIsNoAuth(t *testing.T) {
	if DefaultConfig().RequireAuth {
		t.Fatal("default must allow LAN clients without a password")
	}
	var c Config
	if c.RequireAuth { // a config file written before this switch existed
		t.Fatal("missing field must mean no-auth")
	}
}

func TestLogMergeRepeats(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", func(s *Server) { s.MergeWindow = 400 * time.Millisecond })
	h.setNoAuth(true)
	for i := 0; i < 5; i++ {
		c, _, _ := h.connect("", "nas.test:443")
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	var den []ConnRecord
	for _, r := range h.logs() {
		if r.Result == "dst_denied" {
			den = append(den, r)
		}
	}
	if len(den) != 1 || den[0].N != 0 {
		t.Fatalf("before the window ends: %+v", den)
	}
	time.Sleep(600 * time.Millisecond)
	den = nil
	for _, r := range h.logs() {
		if r.Result == "dst_denied" {
			den = append(den, r)
		}
	}
	if len(den) != 2 || den[1].N != 4 || den[1].MAC == "" || den[1].Target != "nas.test:443" {
		t.Fatalf("after the window: %+v", den)
	}
	// A different target is a different run.
	c, _, _ := h.connect("", "docker.test:443")
	c.Close()
	if r := h.lastLog("dst_denied"); r.Target != "docker.test:443" || r.N != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestAppendRotatingCapsTotal(t *testing.T) {
	base := filepath.Join(t.TempDir(), "conn.jsonl")
	line := []byte(strings.Repeat("x", 99) + "\n")
	for i := 0; i < 5000; i++ {
		if err := AppendRotating(base, line, 10_000, 5); err != nil {
			t.Fatal(err)
		}
	}
	files := LogFilesNewestFirst(base, 10)
	if len(files) != 5 {
		t.Fatalf("files %v", files)
	}
	var total int64
	for _, f := range files {
		st, _ := os.Stat(f)
		if st.Size() > 10_000 {
			t.Fatalf("%s is %d bytes", f, st.Size())
		}
		total += st.Size()
	}
	if total > 50_000 {
		t.Fatalf("total %d", total)
	}
	if _, err := os.Stat(base + ".5"); err == nil {
		t.Fatal("kept a sixth file")
	}
}

func TestParseARP(t *testing.T) {
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.3.192    0x1         0x2         3c:7c:3f:11:22:33     *        enp2s0
192.168.3.50     0x1         0x0         00:00:00:00:00:00     *        enp2s0
`
	m := ParseARP(bufio.NewScanner(strings.NewReader(in)))
	if m["192.168.3.192"] != "3c:7c:3f:11:22:33" || len(m) != 1 {
		t.Fatalf("%v", m)
	}
}

// Wrong credentials are refused even in no-auth mode (never downgraded to
// anonymous), logged as a password error and counted by the rate limiter.
func TestNoAuthWrongPasswordNotDowngraded(t *testing.T) {
	h := newHarness(t, "127.0.0.0/8", func(s *Server) { s.Limits.AuthFailMax = 3 })
	h.setNoAuth(true)
	// SOCKS5 client offering both "no auth" and "username/password", with a wrong password.
	c, _ := net.Dial("tcp4", h.addr)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 2, 0, 2})
	b := make([]byte, 2)
	io.ReadFull(c, b)
	if b[1] != 2 {
		t.Fatalf("server chose method %x, want 02 when the client offers a password", b[1])
	}
	c.Write(append(append([]byte{1, 5}, "alice"...), append([]byte{5}, "wrong"...)...))
	io.ReadFull(c, b)
	c.Close()
	if b[1] != 1 {
		t.Fatalf("wrong password accepted: %x", b[1])
	}
	r := h.lastLog("auth_failed")
	if r.NoAuth || r.User != "alice" || !strings.Contains(r.Reason, "密码错误") {
		t.Fatalf("log %+v", r)
	}
	c, _, code := h.connect(basic("alice", "wrong"), "public.test:443")
	c.Close()
	if code != 407 {
		t.Fatalf("HTTP wrong password: %d", code)
	}
	c, _, code = h.connect(basic("alice", "wrong"), "public.test:443")
	c.Close()
	// Third failure reaches the limit: the source is blocked for credential logins.
	c, a, _ := h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if a != 1 {
		t.Fatalf("correct password accepted while blocked: %d", a)
	}
	if r := h.lastLog("auth_blocked"); r.User != "alice" {
		t.Fatalf("log %+v", r)
	}
	if h.dials.Load() != 0 {
		t.Fatal("dialed upstream for a failed login")
	}
}
