package core

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var (
	meshPeer  = netip.MustParseAddr("fc03:1136:3800::77")
	meshLocal = netip.MustParseAddr("fc03:1136:3800::5")
	lanLocal  = netip.MustParseAddr("192.168.3.89")
)

func TestFindMesh(t *testing.T) {
	p := fakePolicy(t)
	if p.MeshIP != meshLocal || p.Mesh.String() != "fc03:1136:3800::/64" || p.MeshIf != "heiyu0" {
		t.Fatalf("mesh %v %v %q note %q", p.MeshIP, p.Mesh, p.MeshIf, p.MeshNote)
	}
	// Container ULAs (fd00::/8), public IPv6, /128 host routes are never the mesh.
	v := fakeView()
	v.Ifaces = append(v.Ifaces, IfStatus{"lzc-br-1", []string{"fd03:1136:3800::1/122"}}, IfStatus{"lo2", []string{"fc03:1136:38::1/128"}})
	p, _ = BuildPolicy(DefaultConfig(), v)
	if p.MeshIP != meshLocal {
		t.Fatalf("picked %v", p.MeshIP)
	}
	// Two candidates: refuse to guess.
	v.Ifaces = append(v.Ifaces, IfStatus{"tun9", []string{"fc99::1/48"}})
	p, _ = BuildPolicy(DefaultConfig(), v)
	if p.MeshIP.IsValid() || p.MeshNote == "" {
		t.Fatalf("ambiguous mesh accepted: %v", p.MeshIP)
	}
	// None.
	v = fakeView()
	v.Ifaces = v.Ifaces[:3]
	p, _ = BuildPolicy(DefaultConfig(), v)
	if p.MeshIP.IsValid() {
		t.Fatal("mesh found without a LazyCat interface")
	}
	// Switched off.
	c := DefaultConfig()
	c.NoMesh = true
	p, _ = BuildPolicy(c, fakeView())
	if p.MeshIP.IsValid() {
		t.Fatal("mesh on while disabled")
	}
}

func TestCheckSourceAt(t *testing.T) {
	p := fakePolicy(t)
	ok := [][2]string{
		{"fc03:1136:3800::77", "fc03:1136:3800::5"}, // LazyCat device -> mesh listener
		{"192.168.3.192", "192.168.3.89"},           // LAN device -> LAN listener
		{"::ffff:192.168.3.192", "192.168.3.89"},
	}
	for _, c := range ok {
		if r := p.CheckSourceAt(netip.MustParseAddr(c[0]), netip.MustParseAddr(c[1])); r != "" {
			t.Errorf("%s -> %s refused: %s", c[0], c[1], r)
		}
	}
	bad := [][2]string{
		{"fc03:1136:3800::5", "fc03:1136:3800::5"},  // the NAS itself
		{"fd03:1136:3800::41", "fc03:1136:3800::5"}, // container network
		{"172.28.4.66", "fc03:1136:3800::5"},
		{"192.168.3.192", "fc03:1136:3800::5"},     // LAN source on the mesh listener
		{"2408:8000:1:2::99", "fc03:1136:3800::5"}, // public IPv6
		{"fc03:1136:3900::1", "fc03:1136:3800::5"}, // outside the mesh prefix
		{"fc03:1136:3800::77", "192.168.3.89"},     // mesh source on the LAN listener
		{"192.168.3.192", "172.17.0.1"},            // connected to some other local address
		{"192.168.3.192", "fc03:1136:3800::99"},    // not the mesh address
		{"6.6.6.7", "192.168.3.89"},
	}
	for _, c := range bad {
		if r := p.CheckSourceAt(netip.MustParseAddr(c[0]), netip.MustParseAddr(c[1])); r == "" {
			t.Errorf("%s -> %s accepted", c[0], c[1])
		}
	}
	// Return route must go out the LazyCat interface.
	v := fakeView()
	v.Routes = append(v.Routes, Route{netip.MustParsePrefix("fc03:1136:3800::77/128"), "eth0", 0})
	p, _ = BuildPolicy(DefaultConfig(), v)
	if r := p.CheckSourceAt(meshPeer, meshLocal); !strings.Contains(r, "回程路由") {
		t.Fatalf("got %q", r)
	}
	// Mesh off: LazyCat sources refused.
	c := DefaultConfig()
	c.NoMesh = true
	p, _ = BuildPolicy(c, fakeView())
	if p.CheckSourceAt(meshPeer, meshLocal) == "" {
		t.Fatal("mesh source accepted with the mesh disabled")
	}
	_ = lanLocal
}

func TestMeshDestinationsStillDenied(t *testing.T) {
	p := fakePolicy(t)
	for _, s := range []string{"fc03:1136:3800::5", "fc03:1136:3800::77", "fd03:1136:3800::41"} {
		if p.CheckDest(netip.MustParseAddr(s)) == "" {
			t.Errorf("destination %s allowed", s)
		}
	}
}

// meshTweak makes the harness also listen on ::1 as if it were the LazyCat address.
func meshTweak(s *Server) {
	scan, mk := s.Scan, s.MakePolicy
	s.Scan = func() (*NetView, error) {
		v, err := scan()
		if err == nil {
			delete(v.LocalIPs, netip.MustParseAddr("::1"))
			v.Routes = append(v.Routes, Route{netip.MustParsePrefix("::1/128"), "lo", 0})
		}
		return v, err
	}
	s.MakePolicy = func(c Config, v *NetView) (*Policy, error) {
		p, err := mk(c, v)
		if err == nil && !c.NoMesh {
			p.MeshIP, p.Mesh, p.MeshIf, p.MeshNote = netip.MustParseAddr("::1"), netip.MustParsePrefix("::1/128"), "lo", ""
		} else if err == nil {
			p.MeshIP, p.Mesh = netip.Addr{}, netip.Prefix{}
		}
		return p, err
	}
}

func (h *harness) onMesh(f func()) {
	lan := h.addr
	deadline := time.Now().Add(3 * time.Second)
	for h.s.MeshListenAddr() == "" {
		if time.Now().After(deadline) {
			h.t.Fatal("mesh listener not started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.addr = h.s.MeshListenAddr()
	defer func() { h.addr = lan }()
	f()
}

func TestMeshListenerNoAuth(t *testing.T) {
	if c, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		c.Close()
	}
	h := newHarness(t, "127.0.0.0/8", meshTweak)
	h.setNoAuth(true)
	h.onMesh(func() {
		if !strings.HasPrefix(h.addr, "[::1]:") {
			t.Fatalf("mesh listener %s", h.addr)
		}
		c, a, rep := h.socksAnon("public.test", 7)
		if a != 0 || rep != 0 {
			t.Fatalf("socks over mesh: %x %x", a, rep)
		}
		echoCheck(t, c, c)
		c.Close()
		r := h.lastLog("ok")
		if !strings.HasPrefix(r.Src, "[::1]:") || !r.NoAuth {
			t.Fatalf("log %+v", r)
		}
		c, br, code := h.connect("", "public.test:443")
		if code != 200 {
			t.Fatalf("CONNECT over mesh: %d", code)
		}
		echoCheck(t, c, br)
		c.Close()
		// NAS and internal targets stay refused; wrong passwords stay refused.
		for _, tg := range []string{"nas.test:443", "docker.test:80", "localhost:80"} {
			c, _, code := h.connect("", tg)
			c.Close()
			if code != 403 {
				t.Fatalf("CONNECT %s over mesh: %d", tg, code)
			}
		}
		c, _, code = h.connect(basic("alice", "wrong"), "public.test:443")
		c.Close()
		if code != 407 {
			t.Fatalf("wrong password over mesh: %d", code)
		}
	})
	// LAN listener still works alongside.
	c, a, rep := h.socksAnon("public.test", 7)
	c.Close()
	if a != 0 || rep != 0 {
		t.Fatalf("LAN listener: %x %x", a, rep)
	}
}

func TestMeshSwitchOffClosesListenerAndConns(t *testing.T) {
	if c, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		c.Close()
	}
	h := newHarness(t, "127.0.0.0/8", meshTweak)
	h.setNoAuth(true)
	var mc net.Conn
	mesh := ""
	h.onMesh(func() {
		mesh = h.addr
		var a, rep byte
		mc, a, rep = h.socksAnon("public.test", 7)
		if a != 0 || rep != 0 {
			t.Fatal(a, rep)
		}
		echoCheck(t, mc, mc)
	})
	lc, _, _ := h.socksAnon("public.test", 7)
	cfg := h.readConfig()
	cfg.NoMesh = true
	h.writeConfig(cfg)
	time.Sleep(200 * time.Millisecond)
	mc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := mc.Read(make([]byte, 1)); err == nil {
		t.Fatal("mesh tunnel still open after switching the mesh off")
	}
	if h.s.MeshListenAddr() != "" {
		t.Fatal("mesh listener still open")
	}
	d := net.Dialer{Timeout: time.Second}
	if c, err := d.DialContext(context.Background(), "tcp6", mesh); err == nil {
		c.Close()
		t.Fatal("mesh address still accepts connections")
	}
	echoCheck(t, lc, lc) // LAN tunnel unaffected
	lc.Close()
}
