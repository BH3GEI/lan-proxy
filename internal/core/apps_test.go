package core

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// appView is fakeView plus two LazyCat app bridges, a plain docker bridge and
// a bridge-named interface outside the container range.
func appView() *NetView {
	v := fakeView()
	add := func(name string, addrs ...string) {
		v.Ifaces = append(v.Ifaces, IfStatus{name, addrs})
		for _, s := range addrs {
			v.LocalIPs[netip.MustParsePrefix(s).Addr()] = name
		}
	}
	add("lzc-br-494e6bb1", "172.28.3.193/26", "fd03:1136:3800::3c1/122", "fe80::42:fdff:fef9:e0e3/64")
	add("lzc-br-a8667ecd", "172.28.0.1/26", "fd03:1136:3800::1/122")
	add("br-895206e6329e", "172.18.0.1/16")
	add("lzc-br-odd", "10.77.0.1/24", "172.29.0.1/31")
	v.Routes = append(v.Routes,
		Route{netip.MustParsePrefix("172.28.3.192/26"), "lzc-br-494e6bb1", 0},
		Route{netip.MustParsePrefix("172.28.0.0/26"), "lzc-br-a8667ecd", 0},
		Route{netip.MustParsePrefix("172.18.0.0/16"), "br-895206e6329e", 0},
		Route{netip.MustParsePrefix("10.77.0.0/24"), "lzc-br-odd", 0},
	)
	return v
}

func TestFindApps(t *testing.T) {
	p, err := BuildPolicy(DefaultConfig(), appView())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range p.Apps {
		got = append(got, n.Prefix.String()+"@"+n.Iface)
	}
	want := "172.28.3.192/26@lzc-br-494e6bb1 172.28.0.0/26@lzc-br-a8667ecd"
	if strings.Join(got, " ") != want {
		t.Fatalf("apps %v, want %s", got, want)
	}
	c := DefaultConfig()
	c.NoApps = true
	p, _ = BuildPolicy(c, appView())
	if len(p.Apps) != 0 {
		t.Fatal("app networks found while switched off")
	}
}

func TestAppSourceKind(t *testing.T) {
	p, err := BuildPolicy(DefaultConfig(), appView())
	if err != nil {
		t.Fatal(err)
	}
	lan := netip.MustParseAddr("192.168.3.89")
	mesh := netip.MustParseAddr("fc03:1136:3800::5")
	type tc struct {
		src, local, kind string
	}
	for _, c := range []tc{
		{"172.28.3.196", "192.168.3.89", SrcApp}, // brief's container -> LAN listener
		{"::ffff:172.28.3.196", "192.168.3.89", SrcApp},
		{"172.28.0.5", "192.168.3.89", SrcApp},
		{"192.168.3.192", "192.168.3.89", SrcLAN},
		{"fc03:1136:3800::77", "fc03:1136:3800::5", SrcMesh},
	} {
		k, r := p.SourceKind(netip.MustParseAddr(c.src), netip.MustParseAddr(c.local))
		if k != c.kind || r != "" {
			t.Errorf("%s -> %s: kind %q reason %q, want %q", c.src, c.local, k, r, c.kind)
		}
	}
	for _, c := range [][2]string{
		{"172.28.3.193", "192.168.3.89"},        // the bridge gateway is the NAS itself
		{"172.28.3.196", "fc03:1136:3800::5"},   // app source on the mesh listener
		{"172.28.3.196", "172.28.3.193"},        // connected to the bridge address, not the LAN one
		{"172.28.1.5", "192.168.3.89"},          // no such bridge here
		{"172.18.0.5", "192.168.3.89"},          // plain docker bridge
		{"172.17.0.2", "192.168.3.89"},          // docker0
		{"10.77.0.5", "192.168.3.89"},           // lzc-br-* outside 172.16.0.0/12
		{"fd03:1136:3800::3c5", "192.168.3.89"}, // app IPv6
		{"6.6.6.7", "192.168.3.89"},
	} {
		if k, r := p.SourceKind(netip.MustParseAddr(c[0]), netip.MustParseAddr(c[1])); r == "" {
			t.Errorf("%s -> %s accepted as %q", c[0], c[1], k)
		}
	}
	// Return route must use the bridge.
	v := appView()
	v.Routes = append(v.Routes, Route{netip.MustParsePrefix("172.28.3.196/32"), "eth0", 0})
	p, _ = BuildPolicy(DefaultConfig(), v)
	if _, r := p.CheckSource(netip.MustParseAddr("172.28.3.196")), p.CheckSourceAt(netip.MustParseAddr("172.28.3.196"), lan); !strings.Contains(r, "回程路由") {
		t.Fatalf("got %q", r)
	}
	// Switched off: refused like before.
	c := DefaultConfig()
	c.NoApps = true
	p, _ = BuildPolicy(c, appView())
	if r := p.CheckSourceAt(netip.MustParseAddr("172.28.3.196"), lan); r != reasonNotLAN {
		t.Fatalf("app source with apps off: %q", r)
	}
	_ = mesh
}

func TestAppDestinationsStillDenied(t *testing.T) {
	p, _ := BuildPolicy(DefaultConfig(), appView())
	for _, s := range []string{"172.28.3.193", "172.28.3.196", "172.28.0.5", "fd03:1136:3800::3c5", "192.168.3.89", "192.168.3.2"} {
		if p.CheckDest(netip.MustParseAddr(s)) == "" {
			t.Errorf("destination %s allowed", s)
		}
	}
}

// appsTweak makes the test client (127.0.0.1) an app container: the LAN is
// somewhere else and 127.0.0.0/8 is an app bridge on "lo".
func appsTweak(s *Server) {
	scan, mk := s.Scan, s.MakePolicy
	s.Scan = func() (*NetView, error) {
		v, err := scan()
		if err == nil {
			v.Routes = append(v.Routes, Route{netip.MustParsePrefix("127.0.0.0/8"), "lo", 0})
		}
		return v, err
	}
	s.MakePolicy = func(c Config, v *NetView) (*Policy, error) {
		p, err := mk(c, v)
		if err == nil {
			p.Apps = nil
			if !c.NoApps {
				p.Apps = []AppNet{{netip.MustParsePrefix("127.0.0.0/8"), "lo"}}
			}
		}
		return p, err
	}
}

func TestAppNeedsAccount(t *testing.T) {
	h := newHarness(t, "10.9.9.0/24", appsTweak)
	h.setNoAuth(true) // LAN no-auth on: still not for apps

	c, a, _ := h.socksAnon("public.test", 7)
	c.Close()
	if a != 0xFF {
		t.Fatalf("app without credentials: method %x", a)
	}
	if r := h.lastLog("auth_failed"); r.Kind != SrcApp {
		t.Fatalf("log %+v", r)
	}
	c, a, _ = h.socks("", "", "public.test", 7)
	c.Close()
	if a == 0 {
		t.Fatal("app with empty credentials accepted")
	}
	c, _, code := h.connect("", "public.test:443")
	c.Close()
	if code != 407 {
		t.Fatalf("app CONNECT without credentials: %d", code)
	}
	c, a, _ = h.socks("alice", "wrong", "public.test", 7)
	c.Close()
	if a == 0 {
		t.Fatal("app with wrong password accepted")
	}
	c, a, _ = h.socks("bob", "bob-password", "public.test", 7)
	c.Close()
	if a == 0 {
		t.Fatal("app with disabled account accepted")
	}

	c, a, rep := h.socks("alice", "alice-password", "public.test", 7)
	if a != 0 || rep != 0 {
		t.Fatalf("app with account: %x %x", a, rep)
	}
	echoCheck(t, c, c)
	c.Close()
	r := h.lastLog("ok")
	if r.Kind != SrcApp || r.User != "alice" || r.NoAuth {
		t.Fatalf("log %+v", r)
	}
	c, br, code := h.connect(basic("alice", "alice-password"), "public.test:443")
	if code != 200 {
		t.Fatalf("app CONNECT with account: %d", code)
	}
	echoCheck(t, c, br)
	c.Close()
	// Internal destinations stay refused for apps too.
	for _, tg := range []string{"nas.test:443", "docker.test:80", "localhost:80"} {
		c, _, code := h.connect(basic("alice", "alice-password"), tg)
		c.Close()
		if code != 403 {
			t.Fatalf("app CONNECT %s: %d", tg, code)
		}
	}
}

func TestAppSwitchOff(t *testing.T) {
	h := newHarness(t, "10.9.9.0/24", appsTweak)
	c, a, rep := h.socks("alice", "alice-password", "public.test", 7)
	if a != 0 || rep != 0 {
		t.Fatalf("app with account: %x %x", a, rep)
	}
	cfg := h.readConfig()
	cfg.NoApps = true
	h.writeConfig(cfg)
	time.Sleep(200 * time.Millisecond)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("app tunnel still open after switching apps off")
	}
	c.Close()
	c, _, _ = h.socks("alice", "alice-password", "public.test", 7)
	c.Close()
	if r := h.lastLog("src_denied"); r.Reason != reasonNotLAN {
		t.Fatalf("log %+v", r)
	}
}
