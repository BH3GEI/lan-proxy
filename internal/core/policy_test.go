package core

import (
	"net/netip"
	"strings"
	"testing"
)

// fakeView models the NAS: LAN on eth0, a docker bridge, a LazyCat tunnel
// with both a private and a public-looking range, IPv6 global and ULA addresses.
func fakeView() *NetView {
	v := &NetView{
		DefaultIf:  "eth0",
		DefaultIP:  netip.MustParseAddr("192.168.3.89"),
		DefaultNet: netip.MustParsePrefix("192.168.3.0/24"),
		LocalIPs:   map[netip.Addr]string{},
		Ifaces: []IfStatus{
			{"lo", []string{"127.0.0.1/8", "::1/128"}},
			{"eth0", []string{"192.168.3.89/24", "2408:8000:1:2::89/64", "fe80::1234/64"}},
			{"docker0", []string{"172.17.0.1/16"}},
			{"heiyu0", []string{"100.80.0.5/16", "fc03:1136:3800::5/64", "6.6.6.6/32"}},
			{"vlan-shim-a", []string{"192.168.3.250/32"}},
		},
		Routes: []Route{
			{netip.MustParsePrefix("0.0.0.0/0"), "eth0", 100},
			{netip.MustParsePrefix("192.168.3.0/24"), "eth0", 100},
			{netip.MustParsePrefix("192.168.3.2/32"), "vlan-shim-a", 0},
			{netip.MustParsePrefix("172.17.0.0/16"), "docker0", 0},
			{netip.MustParsePrefix("100.80.0.0/16"), "heiyu0", 0},
			{netip.MustParsePrefix("6.6.0.0/16"), "heiyu0", 0},
			{netip.MustParsePrefix("::/0"), "eth0", 1024},
			{netip.MustParsePrefix("fc03:1136:3800::/64"), "heiyu0", 0},
		},
	}
	for _, st := range v.Ifaces {
		for _, s := range st.Addrs {
			v.LocalIPs[netip.MustParsePrefix(s).Addr()] = st.Name
		}
	}
	return v
}

func fakePolicy(t *testing.T) *Policy {
	p, err := BuildPolicy(DefaultConfig(), fakeView())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAutoDetectListenAndLAN(t *testing.T) {
	p := fakePolicy(t)
	if p.ListenIP.String() != "192.168.3.89" {
		t.Fatalf("listen %s", p.ListenIP)
	}
	if len(p.LAN) != 1 || p.LAN[0].String() != "192.168.3.0/24" {
		t.Fatalf("lan %v", p.LAN)
	}
}

func TestDestDenied(t *testing.T) {
	p := fakePolicy(t)
	cases := []string{
		// loopback, including IPv4-mapped IPv6
		"127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::",
		// every NAS address, on every interface, also IPv4-mapped
		"192.168.3.89", "::ffff:192.168.3.89", "2408:8000:1:2::89", "fe80::1234", "172.17.0.1",
		"100.80.0.5", "fc03:1136:3800::5", "6.6.6.6", "192.168.3.250",
		// container networks
		"172.17.0.2", "172.20.1.1", "::ffff:172.17.0.2", "10.0.0.1",
		// LazyCat virtual network peers (private and routed via the tunnel)
		"100.80.0.9", "fc03:1136:3800::9", "6.6.1.1",
		// link-local
		"169.254.1.1", "fe80::1", "::ffff:169.254.169.254",
		// multicast and broadcast
		"224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255", "192.168.3.255", "192.168.3.0",
		// other private or reserved ranges outside the LAN
		"192.168.4.10", "198.18.0.1", "fd00::1", "64:ff9b::7f00:1", "2002:7f00:1::1",
		// extra deny (LZCWrt on the NAS)
		"192.168.3.2",
	}
	for _, s := range cases {
		a := netip.MustParseAddr(s)
		if r := p.CheckDest(a); r == "" {
			t.Errorf("%s: allowed, want denied", s)
		} else {
			t.Logf("%-22s denied: %s", s, r)
		}
	}
}

func TestDestAllowed(t *testing.T) {
	p := fakePolicy(t)
	for _, s := range []string{"192.168.3.50", "192.168.3.1", "1.1.1.1", "93.184.216.34", "::ffff:8.8.8.8", "2606:4700:4700::1111"} {
		if r := p.CheckDest(netip.MustParseAddr(s)); r != "" {
			t.Errorf("%s: denied (%s), want allowed", s, r)
		}
	}
}

func TestSource(t *testing.T) {
	p := fakePolicy(t)
	ok := []string{"192.168.3.50", "::ffff:192.168.3.192"}
	bad := []string{"192.168.3.89", "192.168.3.250", "172.17.0.2", "100.80.0.9", "fc03:1136:3800::9", "6.6.6.6", "127.0.0.1", "192.168.4.1", "8.8.8.8", "2408:8000:1:2::50"}
	for _, s := range ok {
		if r := p.CheckSource(netip.MustParseAddr(s)); r != "" {
			t.Errorf("source %s denied: %s", s, r)
		}
	}
	for _, s := range bad {
		if r := p.CheckSource(netip.MustParseAddr(s)); r == "" {
			t.Errorf("source %s allowed, want denied", s)
		}
	}
}

func TestListenAddressRestrictions(t *testing.T) {
	v := fakeView()
	for _, ip := range []string{"0.0.0.0", "::", "127.0.0.1", "172.17.0.1", "100.80.0.5", "2408:8000:1:2::89", "192.168.3.77"} {
		c := DefaultConfig()
		c.ListenIP = ip
		if _, err := BuildPolicy(c, v); err == nil {
			t.Errorf("listen %s accepted, want error", ip)
		}
	}
	for _, lan := range []string{"0.0.0.0/0", "192.168.0.0/8", "172.16.0.0/12", "100.80.0.0/16", "8.8.8.0/24", "fd00::/8"} {
		c := DefaultConfig()
		c.LANCIDRs = []string{lan}
		if _, err := BuildPolicy(c, v); err == nil {
			t.Errorf("lan %s accepted, want error", lan)
		}
	}
}

func TestParseProcRoutes(t *testing.T) {
	v4 := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0203A8C0	0003	0	0	100	00000000	0	0	0
eth0	0003A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`
	rs := parseIPv4Routes(strings.NewReader(v4))
	if len(rs) != 3 || rs[0].Prefix.String() != "0.0.0.0/0" || rs[1].Prefix.String() != "192.168.3.0/24" || rs[2].Prefix.String() != "172.17.0.0/16" || rs[2].Iface != "docker0" || rs[0].Metric != 100 {
		t.Fatalf("v4 %+v", rs)
	}
	v6 := `fc031136380000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001   heiyu0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000003 00000000 80200001       lo
`
	rs = parseIPv6Routes(strings.NewReader(v6))
	if len(rs) != 2 || rs[0].Prefix.String() != "fc03:1136:3800::/64" || rs[0].Iface != "heiyu0" || rs[1].Prefix.String() != "::/0" || rs[1].Metric != 1024 {
		t.Fatalf("v6 %+v", rs)
	}
}

func TestPasswordHash(t *testing.T) {
	salt, hash, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	u := User{Salt: salt, Hash: hash}
	if !u.Check("correct horse") || u.Check("correct horsf") || u.Check("") {
		t.Fatal("check mismatch")
	}
	if strings.Contains(hash, "correct") {
		t.Fatal("hash contains plaintext")
	}
}
