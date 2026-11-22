package core

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

func ParseIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return a, err
	}
	return a.Unmap(), nil
}

// ParsePrefix accepts "a.b.c.d/n" or a bare address (treated as a single host).
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := ParseIP(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, err
	}
	return p.Masked(), nil
}

// Address ranges that are never valid destinations unless they fall inside the
// LAN subnet. They cover loopback, container and VPN networks, link-local,
// multicast, documentation and benchmarking ranges and translation prefixes.
var reservedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
	"2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := ParsePrefix(s)
		if err != nil {
			panic(err)
		}
		out = append(out, p)
	}
	return out
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Route is one entry of the kernel main routing table.
type Route struct {
	Prefix netip.Prefix
	Iface  string
	Metric int
}

// NetView is a snapshot of the host network as seen from the proxy's network namespace.
type NetView struct {
	DefaultIf  string
	DefaultIP  netip.Addr   // IPv4 address on DefaultIf
	DefaultNet netip.Prefix // its subnet
	LocalIPs   map[netip.Addr]string
	Ifaces     []IfStatus
	Routes     []Route // empty when the routing table is unavailable (non-Linux)
}

// ScanNetwork reads interface addresses and the main routing table.
func ScanNetwork() (*NetView, error) {
	v := &NetView{LocalIPs: map[netip.Addr]string{}}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ifNets := map[string][]netip.Prefix{}
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		st := IfStatus{Name: ifc.Name}
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			a, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			ones, _ := ipn.Mask.Size()
			v.LocalIPs[a] = ifc.Name
			ifNets[ifc.Name] = append(ifNets[ifc.Name], netip.PrefixFrom(a, ones))
			st.Addrs = append(st.Addrs, netip.PrefixFrom(a, ones).String())
		}
		if len(st.Addrs) > 0 {
			v.Ifaces = append(v.Ifaces, st)
		}
	}
	v.Routes = readRoutes()
	best := -1
	for _, r := range v.Routes {
		if r.Prefix.Bits() == 0 && r.Prefix.Addr().Is4() && (best < 0 || r.Metric < best) {
			best = r.Metric
			v.DefaultIf = r.Iface
		}
	}
	if v.DefaultIf == "" {
		// Fallback for systems without /proc: first interface holding a private IPv4 address.
		for _, st := range v.Ifaces {
			for _, p := range ifNets[st.Name] {
				if p.Addr().Is4() && p.Addr().IsPrivate() && !strings.HasPrefix(st.Name, "docker") && !strings.HasPrefix(st.Name, "br-") {
					v.DefaultIf = st.Name
					break
				}
			}
			if v.DefaultIf != "" {
				break
			}
		}
	}
	for _, p := range ifNets[v.DefaultIf] {
		if p.Addr().Is4() {
			v.DefaultIP = p.Addr()
			v.DefaultNet = p.Masked()
			break
		}
	}
	return v, nil
}

func readRoutes() []Route {
	var out []Route
	if f, err := os.Open("/proc/net/route"); err == nil {
		out = append(out, parseIPv4Routes(f)...)
		f.Close()
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		out = append(out, parseIPv6Routes(f)...)
		f.Close()
	}
	return out
}

func parseIPv4Routes(r io.Reader) []Route {
	var out []Route
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 8 {
			continue
		}
		dst, err1 := hexLE32(fs[1])
		mask, err2 := hexLE32(fs[7])
		if err1 != nil || err2 != nil {
			continue
		}
		ones, _ := net.IPMask(mask[:]).Size()
		metric, _ := strconv.Atoi(fs[6])
		out = append(out, Route{netip.PrefixFrom(netip.AddrFrom4(dst), ones).Masked(), fs[0], metric})
	}
	return out
}

func parseIPv6Routes(r io.Reader) []Route {
	var out []Route
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		b, err := hex.DecodeString(fs[0])
		if err != nil || len(b) != 16 {
			continue
		}
		ones, _ := strconv.ParseInt(fs[1], 16, 32)
		metric, _ := strconv.ParseInt(fs[5], 16, 64)
		if fs[9] == "lo" {
			continue // local and unreachable entries; local IPs are handled separately
		}
		out = append(out, Route{netip.PrefixFrom(netip.AddrFrom16([16]byte(b)), int(ones)).Masked(), fs[9], int(metric)})
	}
	return out
}

func hexLE32(s string) ([4]byte, error) {
	var r [4]byte
	u, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return r, err
	}
	r[0], r[1], r[2], r[3] = byte(u), byte(u>>8), byte(u>>16), byte(u>>24)
	return r, nil
}

// RouteIface returns the interface the main table would use for a, or "" if unknown.
func (v *NetView) RouteIface(a netip.Addr) string {
	bestBits, bestMetric, iface := -1, 0, ""
	for _, r := range v.Routes {
		if r.Prefix.Addr().Is4() != a.Is4() || !r.Prefix.Contains(a) {
			continue
		}
		if r.Prefix.Bits() > bestBits || (r.Prefix.Bits() == bestBits && r.Metric < bestMetric) {
			bestBits, bestMetric, iface = r.Prefix.Bits(), r.Metric, r.Iface
		}
	}
	return iface
}

// Policy decides which clients may connect and which destinations they may reach.
type Policy struct {
	Net       *NetView
	ListenIP  netip.Addr
	LAN       []netip.Prefix
	ExtraDeny []netip.Prefix

	// LazyCat network (IPv6 ULA overlay, interface heiyu-0 on the NAS).
	// Valid only when found and enabled.
	MeshIP   netip.Addr
	Mesh     netip.Prefix
	MeshIf   string
	MeshNote string // why it is off
}

// fc00::/8 holds the LazyCat network (fc03:1136:…); docker and LazyCat
// container networks use fd00::/8 and are never treated as the mesh.
var meshSpace = netip.MustParsePrefix("fc00::/8")

// findMesh returns the single local address inside fc00::/8 with a
// network-sized prefix (/8 to /64), the LazyCat network interface address.
func findMesh(v *NetView) (netip.Addr, netip.Prefix, string, string) {
	type cand struct {
		pf    netip.Prefix
		iface string
	}
	var cs []cand
	for _, st := range v.Ifaces {
		for _, s := range st.Addrs {
			pf, err := netip.ParsePrefix(s)
			if err != nil || !pf.Addr().Is6() || pf.Addr().Is4In6() || !meshSpace.Contains(pf.Addr()) {
				continue
			}
			if pf.Bits() < 8 || pf.Bits() > 64 {
				continue
			}
			cs = append(cs, cand{pf, st.Name})
		}
	}
	switch len(cs) {
	case 0:
		return netip.Addr{}, netip.Prefix{}, "", "未找到懒猫组网地址"
	case 1:
		return cs[0].pf.Addr(), cs[0].pf.Masked(), cs[0].iface, ""
	}
	return netip.Addr{}, netip.Prefix{}, "", "找到多个懒猫组网地址，为安全起见不监听"
}

func BuildPolicy(cfg Config, v *NetView) (*Policy, error) {
	p := &Policy{Net: v}
	if cfg.ListenIP != "" {
		a, err := ParseIP(cfg.ListenIP)
		if err != nil {
			return nil, err
		}
		p.ListenIP = a
	} else {
		p.ListenIP = v.DefaultIP
	}
	if !p.ListenIP.IsValid() {
		return nil, fmt.Errorf("找不到局域网 IPv4 地址（默认路由网卡 %q）", v.DefaultIf)
	}
	if !p.ListenIP.Is4() || p.ListenIP.IsUnspecified() || p.ListenIP.IsLoopback() {
		return nil, fmt.Errorf("监听地址 %s 无效：只允许局域网 IPv4 地址", p.ListenIP)
	}
	if _, ok := v.LocalIPs[p.ListenIP]; !ok {
		return nil, fmt.Errorf("监听地址 %s 不在本机网卡上", p.ListenIP)
	}
	for _, s := range cfg.LANCIDRs {
		pf, err := ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		p.LAN = append(p.LAN, pf)
	}
	if len(p.LAN) == 0 {
		if !v.DefaultNet.IsValid() {
			return nil, fmt.Errorf("无法确定局域网网段")
		}
		p.LAN = []netip.Prefix{v.DefaultNet}
	}
	rfc1918 := mustPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	for _, pf := range p.LAN {
		if !pf.Addr().Is4() || pf.Bits() < 16 || !inAny(pf.Addr(), rfc1918) || !inAny(lastAddr(pf), rfc1918) {
			return nil, fmt.Errorf("局域网网段 %s 无效：须为私有 IPv4 网段，前缀不短于 /16", pf)
		}
		for _, st := range v.Ifaces {
			if v.OnLAN(st.Name) {
				continue // the LAN interface itself, or a macvlan shim on the same LAN
			}
			for _, s := range st.Addrs {
				if ip, err := netip.ParsePrefix(s); err == nil && ip.Masked().Overlaps(pf) {
					return nil, fmt.Errorf("局域网网段 %s 与网卡 %s 的网段 %s 重叠", pf, st.Name, ip.Masked())
				}
			}
		}
	}
	if !inAny(p.ListenIP, p.LAN) {
		return nil, fmt.Errorf("监听地址 %s 不在局域网网段内", p.ListenIP)
	}
	for _, s := range cfg.ExtraDeny {
		pf, err := ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		p.ExtraDeny = append(p.ExtraDeny, pf)
	}
	if cfg.NoMesh {
		p.MeshNote = "已关闭"
	} else {
		p.MeshIP, p.Mesh, p.MeshIf, p.MeshNote = findMesh(v)
	}
	return p, nil
}

// CheckSourceAt checks a client by the address it came from and the local
// address it connected to. The LAN listener serves only LAN IPv4 sources; the
// LazyCat-network listener serves only sources inside that network whose
// return route goes out the LazyCat interface.
func (p *Policy) CheckSourceAt(a, local netip.Addr) string {
	a, local = a.Unmap(), local.Unmap()
	if p.MeshIP.IsValid() && local == p.MeshIP {
		if iface, ok := p.Net.LocalIPs[a]; ok {
			return "来源是本机地址（" + iface + "）"
		}
		if !p.Mesh.Contains(a) {
			return "来源不在懒猫组网网段内"
		}
		if len(p.Net.Routes) > 0 {
			if iface := p.Net.RouteIface(a); iface != p.MeshIf {
				return "来源的回程路由不经懒猫组网网卡（" + iface + "）"
			}
		}
		return ""
	}
	if local.IsValid() && local != p.ListenIP {
		return "连接到了未授权的本机地址 " + local.String()
	}
	return p.CheckSource(a)
}

// CheckSource returns "" when the client address may use the proxy.
func (p *Policy) CheckSource(a netip.Addr) string {
	a = a.Unmap()
	if iface, ok := p.Net.LocalIPs[a]; ok {
		return "来源是本机地址（" + iface + "）"
	}
	if !inAny(a, p.LAN) {
		return "来源不在局域网网段内"
	}
	return ""
}

// CheckDest returns "" when the proxy may open a connection to a.
func (p *Policy) CheckDest(a netip.Addr) string {
	a = a.Unmap()
	if !a.IsValid() {
		return "地址无效"
	}
	if iface, ok := p.Net.LocalIPs[a]; ok {
		return "目标是 NAS 本机地址（" + iface + "）"
	}
	if a.IsUnspecified() || a.IsLoopback() {
		return "目标是本机回环地址"
	}
	if inAny(a, p.ExtraDeny) {
		return "目标在禁止网段内"
	}
	if a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return "目标是组播或链路本地地址"
	}
	for _, pf := range append(append([]netip.Prefix{}, p.LAN...), p.Net.LocalNets()...) {
		if pf.Addr().Is4() && a.Is4() && pf.Bits() < 31 && pf.Contains(a) && (a == pf.Masked().Addr() || a == lastAddr(pf)) {
			return "目标是网段的网络地址或广播地址"
		}
	}
	lan := inAny(a, p.LAN)
	if !lan && inAny(a, reservedPrefixes) {
		return "目标是内网或保留地址（不在局域网网段内）"
	}
	if len(p.Net.Routes) > 0 {
		if iface := p.Net.RouteIface(a); iface != "" && !p.Net.OnLAN(iface) {
			return "目标经由非局域网网卡 " + iface
		}
	}
	return ""
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	u := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

// OnLAN reports whether iface is the default-route interface or carries an
// address inside its subnet (for example a macvlan shim attached to the LAN).
func (v *NetView) OnLAN(iface string) bool {
	if iface == v.DefaultIf {
		return true
	}
	if !v.DefaultNet.IsValid() {
		return false
	}
	for _, st := range v.Ifaces {
		if st.Name != iface {
			continue
		}
		for _, s := range st.Addrs {
			if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() && v.DefaultNet.Contains(p.Addr()) && p.Bits() >= v.DefaultNet.Bits() {
				return true
			}
		}
	}
	return false
}

// LocalNets returns the subnets of all local interface addresses.
func (v *NetView) LocalNets() []netip.Prefix {
	var out []netip.Prefix
	for _, st := range v.Ifaces {
		for _, s := range st.Addrs {
			if p, err := netip.ParsePrefix(s); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

func (v *NetView) IfaceList() []IfStatus {
	out := append([]IfStatus(nil), v.Ifaces...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
