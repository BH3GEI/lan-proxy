// Package core holds the shared configuration, status and log formats, the
// destination/source policy and the proxy server itself.
package core

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Version = "0.5.0"

// User is one proxy account. Only a salted PBKDF2 hash of the password is stored.
type User struct {
	Name    string `json:"name"`
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
	Enabled bool   `json:"enabled"`
	Note    string `json:"note,omitempty"`
	Created string `json:"created"`
}

// Config is written only by the admin service and read by the proxy service.
type Config struct {
	Enabled   bool     `json:"enabled"`
	Port      int      `json:"port"`
	ListenIP  string   `json:"listen_ip"`  // empty = the IPv4 address of the default-route interface
	LANCIDRs  []string `json:"lan_cidrs"`  // empty = the subnet of that interface
	ExtraDeny []string `json:"extra_deny"` // destinations always refused, in addition to the built-in list
	Users     []User   `json:"users"`
	// RequireAuth=false (the default, Yao's choice): clients from the LAN may
	// connect without credentials; clients that send credentials are still checked.
	RequireAuth bool `json:"require_auth"`
	// NoMesh=false (the default): also listen on the NAS's LazyCat network
	// address and accept clients from that network (same rules as the LAN).
	NoMesh bool `json:"no_mesh"`
	// NoApps=false (the default): LazyCat app containers on this NAS (the
	// lzc-br-* bridges) may use the LAN listener, always with an account.
	NoApps bool `json:"no_apps"`

	// Egress. "rules": LAN destinations direct, everything else through the
	// mihomo core (China list direct, the rest via subscription nodes).
	// "direct": everything direct from the NAS.
	EgressMode       string `json:"egress_mode"`
	SubURL           string `json:"sub_url,omitempty"` // secret: contains a token; never logged or shown
	SubIntervalHours int    `json:"sub_interval_hours"`
	TestURL          string `json:"test_url"`
}

const (
	EgressRules  = "rules"
	EgressDirect = "direct"
)

// Normalize fills defaults for fields added after the first release.
func (c *Config) Normalize() {
	if c.EgressMode == "" {
		c.EgressMode = EgressRules
	}
	if c.SubIntervalHours == 0 {
		c.SubIntervalHours = 6
	}
	if c.TestURL == "" {
		c.TestURL = "https://www.gstatic.com/generate_204"
	}
}

// MaskURL returns only the scheme and host of a subscription URL.
func MaskURL(u string) string {
	if u == "" {
		return ""
	}
	pu, err := url.Parse(u)
	if err != nil || pu.Host == "" {
		return "（已设置）"
	}
	return pu.Scheme + "://" + pu.Host + "/…"
}

func DefaultConfig() Config {
	return Config{
		Enabled: true,
		Port:    10800,
		// 192.168.3.2 is the LZCWrt side router, a VM that runs on the NAS itself.
		ExtraDeny:        []string{"192.168.3.2/32"},
		Users:            []User{},
		EgressMode:       EgressRules,
		SubIntervalHours: 6,
		TestURL:          "https://www.gstatic.com/generate_204",
	}
}

var userNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

func ValidUserName(name string) bool { return userNameRe.MatchString(name) }

const pbkdfIter = 120000

func HashPassword(password string) (salt, hash string, err error) {
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return
	}
	salt = hex.EncodeToString(b)
	k, err := pbkdf2.Key(sha256.New, password, b, pbkdfIter, 32)
	if err != nil {
		return
	}
	return salt, hex.EncodeToString(k), nil
}

func (u *User) Check(password string) bool {
	salt, err := hex.DecodeString(u.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(u.Hash)
	if err != nil {
		return false
	}
	k, err := pbkdf2.Key(sha256.New, password, salt, pbkdfIter, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(k, want) == 1
}

func (c *Config) Validate() error {
	if c.Port < 1024 || c.Port > 65535 {
		return fmt.Errorf("端口须在 1024–65535 之间")
	}
	if c.ListenIP != "" {
		if _, err := ParseIP(c.ListenIP); err != nil {
			return fmt.Errorf("监听地址无效：%v", err)
		}
	}
	for _, s := range append(append([]string{}, c.LANCIDRs...), c.ExtraDeny...) {
		if _, err := ParsePrefix(s); err != nil {
			return fmt.Errorf("网段 %q 无效", s)
		}
	}
	if c.EgressMode != EgressRules && c.EgressMode != EgressDirect {
		return fmt.Errorf("出口模式无效")
	}
	if c.SubURL != "" {
		u, err := url.Parse(c.SubURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.ContainsAny(c.SubURL, "\"'\n\r ") {
			return fmt.Errorf("订阅地址无效")
		}
	}
	if c.SubIntervalHours < 1 || c.SubIntervalHours > 168 {
		return fmt.Errorf("订阅更新间隔须为 1–168 小时")
	}
	if u, err := url.Parse(c.TestURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || strings.ContainsAny(c.TestURL, "\"'\n\r ") {
		return fmt.Errorf("测速地址无效")
	}
	seen := map[string]bool{}
	for _, u := range c.Users {
		if !ValidUserName(u.Name) {
			return fmt.Errorf("用户名 %q 无效", u.Name)
		}
		if seen[u.Name] {
			return fmt.Errorf("用户名 %q 重复", u.Name)
		}
		seen[u.Name] = true
	}
	return nil
}

// Paths of the files shared between the two services.
type Paths struct{ Dir string }

func (p Paths) Config() string  { return filepath.Join(p.Dir, "config.json") }
func (p Paths) Status() string  { return filepath.Join(p.Dir, "status.json") }
func (p Paths) ConnLog() string { return filepath.Join(p.Dir, "conn.jsonl") }

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultConfig(), err
	}
	if err != nil {
		return Config{}, err
	}
	c := DefaultConfig()
	c.ExtraDeny = nil
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	if c.Users == nil {
		c.Users = []User{}
	}
	c.Normalize()
	return c, nil
}

// WriteJSONAtomic writes v to path via a temporary file and rename, so readers never see a partial file.
func WriteJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Status is written by the proxy service every few seconds.
type Status struct {
	Version    string     `json:"version"`
	PID        int        `json:"pid"`
	Started    time.Time  `json:"started"`
	Updated    time.Time  `json:"updated"`
	Enabled    bool       `json:"enabled"`
	Listening  bool       `json:"listening"`
	Listen     string     `json:"listen"`
	ListenMesh string     `json:"listen_mesh,omitempty"`
	MeshCIDR   string     `json:"mesh_cidr,omitempty"`
	MeshNote   string     `json:"mesh_note,omitempty"` // why the LazyCat network listener is off
	AppCIDRs   []string   `json:"app_cidrs,omitempty"` // LazyCat app networks accepted with credentials
	LANCIDRs   []string   `json:"lan_cidrs"`
	DefaultIf  string     `json:"default_if"`
	Interfaces []IfStatus `json:"interfaces"`
	Error      string     `json:"error,omitempty"`
	Active     int64      `json:"active"`
	Total      int64      `json:"total"`
	Denied     int64      `json:"denied"`
	AuthFailed int64      `json:"auth_failed"`
	BytesUp    int64      `json:"bytes_up"`
	BytesDown  int64      `json:"bytes_down"`
	Users      int        `json:"users"`
	ActiveIDs  []string   `json:"active_users,omitempty"`
}

type IfStatus struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// ConnRecord is one line of conn.jsonl: metadata only, never payload.
type ConnRecord struct {
	Time    time.Time `json:"t"`
	ID      uint64    `json:"id"`
	Src     string    `json:"src"`
	User    string    `json:"user,omitempty"`
	Proto   string    `json:"proto,omitempty"` // socks5 | connect | http
	Target  string    `json:"target,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Result  string    `json:"result"` // ok | src_denied | auth_failed | auth_blocked | dst_denied | dial_failed | bad_request
	Reason  string    `json:"reason,omitempty"`
	Up      int64     `json:"up,omitempty"`
	Down    int64     `json:"down,omitempty"`
	DurMS   int64     `json:"dur_ms,omitempty"`
	Via     string    `json:"via,omitempty"`      // direct | core
	CoreSrc string    `json:"core_src,omitempty"` // local address of the hop to the core, to join with its routing log
	NoAuth  bool      `json:"noauth,omitempty"`   // accepted without credentials (LAN no-auth mode)
	Kind    string    `json:"kind,omitempty"`     // "app" for a LazyCat app container
	MAC     string    `json:"mac,omitempty"`      // source MAC from the NAS's ARP table, when known
	N       int       `json:"n,omitempty"`        // >0: this record folds N repeats of the previous identical one
}

// CoreEndpoint is written by the core service: where its SOCKS5 listener is.
type CoreEndpoint struct {
	Addr    string    `json:"addr"`
	User    string    `json:"user"`
	Pass    string    `json:"pass"`
	Started time.Time `json:"started"`
}

func (p Paths) CoreEndpoint() string { return filepath.Join(p.Dir, "core.json") }
func (p Paths) CoreDir() string      { return filepath.Join(p.Dir, "core") }
func (p Paths) CoreState() string    { return filepath.Join(p.Dir, "core-state.json") }
func (p Paths) RouteLog() string     { return filepath.Join(p.Dir, "route.jsonl") }
func (p Paths) ControllerSock() string {
	return filepath.Join(p.Dir, "run", "mihomo.sock")
}
