// Package web is the management interface. It runs in an ordinary app
// container behind LazyCat's login and talks to the proxy only through files.
package web

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lanproxy/internal/core"
	"lanproxy/internal/engine"
)

//go:embed index.html
var indexHTML []byte

type Admin struct {
	Paths       core.Paths
	RequireRole bool // require LazyCat's X-HC-User-Role: ADMIN header
	mu          sync.Mutex
}

func (a *Admin) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		w.Write(indexHTML)
	})
	m.HandleFunc("GET /api/state", a.state)
	m.HandleFunc("GET /api/logs", a.logs)
	m.HandleFunc("POST /api/settings", a.settings)
	m.HandleFunc("POST /api/users", a.upsertUser)
	m.HandleFunc("POST /api/users/toggle", a.toggleUser)
	m.HandleFunc("POST /api/users/delete", a.deleteUser)
	m.HandleFunc("POST /api/selftest", a.selftest)
	m.HandleFunc("GET /api/core", a.coreState)
	m.HandleFunc("POST /api/core/select", a.coreSelect)
	m.HandleFunc("POST /api/core/test", a.coreTest)
	m.HandleFunc("POST /api/core/update", a.coreUpdate)
	return a.guard(m)
}

func (a *Admin) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.RequireRole && r.Header.Get("X-HC-User-Role") != "ADMIN" {
			http.Error(w, "仅限懒猫管理员", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Lanproxy") != "1" {
			http.Error(w, "missing X-Lanproxy header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v)
}

// EnsureConfig writes the default config on first start.
func (a *Admin) EnsureConfig() error {
	if _, err := os.Stat(a.Paths.Config()); err == nil {
		return nil
	}
	return core.WriteJSONAtomic(a.Paths.Config(), core.DefaultConfig())
}

// mutate loads the config, applies fn, validates and writes it atomically.
func (a *Admin) Mutate(fn func(c *core.Config) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, err := core.LoadConfig(a.Paths.Config())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := fn(&c); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	return core.WriteJSONAtomic(a.Paths.Config(), c)
}

type userView struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Note    string `json:"note"`
	Created string `json:"created"`
}

func (a *Admin) state(w http.ResponseWriter, r *http.Request) {
	c, err := core.LoadConfig(a.Paths.Config())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fail(w, 500, err.Error())
		return
	}
	users := []userView{}
	for _, u := range c.Users {
		users = append(users, userView{u.Name, u.Enabled, u.Note, u.Created})
	}
	var st *core.Status
	if b, err := os.ReadFile(a.Paths.Status()); err == nil {
		st = &core.Status{}
		if json.Unmarshal(b, st) != nil {
			st = nil
		}
	}
	stale := st == nil || time.Since(st.Updated) > 15*time.Second
	writeJSON(w, 200, map[string]any{
		"settings": map[string]any{
			"enabled": c.Enabled, "port": c.Port, "listen_ip": c.ListenIP,
			"lan_cidrs": nz(c.LANCIDRs), "extra_deny": nz(c.ExtraDeny),
			"egress_mode": c.EgressMode, "sub_set": c.SubURL != "", "sub_host": core.MaskURL(c.SubURL),
			"sub_interval_hours": c.SubIntervalHours, "test_url": c.TestURL,
			"lan_no_auth": !c.RequireAuth, "mesh": !c.NoMesh, "apps": !c.NoApps,
		},
		"disk":   a.diskUsage(),
		"users":  users,
		"status": st,
		"stale":  stale,
		"now":    time.Now(),
	})
}

func (a *Admin) diskUsage() map[string]int64 {
	sum := func(base string, keep int) int64 {
		var n int64
		for _, p := range core.LogFilesNewestFirst(base, keep) {
			if st, err := os.Stat(p); err == nil {
				n += st.Size()
			}
		}
		return n
	}
	return map[string]int64{
		"conn":      sum(a.Paths.ConnLog(), core.LogFiles),
		"conn_cap":  core.LogFileBytes * core.LogFiles,
		"route":     sum(a.Paths.RouteLog(), engine.RouteFiles),
		"route_cap": engine.RouteFileBytes * engine.RouteFiles,
		"core":      core.DirBytes(a.Paths.CoreDir()),
	}
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *Admin) settings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled   *bool     `json:"enabled"`
		Port      *int      `json:"port"`
		ListenIP  *string   `json:"listen_ip"`
		LANCIDRs  *[]string `json:"lan_cidrs"`
		ExtraDeny *[]string `json:"extra_deny"`
		Egress    *string   `json:"egress_mode"`
		SubURL    *string   `json:"sub_url"` // write-only; "" clears
		SubHours  *int      `json:"sub_interval_hours"`
		TestURL   *string   `json:"test_url"`
		LANNoAuth *bool     `json:"lan_no_auth"`
		Mesh      *bool     `json:"mesh"`
		Apps      *bool     `json:"apps"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "请求格式错误")
		return
	}
	err := a.Mutate(func(c *core.Config) error {
		if in.Enabled != nil {
			c.Enabled = *in.Enabled
		}
		if in.Port != nil {
			c.Port = *in.Port
		}
		if in.ListenIP != nil {
			c.ListenIP = strings.TrimSpace(*in.ListenIP)
		}
		if in.LANCIDRs != nil {
			c.LANCIDRs = cleanList(*in.LANCIDRs)
		}
		if in.ExtraDeny != nil {
			c.ExtraDeny = cleanList(*in.ExtraDeny)
		}
		if in.Egress != nil {
			c.EgressMode = *in.Egress
		}
		if in.SubURL != nil {
			c.SubURL = strings.TrimSpace(*in.SubURL)
		}
		if in.SubHours != nil {
			c.SubIntervalHours = *in.SubHours
		}
		if in.TestURL != nil {
			c.TestURL = strings.TrimSpace(*in.TestURL)
		}
		if in.LANNoAuth != nil {
			c.RequireAuth = !*in.LANNoAuth
		}
		if in.Mesh != nil {
			c.NoMesh = !*in.Mesh
		}
		if in.Apps != nil {
			c.NoApps = !*in.Apps
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func cleanList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

const pwAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randomPassword(n int) string {
	b := make([]byte, n)
	for i := range b {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pwAlphabet))))
		b[i] = pwAlphabet[k.Int64()]
	}
	return string(b)
}

// upsertUser creates an account or sets a new password. An empty password generates one.
func (a *Admin) upsertUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Note     string `json:"note"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "请求格式错误")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !core.ValidUserName(in.Name) {
		fail(w, 400, "用户名只能包含字母、数字和 . _ -，长度 1–32")
		return
	}
	generated := false
	if in.Password == "" {
		in.Password, generated = randomPassword(16), true
	}
	if len(in.Password) < 8 || len(in.Password) > 128 || strings.ContainsAny(in.Password, ":\r\n") {
		fail(w, 400, "密码长度须为 8–128，且不能包含冒号或换行")
		return
	}
	salt, hash, err := core.HashPassword(in.Password)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	created := false
	err = a.Mutate(func(c *core.Config) error {
		for i := range c.Users {
			if c.Users[i].Name == in.Name {
				c.Users[i].Salt, c.Users[i].Hash = salt, hash
				if in.Note != "" {
					c.Users[i].Note = in.Note
				}
				return nil
			}
		}
		if len(c.Users) >= 64 {
			return fmt.Errorf("账号数已达上限 64")
		}
		created = true
		c.Users = append(c.Users, core.User{Name: in.Name, Salt: salt, Hash: hash, Enabled: true, Note: in.Note, Created: time.Now().Format(time.RFC3339)})
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	resp := map[string]any{"ok": true, "created": created}
	if generated {
		resp["password"] = in.Password // shown once; only the hash is stored
	}
	writeJSON(w, 200, resp)
}

func (a *Admin) toggleUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "请求格式错误")
		return
	}
	err := a.Mutate(func(c *core.Config) error {
		for i := range c.Users {
			if c.Users[i].Name == in.Name {
				c.Users[i].Enabled = in.Enabled
				return nil
			}
		}
		return fmt.Errorf("没有账号 %q", in.Name)
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Admin) deleteUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, "请求格式错误")
		return
	}
	err := a.Mutate(func(c *core.Config) error {
		for i := range c.Users {
			if c.Users[i].Name == in.Name {
				c.Users = append(c.Users[:i], c.Users[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("没有账号 %q", in.Name)
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// LogFilter selects connection records; empty fields match everything.
type LogFilter struct {
	User, Result, Src, Target string
}

func (f LogFilter) match(rec core.ConnRecord) bool {
	if f.User != "" && rec.User != f.User && !(f.User == "-" && rec.NoAuth) {
		return false
	}
	if f.Result == "denied" {
		if rec.Result == "ok" {
			return false
		}
	} else if f.Result != "" && rec.Result != f.Result {
		return false
	}
	if f.Src != "" && !strings.Contains(rec.Src, f.Src) && !strings.EqualFold(rec.MAC, f.Src) {
		return false
	}
	if f.Target != "" && !strings.Contains(strings.ToLower(rec.Target+" "+rec.IP), strings.ToLower(f.Target)) {
		return false
	}
	return true
}

// readLog returns up to n records, newest first, reading the newest files first.
func (a *Admin) readLog(n int, f LogFilter) []core.ConnRecord {
	out := make([]core.ConnRecord, 0, n)
	for _, p := range core.LogFilesNewestFirst(a.Paths.ConnLog(), core.LogFiles) {
		fh, err := os.Open(p)
		if err != nil {
			continue
		}
		var recs []core.ConnRecord
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var rec core.ConnRecord
			if json.Unmarshal(sc.Bytes(), &rec) == nil && f.match(rec) {
				recs = append(recs, rec)
			}
		}
		fh.Close()
		for i := len(recs) - 1; i >= 0 && len(out) < n; i-- {
			out = append(out, recs[i])
		}
		if len(out) >= n {
			break
		}
	}
	return out
}

func (a *Admin) logs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 2000 {
		n = 300
	}
	q := r.URL.Query()
	f := LogFilter{User: q.Get("user"), Result: q.Get("result"), Src: strings.TrimSpace(q.Get("src")), Target: strings.TrimSpace(q.Get("target"))}
	writeJSON(w, 200, a.enrich(a.readLog(n, f)))
}

// selftest connects to the proxy from this container (a container-network
// address, outside the LAN) and checks that the proxy refuses it.
func (a *Admin) selftest(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(a.Paths.Status())
	var st core.Status
	if err != nil || json.Unmarshal(b, &st) != nil || st.Listen == "" {
		fail(w, 400, "代理未在监听，无法自检")
		return
	}
	res := map[string]any{"target": st.Listen}
	c, err := net.DialTimeout("tcp", st.Listen, 3*time.Second)
	if err != nil {
		res["connect"] = "连接失败：" + err.Error()
		res["pass"] = true
		res["summary"] = "容器网络无法连到代理端口，来源被拒（连接层）"
		writeJSON(w, 200, res)
		return
	}
	local := c.LocalAddr().String()
	res["source"] = local
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{0x05, 0x01, 0x02})
	buf := make([]byte, 2)
	nr, rerr := io.ReadFull(c, buf)
	c.Close()
	if nr == 2 && buf[0] == 0x05 {
		res["pass"] = false
		res["summary"] = "代理回应了来自容器网络的 SOCKS5 握手，来源过滤未生效"
		writeJSON(w, 200, res)
		return
	}
	res["pass"] = true
	res["summary"] = fmt.Sprintf("代理在握手前关闭了来自 %s 的连接（%v）", local, rerr)
	time.Sleep(300 * time.Millisecond)
	for _, rec := range a.readLog(50, LogFilter{Result: "src_denied"}) {
		if rec.Src == local {
			res["log"] = rec
			break
		}
	}
	writeJSON(w, 200, res)
}

func ListenAndServe(addr string, a *Admin) error {
	srv := &http.Server{Addr: addr, Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}
