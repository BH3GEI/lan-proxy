package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"lanproxy/internal/core"
)

func req(t *testing.T, h http.Handler, method, path, body string, hdr map[string]string) (int, map[string]any) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var m map[string]any
	json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func TestAdmin(t *testing.T) {
	dir := t.TempDir()
	a := &Admin{Paths: core.Paths{Dir: dir}, RequireRole: true}
	if err := a.EnsureConfig(); err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	admin := map[string]string{"X-HC-User-Role": "ADMIN", "X-Lanproxy": "1"}
	if c, _ := req(t, h, "GET", "/api/state", "", nil); c != 403 {
		t.Fatalf("no role: %d", c)
	}
	if c, _ := req(t, h, "GET", "/api/state", "", map[string]string{"X-HC-User-Role": "NORMAL"}); c != 403 {
		t.Fatalf("normal user: %d", c)
	}
	if c, _ := req(t, h, "POST", "/api/users", `{"name":"x","password":"12345678"}`, map[string]string{"X-HC-User-Role": "ADMIN"}); c != 403 {
		t.Fatalf("missing csrf header: %d", c)
	}
	c, m := req(t, h, "POST", "/api/users", `{"name":"phone","password":"secret-pass-1"}`, admin)
	if c != 200 || m["created"] != true {
		t.Fatalf("create: %d %v", c, m)
	}
	c, m = req(t, h, "POST", "/api/users", `{"name":"laptop"}`, admin)
	pw, _ := m["password"].(string)
	if c != 200 || len(pw) != 16 {
		t.Fatalf("generated: %d %v", c, m)
	}
	raw, _ := os.ReadFile(a.Paths.Config())
	if strings.Contains(string(raw), "secret-pass-1") || strings.Contains(string(raw), pw) {
		t.Fatal("plaintext password in config file")
	}
	cfg, _ := core.LoadConfig(a.Paths.Config())
	if len(cfg.Users) != 2 || !cfg.Users[0].Check("secret-pass-1") || !cfg.Users[1].Check(pw) {
		t.Fatal("hash check")
	}
	if c, _ := req(t, h, "POST", "/api/users", `{"name":"bad name","password":"12345678"}`, admin); c != 400 {
		t.Fatal("bad username accepted")
	}
	if c, _ := req(t, h, "POST", "/api/users", `{"name":"y","password":"short"}`, admin); c != 400 {
		t.Fatal("short password accepted")
	}
	if c, _ := req(t, h, "POST", "/api/users/toggle", `{"name":"phone","enabled":false}`, admin); c != 200 {
		t.Fatal("toggle")
	}
	if c, _ := req(t, h, "POST", "/api/settings", `{"port":80}`, admin); c != 400 {
		t.Fatal("port 80 accepted")
	}
	if c, _ := req(t, h, "POST", "/api/settings", `{"lan_cidrs":["nonsense"]}`, admin); c != 400 {
		t.Fatal("bad cidr accepted")
	}
	if c, _ := req(t, h, "POST", "/api/settings", `{"enabled":false,"port":12000}`, admin); c != 200 {
		t.Fatal("settings")
	}
	c, m = req(t, h, "GET", "/api/state", "", admin)
	s := m["settings"].(map[string]any)
	us := m["users"].([]any)
	if c != 200 || s["enabled"] != false || s["port"].(float64) != 12000 || us[0].(map[string]any)["enabled"] != false {
		t.Fatalf("state %v", m)
	}
	if strings.Contains(func() string { b, _ := json.Marshal(m); return string(b) }(), "hash") {
		t.Fatal("state exposes hashes")
	}
	if c, _ := req(t, h, "POST", "/api/users/delete", `{"name":"laptop"}`, admin); c != 200 {
		t.Fatal("delete")
	}
}
