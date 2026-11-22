package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"lanproxy/internal/core"
)

// SubStatus describes the last subscription fetch.
type SubStatus struct {
	Fetched  time.Time `json:"fetched"`         // last successful fetch or import
	Via      string    `json:"via,omitempty"`   // 直连 | 经节点 | 导入
	Attempt  time.Time `json:"attempt"`         // last attempt
	Error    string    `json:"error,omitempty"` // last error, scrubbed
	Bytes    int       `json:"bytes,omitempty"`
	Upload   int64     `json:"upload,omitempty"` // from subscription-userinfo
	Download int64     `json:"download,omitempty"`
	Total    int64     `json:"total,omitempty"`
	Expire   int64     `json:"expire,omitempty"`
}

func (p refreshPaths) flag() string { return filepath.Join(string(p), "run", "sub-refresh") }

type refreshPaths string

// RequestRefresh asks the engine to fetch the subscription now (used by the admin page).
func RequestRefresh(dir string) error {
	return os.WriteFile(refreshPaths(dir).flag(), []byte(time.Now().Format(time.RFC3339)), 0o600)
}

// ValidateSub checks that b looks like a node list mihomo can read: a Clash
// YAML document with proxies, or (base64-encoded) share links.
func ValidateSub(b []byte) error {
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return errors.New("订阅内容为空")
	}
	if bytes.Contains(t, []byte("proxies:")) {
		return nil
	}
	if d, err := base64.StdEncoding.DecodeString(string(t)); err == nil {
		t = d
	} else if d, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(string(t), "=")); err == nil {
		t = d
	}
	if bytes.Contains(t, []byte("://")) {
		return nil
	}
	return errors.New("订阅内容无法识别（既不是 Clash YAML，也不是分享链接）")
}

// ImportSub stores a node list supplied out of band (first bootstrap when the
// subscription host cannot be reached directly).
func ImportSub(dir string, b []byte) error {
	if err := ValidateSub(b); err != nil {
		return err
	}
	p := core.Paths{Dir: dir}
	f := filepath.Join(p.CoreDir(), "providers", "sub.yaml")
	os.MkdirAll(filepath.Dir(f), 0o700)
	if err := os.WriteFile(f+".tmp", b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(f+".tmp", f); err != nil {
		return err
	}
	return core.WriteJSONAtomic(filepath.Join(p.CoreDir(), "sub-import.json"), map[string]any{"t": time.Now(), "bytes": len(b)})
}

func (e *Engine) maybeFetch(c core.Config) {
	e.mu.Lock()
	st := e.state.Sub
	e.mu.Unlock()
	// Pick up an import done by `lanproxy import-sub`.
	if b, err := os.ReadFile(filepath.Join(e.Paths.CoreDir(), "sub-import.json")); err == nil {
		var imp struct {
			T     time.Time `json:"t"`
			Bytes int       `json:"bytes"`
		}
		if json.Unmarshal(b, &imp) == nil && imp.T.After(st.Fetched) {
			e.mu.Lock()
			e.state.Sub.Fetched, e.state.Sub.Via, e.state.Sub.Bytes, e.state.Sub.Error = imp.T, "导入", imp.Bytes, ""
			e.mu.Unlock()
			go e.reloadProvider()
			e.mu.Lock()
			st = e.state.Sub
			e.mu.Unlock()
		}
	}
	if c.SubURL == "" {
		return
	}
	forced := false
	if _, err := os.Stat(refreshPaths(e.Paths.Dir).flag()); err == nil {
		os.Remove(refreshPaths(e.Paths.Dir).flag())
		forced = true
	}
	interval := time.Duration(c.SubIntervalHours) * time.Hour
	due := st.Fetched.IsZero() && !e.haveNodes() || time.Since(st.Fetched) > interval
	if fi, err := os.Stat(e.subFile()); err == nil && st.Fetched.IsZero() && time.Since(fi.ModTime()) < interval {
		due = false // file from a previous run is still fresh
		e.mu.Lock()
		e.state.Sub.Fetched = fi.ModTime()
		e.mu.Unlock()
	}
	retry := !st.Attempt.IsZero() && time.Since(st.Attempt) < 5*time.Minute && st.Error != ""
	if !forced && (!due || retry) {
		return
	}
	e.mu.Lock()
	e.state.Sub.Attempt = time.Now()
	e.mu.Unlock()
	go e.fetch(c.SubURL)
}

func (e *Engine) fetch(subURL string) {
	body, hdr, via, err := e.download(subURL)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.state.Sub.Error = Scrub(err.Error(), subURL)
		return
	}
	if err := ValidateSub(body); err != nil {
		e.state.Sub.Error = err.Error()
		return
	}
	f := e.subFile()
	if err := os.WriteFile(f+".tmp", body, 0o600); err != nil {
		e.state.Sub.Error = err.Error()
		return
	}
	os.Rename(f+".tmp", f)
	s := &e.state.Sub
	s.Fetched, s.Via, s.Bytes, s.Error = time.Now(), via, len(body), ""
	for _, kv := range strings.Split(hdr.Get("Subscription-Userinfo"), ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch k {
		case "upload":
			s.Upload = n
		case "download":
			s.Download = n
		case "total":
			s.Total = n
		case "expire":
			s.Expire = n
		}
	}
	go e.reloadProvider()
}

// download tries a direct request first, then through mihomo's own listener.
func (e *Engine) download(subURL string) ([]byte, http.Header, string, error) {
	b, h, err1 := get(subURL, nil)
	if err1 == nil {
		return b, h, "直连", nil
	}
	ep, err := readEndpoint(e.Paths.CoreEndpoint())
	if err != nil || !e.haveNodes() {
		return nil, nil, "", fmt.Errorf("直连失败（%v），且没有可用节点", err1)
	}
	pu := &url.URL{Scheme: "socks5", User: url.UserPassword(ep.User, ep.Pass), Host: ep.Addr}
	b, h, err2 := get(subURL, pu)
	if err2 == nil {
		return b, h, "经节点", nil
	}
	return nil, nil, "", fmt.Errorf("直连失败（%v）；经节点失败（%v）", err1, err2)
}

func readEndpoint(p string) (core.CoreEndpoint, error) {
	var ep core.CoreEndpoint
	b, err := os.ReadFile(p)
	if err != nil {
		return ep, errors.New("内核未就绪")
	}
	return ep, json.Unmarshal(b, &ep)
}

func get(u string, proxy *url.URL) ([]byte, http.Header, error) {
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	cl := &http.Client{Transport: tr, Timeout: 45 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("User-Agent", "clash.meta/mihomo")
	resp, err := cl.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL from the message
		}
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return b, resp.Header, err
}

// reloadProvider asks mihomo to re-read the provider file, or restarts it when
// the config does not have a provider yet (first node list).
func (e *Engine) reloadProvider() {
	cl := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", e.Paths.ControllerSock())
	}}}
	req, _ := http.NewRequest("PUT", "http://mihomo/providers/proxies/"+Provider, nil)
	resp, err := cl.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	// reconcile() notices haveNodes() changed and restarts mihomo if needed.
}
