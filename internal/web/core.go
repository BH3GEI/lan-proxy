package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"lanproxy/internal/core"
	"lanproxy/internal/engine"
)

// ctl calls mihomo's REST API over its unix socket (shared data directory).
func (a *Admin) ctl(method, path string, body any, out any) error {
	sock := a.Paths.ControllerSock()
	cl := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, "http://mihomo"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("分流内核不可用")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("分流内核返回 %d：%s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

type mProxy struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now"`
	All     []string `json:"all"`
	Alive   bool     `json:"alive"`
	History []struct {
		Time  time.Time `json:"time"`
		Delay int       `json:"delay"`
	} `json:"history"`
}

func lastDelay(p mProxy) int {
	if len(p.History) == 0 {
		return -1
	}
	return p.History[len(p.History)-1].Delay
}

type nodeView struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Delay int    `json:"delay"` // ms; 0 = timeout/failed; -1 = not tested
	Alive bool   `json:"alive"`
}

type groupView struct {
	Name  string     `json:"name"`
	Type  string     `json:"type"`
	Now   string     `json:"now"`
	Nodes []nodeView `json:"nodes"`
}

func (a *Admin) coreState(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	var st engine.State
	if b, err := os.ReadFile(a.Paths.CoreState()); err == nil && json.Unmarshal(b, &st) == nil {
		out["state"] = st
		out["stale"] = time.Since(st.Updated) > 15*time.Second
	} else {
		out["stale"] = true
	}
	var px struct {
		Proxies map[string]mProxy `json:"proxies"`
	}
	if err := a.ctl("GET", "/proxies", nil, &px); err != nil {
		out["ctl_error"] = err.Error()
		writeJSON(w, 200, out)
		return
	}
	// Nodes from a provider are listed under /providers/proxies, not /proxies.
	var provNodes struct {
		Providers map[string]struct {
			Proxies []mProxy `json:"proxies"`
		} `json:"providers"`
	}
	if a.ctl("GET", "/providers/proxies", nil, &provNodes) == nil {
		for _, pv := range provNodes.Providers {
			for _, p := range pv.Proxies {
				if _, ok := px.Proxies[p.Name]; !ok {
					px.Proxies[p.Name] = p
				}
			}
		}
	}
	var groups []groupView
	for _, gname := range []string{engine.GroupSelect, engine.GroupAuto} {
		g, ok := px.Proxies[gname]
		if !ok {
			continue
		}
		gv := groupView{Name: g.Name, Type: g.Type, Now: g.Now}
		for _, n := range g.All {
			p := px.Proxies[n]
			gv.Nodes = append(gv.Nodes, nodeView{Name: n, Type: p.Type, Delay: lastDelay(p), Alive: p.Alive})
		}
		groups = append(groups, gv)
	}
	out["groups"] = groups
	var prov struct {
		Providers map[string]struct {
			UpdatedAt        time.Time `json:"updatedAt"`
			VehicleType      string    `json:"vehicleType"`
			Proxies          []any     `json:"proxies"`
			SubscriptionInfo *struct {
				Upload, Download, Total, Expire int64
			} `json:"subscriptionInfo"`
		} `json:"providers"`
	}
	if a.ctl("GET", "/providers/proxies", nil, &prov) == nil {
		if p, ok := prov.Providers[engine.Provider]; ok {
			out["subscription"] = map[string]any{"updated": p.UpdatedAt, "nodes": len(p.Proxies), "info": p.SubscriptionInfo}
		}
	}
	var rp struct {
		Providers map[string]struct {
			UpdatedAt time.Time `json:"updatedAt"`
			RuleCount int       `json:"ruleCount"`
			Behavior  string    `json:"behavior"`
		} `json:"providers"`
	}
	if a.ctl("GET", "/providers/rules", nil, &rp) == nil {
		out["rules"] = rp.Providers
	}
	var conns struct {
		Connections []any `json:"connections"`
	}
	if a.ctl("GET", "/connections", nil, &conns) == nil {
		out["core_active"] = len(conns.Connections)
	}
	writeJSON(w, 200, out)
}

func (a *Admin) coreSelect(w http.ResponseWriter, r *http.Request) {
	var in struct{ Group, Name string }
	if err := decode(r, &in); err != nil || in.Group != engine.GroupSelect || in.Name == "" {
		fail(w, 400, "只能切换「"+engine.GroupSelect+"」组")
		return
	}
	if err := a.ctl("PUT", "/proxies/"+url.PathEscape(in.Group), map[string]string{"name": in.Name}, nil); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *Admin) coreTest(w http.ResponseWriter, r *http.Request) {
	c, _ := core.LoadConfig(a.Paths.Config())
	var res map[string]int
	q := "/group/" + url.PathEscape(engine.GroupAuto) + "/delay?timeout=5000&url=" + url.QueryEscape(c.TestURL)
	if err := a.ctl("GET", q, nil, &res); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "tested": len(res)})
}

func (a *Admin) coreUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct{ What string }
	decode(r, &in)
	var err error
	switch in.What {
	case "sub":
		err = engine.RequestRefresh(a.Paths.Dir)
	case "rules":
		for _, n := range []string{"cn_site", "cn_ip"} {
			if e := a.ctl("PUT", "/providers/rules/"+n, nil, nil); e != nil {
				err = e
			}
		}
	default:
		err = fmt.Errorf("未知的更新项")
	}
	if err != nil {
		c, _ := core.LoadConfig(a.Paths.Config())
		fail(w, 400, engine.Scrub(err.Error(), c.SubURL))
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// routesBySrc maps the core-side source addresses in want to their latest
// routing decision, reading the route log newest first and stopping once all
// are found.
func (a *Admin) routesBySrc(want map[string]bool) map[string]engine.Route {
	m := map[string]engine.Route{}
	if len(want) == 0 {
		return m
	}
	for _, p := range core.LogFilesNewestFirst(a.Paths.RouteLog(), engine.RouteFiles) {
		core.ScanLinesReverse(p, func(line []byte) bool {
			var r engine.Route
			if json.Unmarshal(line, &r) == nil && want[r.Src] {
				if _, seen := m[r.Src]; !seen {
					m[r.Src] = r
				}
			}
			return len(m) < len(want)
		})
		if len(m) >= len(want) {
			break
		}
	}
	return m
}

type logView struct {
	core.ConnRecord
	Rule     string `json:"rule,omitempty"`
	Outbound string `json:"outbound,omitempty"`
}

func (a *Admin) enrich(recs []core.ConnRecord) []logView {
	want := map[string]bool{}
	for _, r := range recs {
		if r.Via != "direct" && r.CoreSrc != "" {
			want[r.CoreSrc] = true
		}
	}
	routes := a.routesBySrc(want)
	out := make([]logView, 0, len(recs))
	for _, r := range recs {
		v := logView{ConnRecord: r}
		if r.Via == "direct" {
			v.Outbound = "直连"
		} else if rt, ok := routes[r.CoreSrc]; ok && r.CoreSrc != "" {
			v.Rule, v.Outbound = rt.Rule, rt.Outbound
		}
		out = append(out, v)
	}
	return out
}
