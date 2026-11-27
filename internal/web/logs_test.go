package web

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"lanproxy/internal/core"
	"lanproxy/internal/engine"
)

// A full 10 MB connection log must not be loaded into memory to show the
// newest few hundred records (the admin container has 128 MB; loading whole
// files on every 3 s poll got it killed for memory).
func TestReadLogBoundedMemory(t *testing.T) {
	dir := t.TempDir()
	a := &Admin{Paths: core.Paths{Dir: dir}}
	t0 := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	f, _ := os.Create(a.Paths.ConnLog())
	rf, _ := os.Create(a.Paths.RouteLog())
	size, i := 0, 0
	for size < 10<<20 {
		r := core.ConnRecord{Time: t0.Add(time.Duration(i) * time.Second), ID: uint64(i), Src: "192.168.3.90:5000", Proto: "connect",
			Target: fmt.Sprintf("host%d.example.com:443", i%500), Result: "ok", Via: "core", CoreSrc: fmt.Sprintf("172.28.4.65:%d", 10000+i%50000)}
		b, _ := json.Marshal(r)
		f.Write(append(b, '\n'))
		rb, _ := json.Marshal(engine.Route{Src: r.CoreSrc, Rule: "MATCH", Outbound: fmt.Sprintf("node-%d", i)})
		rf.Write(append(rb, '\n'))
		size += len(b) + 1
		i++
	}
	f.Close()
	rf.Close()
	last := i - 1

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	out := a.enrich(a.readLog(300, LogFilter{}))
	runtime.ReadMemStats(&m1)
	if len(out) != 300 || out[0].ID != uint64(last) || out[299].ID != uint64(last-299) {
		t.Fatalf("got %d records, first %d last %d; want 300 from %d down", len(out), out[0].ID, out[len(out)-1].ID, last)
	}
	if want := fmt.Sprintf("node-%d", last); out[0].Outbound != want {
		t.Fatalf("route of newest record: %q, want %q", out[0].Outbound, want)
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 8<<20 {
		t.Fatalf("reading 300 records allocated %d MB", alloc>>20)
	}
	// A filter that matches nothing scans everything but keeps nothing.
	runtime.ReadMemStats(&m0)
	if n := len(a.readLog(300, LogFilter{Target: "nomatch.invalid"})); n != 0 {
		t.Fatalf("filtered: %d", n)
	}
	runtime.ReadMemStats(&m1)
	if m1.HeapInuse > m0.HeapInuse+32<<20 {
		t.Fatalf("heap grew by %d MB", (m1.HeapInuse-m0.HeapInuse)>>20)
	}
}
