package core

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Connection-log limits: each file at most LogFileBytes, at most LogFiles
// files (current + rotated), so the log never exceeds about 50 MB on disk.
const (
	LogFileBytes = 10 << 20
	LogFiles     = 5
	// Connections that repeat (same source IP, account, target, egress, result)
	// within the merge window are written once more at its end, with a count.
	DefaultMergeWindow = 60 * time.Second
	mergeMax           = 4096
)

// LogFilesNewestFirst lists base, base.1 … base.(keep-1) that exist.
func LogFilesNewestFirst(base string, keep int) []string {
	var out []string
	for i := 0; i < keep; i++ {
		p := base
		if i > 0 {
			p = fmt.Sprintf("%s.%d", base, i)
		}
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// AppendRotating appends line to base, first rotating when the file would
// exceed maxBytes. The oldest file beyond keep is deleted.
func AppendRotating(base string, line []byte, maxBytes int64, keep int) error {
	if st, err := os.Stat(base); err == nil && st.Size()+int64(len(line)) > maxBytes {
		os.Remove(fmt.Sprintf("%s.%d", base, keep-1))
		for i := keep - 2; i >= 1; i-- {
			os.Rename(fmt.Sprintf("%s.%d", base, i), fmt.Sprintf("%s.%d", base, i+1))
		}
		os.Rename(base, base+".1")
	}
	f, err := os.OpenFile(base, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// DirBytes sums the sizes of regular files under dir.
func DirBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, e := d.Info(); e == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// ---- merging repeated connections -----------------------------------------

type mergeEntry struct {
	start time.Time
	rec   ConnRecord // accumulates repeats after the first, which was written immediately
}

func mergeKey(r ConnRecord) string {
	src := r.Src
	if ap, err := netip.ParseAddrPort(r.Src); err == nil {
		src = ap.Addr().String()
	}
	return strings.Join([]string{src, r.User, r.Proto, r.Target, r.Result, r.Reason, r.Via}, "\x00")
}

// ---- source MAC from the ARP table ----------------------------------------

type arpCache struct {
	mu sync.Mutex
	at time.Time
	m  map[string]string
}

func (a *arpCache) lookupWith(read func() (map[string]string, error), ip netip.Addr) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil || time.Since(a.at) > 10*time.Second {
		if m, err := read(); err == nil {
			a.m = m
		} else if a.m == nil {
			a.m = map[string]string{}
		}
		a.at = time.Now()
	}
	return a.m[ip.Unmap().String()]
}

func readProcARP() (map[string]string, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseARP(bufio.NewScanner(f)), nil
}

// ParseARP reads /proc/net/arp: "IP address  HW type  Flags  HW address  Mask  Device".
func ParseARP(sc *bufio.Scanner) map[string]string {
	m := map[string]string{}
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] == "0x0" || f[3] == "00:00:00:00:00:00" {
			continue
		}
		m[f[0]] = f[3]
	}
	return m
}
