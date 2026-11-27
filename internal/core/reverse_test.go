package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanLinesReverse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	var b strings.Builder
	want := []string{}
	for i := 0; i < 20000; i++ {
		l := fmt.Sprintf("line-%d-%s", i, strings.Repeat("x", i%97))
		b.WriteString(l + "\n")
		want = append(want, l)
	}
	b.WriteString("tail-no-newline")
	want = append(want, "tail-no-newline")
	os.WriteFile(p, []byte(b.String()), 0o600)
	var got []string
	if err := ScanLinesReverse(p, func(l []byte) bool { got = append(got, string(l)); return true }); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[len(want)-1-i] {
			t.Fatalf("line %d: %q != %q", i, got[i], want[len(want)-1-i])
		}
	}
	// stops early
	n := 0
	ScanLinesReverse(p, func([]byte) bool { n++; return n < 3 })
	if n != 3 {
		t.Fatalf("early stop: %d", n)
	}
	// empty and missing files
	os.WriteFile(p, nil, 0o600)
	if err := ScanLinesReverse(p, func([]byte) bool { t.Fatal("called"); return true }); err != nil {
		t.Fatal(err)
	}
	if ScanLinesReverse(filepath.Join(dir, "none"), func([]byte) bool { return true }) == nil {
		t.Fatal("missing file: want error")
	}
}
