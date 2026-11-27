package core

import (
	"bytes"
	"io"
	"os"
)

// ScanLinesReverse calls fn for each non-empty line of path, last line first,
// until fn returns false. It reads the file backwards in fixed-size blocks, so
// memory stays bounded however large the file is (lines longer than 1 MB are
// skipped).
func ScanLinesReverse(path string, fn func(line []byte) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	const block = 64 << 10
	const maxLine = 1 << 20
	pos := st.Size()
	var carry []byte // start of the partial line that continues after this block
	buf := make([]byte, block)
	for pos > 0 {
		n := int64(block)
		if pos < n {
			n = pos
		}
		pos -= n
		if _, err := f.ReadAt(buf[:n], pos); err != nil && err != io.EOF {
			return err
		}
		chunk := append(append([]byte(nil), buf[:n]...), carry...)
		for {
			i := bytes.LastIndexByte(chunk, '\n')
			if i < 0 {
				break
			}
			if line := chunk[i+1:]; len(line) > 0 && !fn(line) {
				return nil
			}
			chunk = chunk[:i]
		}
		carry = chunk
		if len(carry) > maxLine {
			carry = nil // drop an over-long line rather than grow without bound
			// skip to the next newline in earlier blocks
			for pos > 0 {
				m := int64(block)
				if pos < m {
					m = pos
				}
				pos -= m
				if _, err := f.ReadAt(buf[:m], pos); err != nil && err != io.EOF {
					return err
				}
				if i := bytes.LastIndexByte(buf[:m], '\n'); i >= 0 {
					carry = nil
					pos += int64(i) + 1
					break
				}
			}
		}
	}
	if len(carry) > 0 {
		fn(carry)
	}
	return nil
}
