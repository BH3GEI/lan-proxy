package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// prepareAndDrop creates the data directory owned by uid and, when started as
// root, permanently switches to that uid/gid before serving anything.
func prepareAndDrop(dir string, uid int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return nil
	}
	if err := os.Chown(dir, uid, uid); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	// The proxy (uid 1000, separate container) must be able to traverse the parent.
	parent := filepath.Dir(dir)
	if st, err := os.Stat(parent); err == nil && st.Mode().Perm()&0o001 == 0 {
		if err := os.Chmod(parent, st.Mode().Perm()|0o001); err != nil {
			return err
		}
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(uid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return fmt.Errorf("failed to drop root")
	}
	return nil
}
