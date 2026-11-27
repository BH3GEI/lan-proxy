//go:build !linux

package engine

import "syscall"

func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
