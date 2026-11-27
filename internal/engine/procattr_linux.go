package engine

import "syscall"

// childAttr puts mihomo in its own process group and has the kernel kill it
// if the core process dies (for example killed for memory), so a restarted
// core never runs alongside an orphaned mihomo.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
