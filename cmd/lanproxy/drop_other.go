//go:build !linux

package main

import "os"

func prepareAndDrop(dir string, uid int) error { return os.MkdirAll(dir, 0o700) }
