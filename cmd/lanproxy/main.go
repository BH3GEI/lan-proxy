// lanproxy: a LAN-only HTTP/SOCKS5 forward proxy for a LazyCat NAS.
//
//	lanproxy proxy -dir /lzcapp/var/data   (host network, non-root)
//	lanproxy core  -dir /lzcapp/var/data -mihomo ... -assets ...   (container network, non-root)
//	lanproxy admin -dir /lzcapp/var/data -addr :8080 -uid 1000
//	lanproxy set-sub -dir /lzcapp/var/data < url.txt
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lanproxy/internal/core"
	"lanproxy/internal/engine"
	"lanproxy/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lanproxy proxy|admin|version [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "/lzcapp/var/data", "shared data directory")
	addr := fs.String("addr", ":8080", "admin listen address")
	uid := fs.Int("uid", 1000, "admin: uid/gid to switch to after preparing the data directory")
	dev := fs.Bool("dev", false, "admin: do not require the LazyCat admin header")
	mihomo := fs.String("mihomo", "/lzcapp/pkg/content/mihomo", "core: mihomo binary")
	assets := fs.String("assets", "/lzcapp/pkg/content/rules", "core: bundled rule sets")
	fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "version":
		fmt.Println(core.Version)
	case "proxy":
		if os.Geteuid() == 0 {
			log.Fatal("refusing to run the proxy as root")
		}
		for {
			if st, err := os.Stat(*dir); err == nil && st.IsDir() {
				break
			}
			log.Printf("waiting for %s", *dir)
			time.Sleep(2 * time.Second)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		log.Printf("lanproxy %s proxy, data %s", core.Version, *dir)
		core.NewServerDefault(*dir).Run(ctx)
	case "core":
		if os.Geteuid() == 0 {
			log.Fatal("refusing to run the core as root")
		}
		for {
			if _, err := os.Stat(*dir + "/config.json"); err == nil {
				break
			}
			log.Printf("waiting for %s/config.json", *dir)
			time.Sleep(2 * time.Second)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		log.Printf("lanproxy %s core, mihomo %s", core.Version, *mihomo)
		engine.New(*dir, *mihomo, *assets).Run(ctx)
	case "set-sub":
		// Reads the subscription URL from stdin so it never appears in a process list.
		if err := prepareAndDrop(*dir, *uid); err != nil {
			log.Fatal(err)
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			log.Fatal(err)
		}
		u := strings.TrimSpace(string(b))
		a := &web.Admin{Paths: core.Paths{Dir: *dir}}
		if err := a.Mutate(func(c *core.Config) error { c.SubURL = u; return nil }); err != nil {
			log.Fatal(err)
		}
		fmt.Println("subscription set:", core.MaskURL(u))
	case "import-sub":
		// Stores a node list read from stdin (bootstrap when the subscription host is unreachable directly).
		if err := prepareAndDrop(*dir, *uid); err != nil {
			log.Fatal(err)
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20))
		if err != nil {
			log.Fatal(err)
		}
		if err := engine.ImportSub(*dir, b); err != nil {
			log.Fatal(err)
		}
		fmt.Println("node list imported,", len(b), "bytes")
	case "admin":
		if err := prepareAndDrop(*dir, *uid); err != nil {
			log.Fatal(err)
		}
		a := &web.Admin{Paths: core.Paths{Dir: *dir}, RequireRole: !*dev}
		if err := a.EnsureConfig(); err != nil {
			log.Fatal(err)
		}
		log.Printf("lanproxy %s admin on %s, uid %d", core.Version, *addr, os.Geteuid())
		log.Fatal(web.ListenAndServe(*addr, a))
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
