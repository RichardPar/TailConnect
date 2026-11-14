// Command tcd is the TailConnect client daemon. It must run as root (or with
// CAP_NET_ADMIN) to create the TUN interface and configure routes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"tailconnect/internal/daemon"
	"tailconnect/internal/engine"
	"tailconnect/internal/key"
	"tailconnect/internal/localapi"
)

var version = "dev"

func main() {
	stateDir := flag.String("state", "/var/lib/tailconnect", "state directory (keys and registration)")
	socket := flag.String("socket", localapi.DefaultSocket, "local API socket")
	tunName := flag.String("tun", "tc0", `TUN interface name, or "userspace" for unprivileged in-process networking`)
	port := flag.Uint("port", engine.DefaultPort, "WireGuard UDP port (0 = random)")
	verbose := flag.Bool("verbose", false, "verbose WireGuard logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *port > 65535 {
		fmt.Fprintln(os.Stderr, "-port out of range")
		os.Exit(2)
	}
	daemon.Version = version

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logf := func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) }

	d, err := daemon.New(daemon.Options{
		StateDir:   *stateDir,
		TUNName:    *tunName,
		ListenPort: uint16(*port),
		Logf:       logf,
		NewEngine: func(priv key.NodePrivate, addrs []netip.Prefix, port uint16) (*engine.Engine, error) {
			if *tunName == "userspace" {
				// Userspace networking: WireGuard terminates in an in-process
				// gVisor stack. No root or TUN device needed, and the OS routing
				// table is untouched. The node answers ping on its tunnel
				// addresses but the host's own services are not exposed.
				var ips []netip.Addr
				for _, p := range addrs {
					ips = append(ips, p.Addr())
				}
				tdev, _, err := netstack.CreateNetTUN(ips, nil, engine.DefaultMTU)
				if err != nil {
					return nil, err
				}
				return engine.New(engine.Config{TUN: tdev, ListenPort: port, Logf: logf, Verbose: *verbose}, priv)
			}
			tdev, err := tun.CreateTUN(*tunName, engine.DefaultMTU)
			if err != nil {
				return nil, fmt.Errorf("create TUN %s (are you root?): %w", *tunName, err)
			}
			name, err := tdev.Name()
			if err != nil {
				tdev.Close()
				return nil, err
			}
			r, err := engine.NewOSRouter(name, logf)
			if err != nil {
				tdev.Close()
				return nil, err
			}
			return engine.New(engine.Config{TUN: tdev, Router: r, ListenPort: port, Logf: logf, Verbose: *verbose}, priv)
		},
	})
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := localapi.Listen(*socket)
	if err != nil {
		log.Error("local API", "err", err)
		os.Exit(1)
	}
	defer os.Remove(*socket)

	log.Info("tcd started", "version", version, "state", *stateDir, "socket", *socket)
	d.Start()
	go func() {
		if err := localapi.NewServer(d, log).Serve(ctx, ln); err != nil {
			log.Error("local API server", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	log.Info("shutting down")
	d.Close()
}
