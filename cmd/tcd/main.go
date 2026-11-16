// Command tcd is the TailConnect client daemon. It must run as root (or with
// CAP_NET_ADMIN) to create the TUN interface and configure routes. On
// Windows it runs as the TailConnect service (tcd install).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"tailconnect/internal/daemon"
	"tailconnect/internal/dns"
	"tailconnect/internal/engine"
	"tailconnect/internal/localapi"
	"tailconnect/internal/metrics"
	"tailconnect/internal/protocol"
)

var version = "dev"

func main() {
	if platformCommand(os.Args[1:]) {
		return
	}
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: tcd [FLAGS]\n")
		flag.PrintDefaults()
		fmt.Fprint(flag.CommandLine.Output(), platformUsage)
	}
	stateDir := flag.String("state", defaultStateDir(), "state directory (keys and registration)")
	socket := flag.String("socket", localapi.DefaultSocket, "local API socket")
	tunName := flag.String("tun", defaultTUN, `TUN interface name, or "userspace" for unprivileged in-process networking`)
	port := flag.Uint("port", engine.DefaultPort, "WireGuard UDP port (0 = random)")
	dnsMode := flag.String("dns", dns.ModeAuto, dnsModeHelp)
	resolvConf := flag.String("resolv-conf", "/etc/resolv.conf", "resolv.conf path (for -dns file)")
	metricsListen := flag.String("metrics-listen", "", `serve metrics (Prometheus text format) at /metrics on this address, e.g. "127.0.0.1:7744" ("" = off)`)
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

	if err := secureStateDir(*stateDir); err != nil {
		fmt.Fprintln(os.Stderr, "tcd: state directory:", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewTextHandler(logOutput(*stateDir), nil))
	logf := func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) }

	d, err := daemon.New(daemon.Options{
		StateDir:   *stateDir,
		TUNName:    *tunName,
		ListenPort: uint16(*port),
		Logf:       logf,
		NewEngine: func(ep daemon.EngineParams) (*engine.Engine, error) {
			cfg := engine.Config{ListenPort: ep.Port, DiscoKey: ep.DiscoKey, OnEndpointsChanged: ep.OnEndpointsChanged, Logf: logf, Verbose: *verbose}
			if *tunName == "userspace" {
				// Userspace networking: WireGuard terminates in an in-process
				// gVisor stack. No root or TUN device needed, and the OS routing
				// table is untouched. The node answers ping on its tunnel
				// addresses but the host's own services are not exposed.
				var ips []netip.Addr
				for _, p := range ep.Addrs {
					ips = append(ips, p.Addr())
				}
				tdev, _, err := netstack.CreateNetTUN(ips, nil, engine.DefaultMTU)
				if err != nil {
					return nil, err
				}
				cfg.TUN = tdev
				return engine.New(cfg, ep.NodeKey)
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
			osdns, err := dns.NewOSConfigurator(dns.OSOptions{
				Mode: *dnsMode, Interface: name, ResolvConf: *resolvConf,
				Backup: filepath.Join(*stateDir, "resolv.conf.backup"), Logf: logf,
			})
			if err != nil {
				// The tunnel works without host DNS; report and carry on.
				logf("%v; MagicDNS is only reachable at %s", err, protocol.MagicDNSAddr)
				osdns = dns.NoopConfigurator{}
			}
			cfg.TUN, cfg.Router, cfg.DNS = tdev, r, osdns
			e, err := engine.New(cfg, ep.NodeKey)
			if err != nil {
				osdns.Close()
			}
			return e, err
		},
	})
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}

	ctx, stop, finish := serviceContext()
	defer finish()

	ln, err := localapi.Listen(*socket)
	if err != nil {
		log.Error("local API", "err", err)
		os.Exit(1)
	}
	defer os.Remove(*socket)

	if *metricsListen != "" {
		reg := metrics.NewRegistry()
		d.RegisterMetrics(reg)
		reg.Collect("tc_build_info", "The running program and version (always 1).", "gauge", func(emit func([]string, float64)) {
			emit([]string{"program", "tcd", "version", version}, 1)
		})
		mmux := http.NewServeMux()
		mmux.Handle("GET /metrics", reg)
		ms := &http.Server{Addr: *metricsListen, Handler: mmux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := ms.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics listener", "err", err)
			}
		}()
		defer ms.Close()
	}

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
