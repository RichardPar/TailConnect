//go:build android

// Command tcd-android is the TailConnect client daemon inside the Android
// app. The app runs it as a child process (it is packaged as libtcd.so so
// Android lets the app execute it) and provides what an Android app process
// can't do for itself, over a bridge socket (see internal/androidbridge):
// the VPN interface, and the underlying network's DNS servers and
// addresses. The app's UI controls it through the usual local API socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"tailconnect/internal/androidbridge"
	"tailconnect/internal/daemon"
	"tailconnect/internal/dns"
	"tailconnect/internal/engine"
	"tailconnect/internal/ipam"
	"tailconnect/internal/localapi"
	"tailconnect/internal/protocol"
)

var version = "dev"

func main() {
	stateDir := flag.String("state", "", "state directory (keys and registration)")
	socket := flag.String("socket", "", "local API socket")
	bridgePath := flag.String("bridge", "", "socket the app connects to, to provide the VPN interface")
	dnsServers := flag.String("dns", "", "comma-separated DNS servers of the underlying network (the app updates them)")
	addrs := flag.String("addrs", "", "comma-separated local addresses with prefix length (the app updates them)")
	port := flag.Uint("port", engine.DefaultPort, "WireGuard UDP port (0 = random)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *stateDir == "" || *socket == "" || *bridgePath == "" {
		fmt.Fprintln(os.Stderr, "tcd-android: -state, -socket and -bridge are required")
		os.Exit(2)
	}
	daemon.Version = version
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logf := func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) }

	bridge, err := androidbridge.Listen(*bridgePath, logf)
	if err != nil {
		log.Error("bridge", "err", err)
		os.Exit(1)
	}
	defer bridge.Close()
	bridge.SetNetwork(androidbridge.Network{DNS: parseAddrs(*dnsServers), Addresses: parsePrefixes(*addrs)})

	// An app process has no /etc/resolv.conf: resolve names (the control
	// server's) with the DNS servers the app reports.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		servers := bridge.Network().DNS
		if len(servers) == 0 {
			return nil, fmt.Errorf("no DNS servers known for the current network")
		}
		var last error
		for _, s := range servers {
			c, err := d.DialContext(ctx, network, netip.AddrPortFrom(s, 53).String())
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}}

	d, err := daemon.New(daemon.Options{
		StateDir:   *stateDir,
		TUNName:    "vpn",
		ListenPort: uint16(*port),
		Logf:       logf,
		// Android doesn't let apps list interfaces; the app reports them.
		Endpoints: func(port uint16) ([]netip.AddrPort, []netip.Prefix) {
			var eps []netip.AddrPort
			pfx := bridge.Network().Addresses
			for _, p := range pfx {
				if a := p.Addr(); a.IsGlobalUnicast() && !ipam.DefaultV4.Contains(a) && !ipam.DefaultV6.Contains(a) {
					eps = append(eps, netip.AddrPortFrom(a, port))
				}
			}
			return eps, pfx
		},
		NewEngine: func(ep daemon.EngineParams) (*engine.Engine, error) {
			return newEngine(bridge, ep, logf)
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
	log.Info("tcd-android started", "version", version, "state", *stateDir)
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

// newEngine asks the app for a VPN interface routing the tunnel's address
// ranges (so new peers need no change), with MagicDNS as its DNS server.
func newEngine(b *androidbridge.Bridge, ep daemon.EngineParams, logf func(string, ...any)) (*engine.Engine, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fd, err := b.RequestTUN(ctx, androidbridge.Message{
		Addresses: ep.Addrs,
		Routes:    []netip.Prefix{ipam.DefaultV4, ipam.DefaultV6},
		DNS:       []netip.Addr{protocol.MagicDNSAddr},
		Search:    searchDomains(ep.Name),
		MTU:       engine.DefaultMTU,
	})
	if err != nil {
		return nil, err
	}
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		syscall.Close(fd)
		b.NotifyClosed()
		return nil, fmt.Errorf("VPN interface: %w", err)
	}
	cfg := engine.Config{
		TUN:        &closeNotifier{Device: dev, b: b},
		ListenPort: ep.Port, DiscoKey: ep.DiscoKey, OnEndpointsChanged: ep.OnEndpointsChanged, Logf: logf,
		DNS: androidDNS{b},
	}
	e, err := engine.New(cfg, ep.NodeKey)
	if err != nil {
		cfg.TUN.Close()
	}
	return e, err
}

// searchDomains turns "tablet.alice.home.internal" into the account's
// domain and the base domain, so short names resolve.
func searchDomains(name string) []string {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(parts) < 3 {
		return nil
	}
	return []string{strings.Join(parts[1:], "."), strings.Join(parts[2:], ".")}
}

// closeNotifier tells the app when WireGuard closes the interface (tc down,
// logout), so it closes its own handle and Android removes the VPN.
type closeNotifier struct {
	tun.Device
	b    *androidbridge.Bridge
	once sync.Once
}

func (c *closeNotifier) Close() error {
	err := c.Device.Close()
	c.once.Do(c.b.NotifyClosed)
	return err
}

// androidDNS: the VPN interface's DNS server is MagicDNS (set when it is
// created), and Android sends it every query, so MagicDNS forwards other
// names to the underlying network's DNS servers.
type androidDNS struct{ b *androidbridge.Bridge }

func (androidDNS) Set(dns.OSConfig) error        { return nil }
func (androidDNS) SupportsSplitDNS() bool        { return false }
func (a androidDNS) HostResolvers() []netip.Addr { return a.b.Network().DNS }
func (androidDNS) Mode() string                  { return "android" }
func (androidDNS) Close() error                  { return nil }

func parseAddrs(s string) []netip.Addr {
	var out []netip.Addr
	for _, f := range strings.Split(s, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(f)); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func parsePrefixes(s string) []netip.Prefix {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(f)); err == nil {
			out = append(out, p)
		}
	}
	return out
}
