// Command tc-relay is a standalone TailConnect relay server, for running
// relays in other locations than tc-control (which has one built in).
//
// Advertise it to clients by passing tc-control a relay map:
//
//	tc-control serve -relay-map relays.json
//
// where relays.json lists this server's URL (tc-relay prints an example).
//
// The relay asks tc-control which machines it may serve, with a token from
// `tc-control relays create NAME`:
//
//	TC_RELAY_TOKEN=tc-relay-... tc-relay -control-url https://ctl.example.com
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tailconnect/internal/autotls"
	"tailconnect/internal/key"
	"tailconnect/internal/metrics"
	"tailconnect/internal/protocol"
	"tailconnect/internal/relay"
	"tailconnect/internal/stun"
)

var version = "dev"

func main() {
	listen := flag.String("listen", ":7742", "listen address")
	keyFile := flag.String("key-file", "relay.key", "relay private key (created if missing)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	acmeDomain := flag.String("acme-domain", "", "get HTTPS certificates from Let's Encrypt for this DNS name (it must point at this server; port 443, or -acme-http-listen, reachable from the internet)")
	acmeEmail := flag.String("acme-email", "", "email address for Let's Encrypt's expiry notices (optional)")
	acmeHTTP := flag.String("acme-http-listen", "", `also serve Let's Encrypt's checks on this address, e.g. ":80" (needed unless -listen is on port 443)`)
	acmeDir := flag.String("acme-dir", "acme", "where certificates are kept")
	acmeStaging := flag.Bool("acme-staging", false, "use Let's Encrypt's test service (untrusted certificates)")
	publicURL := flag.String("public-url", "", "URL clients use, for the example relay map (e.g. https://relay.example.com/relay)")
	stunListen := flag.String("stun-listen", ":3478", `UDP address for the STUN server ("" disables)`)
	controlURL := flag.String("control-url", "", "tc-control URL to check machines with (e.g. https://ctl.example.com)")
	tokenFile := flag.String("token-file", "", "file with the relay token from `tc-control relays create` (or set TC_RELAY_TOKEN)")
	allowAny := flag.Bool("allow-any", false, "serve any machine that proves its key, without asking tc-control (an open relay)")
	metricsListen := flag.String("metrics-listen", "", `serve metrics (Prometheus text format) at /metrics on this address, e.g. "127.0.0.1:7743" ("" = off)`)
	logJSON := flag.Bool("log-json", false, "log in JSON format")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logJSON {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(h)

	token := os.Getenv("TC_RELAY_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tc-relay:", err)
			os.Exit(2)
		}
		token = strings.TrimSpace(string(b))
	}
	switch {
	case *allowAny && *controlURL != "":
		fmt.Fprintln(os.Stderr, "tc-relay: -allow-any and -control-url exclude each other")
		os.Exit(2)
	case !*allowAny && *controlURL == "":
		fmt.Fprintln(os.Stderr, "tc-relay: give -control-url (and a token) so the relay serves only your network's machines.\n"+
			"Create the token on the control server with: tc-control relays create NAME\n"+
			"(-allow-any runs an open relay for any machine instead: packets stay end-to-end encrypted, but anyone\n"+
			"who can reach the relay can use its bandwidth.)")
		os.Exit(2)
	case *controlURL != "" && token == "":
		fmt.Fprintln(os.Stderr, "tc-relay: no relay token: set TC_RELAY_TOKEN or -token-file (from `tc-control relays create NAME`)")
		os.Exit(2)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(os.Stderr, "tc-relay: -tls-cert and -tls-key must be given together")
		os.Exit(2)
	}
	var certs *autotls.Manager
	if *acmeDomain != "" {
		domains, err := autotls.ParseDomains(*acmeDomain)
		if err == nil && *tlsCert != "" {
			err = errors.New("-acme-domain and -tls-cert exclude each other")
		}
		if err == nil {
			cfg := autotls.Config{Domains: domains, Email: *acmeEmail, HTTPListen: *acmeHTTP, TLSListen: *listen, CacheDir: *acmeDir}
			if *acmeStaging {
				cfg.DirectoryURL = autotls.StagingURL
			}
			certs, err = autotls.New(cfg)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "tc-relay: -acme-domain:", err)
			os.Exit(2)
		}
		if *publicURL == "" {
			*publicURL = "https://" + domains[0]
			if _, port, _ := net.SplitHostPort(*listen); port != "443" {
				*publicURL += ":" + port
			}
			*publicURL += "/relay"
		}
	}
	priv, err := loadOrCreateKey(*keyFile)
	if err != nil {
		log.Error("relay key", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var srv *relay.Server
	var pol *relay.RemotePolicy
	if *allowAny {
		srv = relay.NewServer(priv, nil, log)
		log.Warn("open relay: serving any machine that proves its key (-allow-any)")
	} else {
		pol = relay.NewRemotePolicy(*controlURL, token, log)
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := pol.Check(cctx)
		cancel()
		if err != nil {
			log.Error("cannot use the control server", "url", *controlURL, "err", err)
			os.Exit(1)
		}
		srv = relay.NewServer(priv, pol.Authorize, log)
		srv.SetAllow(pol.Allow)
		go pol.Run(ctx)
		log.Info("serving machines of the control server's network", "control", *controlURL)
	}

	if *metricsListen != "" {
		reg := metrics.NewRegistry()
		srv.RegisterMetrics(reg)
		if pol != nil {
			pol.RegisterMetrics(reg)
		}
		reg.Collect("tc_build_info", "The running program and version (always 1).", "gauge", func(emit func([]string, float64)) {
			emit([]string{"program", "tc-relay", "version", version}, 1)
		})
		mmux := http.NewServeMux()
		mmux.Handle("GET /metrics", reg)
		go func() {
			ms := &http.Server{Addr: *metricsListen, Handler: mmux, ReadHeaderTimeout: 10 * time.Second}
			if err := ms.ListenAndServe(); err != nil {
				log.Error("metrics listener", "err", err)
				os.Exit(1)
			}
		}()
	}
	mux := http.NewServeMux()
	mux.Handle("/relay", srv)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		n, fwd, drop := srv.Stats()
		fmt.Fprintf(w, "TailConnect relay %s\nclients: %d\nforwarded: %d\ndropped: %d\n", version, n, fwd, drop)
	})
	hs := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if certs != nil {
		hs.TLSConfig = certs.TLSConfig()
		if *acmeHTTP != "" {
			go func() {
				if err := http.ListenAndServe(*acmeHTTP, certs.HTTPHandler()); err != nil {
					log.Error("certificate checks listener", "err", err)
					os.Exit(1)
				}
			}()
		}
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	if *publicURL == "" {
		scheme := "http"
		if *tlsCert != "" || certs != nil {
			scheme = "https"
		}
		*publicURL = scheme + "://" + ln.Addr().String() + "/relay"
	}
	stunPort := 0
	if *stunListen != "" {
		pc, err := net.ListenPacket("udp", *stunListen)
		if err != nil {
			log.Error("STUN listener", "err", err)
			os.Exit(1)
		}
		defer pc.Close()
		go stun.Serve(pc)
		stunPort = pc.LocalAddr().(*net.UDPAddr).Port
	}
	example, _ := json.MarshalIndent(protocol.RelayMap{Regions: []protocol.RelayRegion{
		{ID: 1, Code: "control", Name: "tc-control (embedded)", Nodes: []protocol.RelayNode{{Name: "1a", URL: "/relay", STUNPort: 3478}}},
		{ID: 2, Code: "edge", Name: "tc-relay", Nodes: []protocol.RelayNode{{Name: "2a", URL: *publicURL, STUNPort: stunPort}}},
	}}, "", "  ")
	log.Info("tc-relay started", "version", version, "addr", ln.Addr().String(), "key", priv.Public().ShortString())
	fmt.Fprintf(os.Stderr, "Example relay map for `tc-control serve -relay-map FILE`:\n%s\n", example)

	go func() {
		<-ctx.Done()
		srv.Close()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	if certs != nil {
		err = hs.ServeTLS(ln, "", "")
	} else if *tlsCert != "" {
		err = hs.ServeTLS(ln, *tlsCert, *tlsKey)
	} else {
		err = hs.Serve(ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func loadOrCreateKey(path string) (key.RelayPrivate, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return key.ParsePrivate[key.RelayKind](string(b))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return key.RelayPrivate{}, err
	}
	k := key.NewPrivate[key.RelayKind]()
	text, _ := k.MarshalText()
	if err := os.WriteFile(path, text, 0o600); err != nil {
		return key.RelayPrivate{}, err
	}
	return k, nil
}
