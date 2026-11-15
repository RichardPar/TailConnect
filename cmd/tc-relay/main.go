// Command tc-relay is a standalone TailConnect relay server, for running
// relays in other locations than tc-control (which has one built in).
//
// Advertise it to clients by passing tc-control a relay map:
//
//	tc-control serve -relay-map relays.json
//
// where relays.json lists this server's URL (tc-relay prints an example).
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
	"syscall"
	"time"

	"tailconnect/internal/key"
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
	publicURL := flag.String("public-url", "", "URL clients use, for the example relay map (e.g. https://relay.example.com/relay)")
	stunListen := flag.String("stun-listen", ":3478", `UDP address for the STUN server ("" disables)`)
	allowAny := flag.Bool("allow-any", false, "serve any node that proves ownership of its key (required: client verification against tc-control is not implemented yet)")
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

	if !*allowAny {
		fmt.Fprintln(os.Stderr, "tc-relay: refusing to start without -allow-any.\n"+
			"A standalone relay cannot yet check which nodes are registered with tc-control, so it would relay for any\n"+
			"node. Packets stay end-to-end encrypted, but the relay's bandwidth is open to anyone who can reach it.\n"+
			"The relay built into tc-control (on by default) only serves registered nodes.")
		os.Exit(2)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(os.Stderr, "tc-relay: -tls-cert and -tls-key must be given together")
		os.Exit(2)
	}
	priv, err := loadOrCreateKey(*keyFile)
	if err != nil {
		log.Error("relay key", "err", err)
		os.Exit(1)
	}
	srv := relay.NewServer(priv, nil, log)

	mux := http.NewServeMux()
	mux.Handle("/relay", srv)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		n, fwd, drop := srv.Stats()
		fmt.Fprintf(w, "TailConnect relay %s\nclients: %d\nforwarded: %d\ndropped: %d\n", version, n, fwd, drop)
	})
	hs := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	if *publicURL == "" {
		scheme := "http"
		if *tlsCert != "" {
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
	log.Warn("serving any node that proves its key (-allow-any)")
	log.Info("tc-relay started", "version", version, "addr", ln.Addr().String(), "key", priv.Public().ShortString())
	fmt.Fprintf(os.Stderr, "Example relay map for `tc-control serve -relay-map FILE`:\n%s\n", example)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		srv.Close()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	if *tlsCert != "" {
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
