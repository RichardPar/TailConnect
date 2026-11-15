// Command tc-control is the TailConnect coordination server and its admin CLI.
//
//	tc-control serve                     run the control server and web portal
//	tc-control admin-token               create/replace the admin token (API, break-glass sign-in)
//	tc-control users ...                 manage accounts (create, approve, suspend, passwords, roles)
//	tc-control invites ...               manage sign-up invite codes
//	tc-control keys create|list|revoke   manage pre-auth keys
//	tc-control nodes list|delete|rename  manage registered machines
//	tc-control shares ...                manage machines shared between accounts
//
// Admin subcommands operate on the SQLite database directly, so they work
// whether or not the server is running.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"golang.org/x/term"
	"time"

	"tailconnect/internal/acl"
	"tailconnect/internal/admin"
	"tailconnect/internal/autotls"
	"tailconnect/internal/control"
	"tailconnect/internal/db"
	"tailconnect/internal/metrics"
	"tailconnect/internal/password"
	"tailconnect/internal/protocol"
	"tailconnect/internal/relay"
	"tailconnect/internal/stun"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `tc-control: TailConnect coordination server

Usage:
  tc-control serve [flags]
  tc-control admin-token [-db PATH]
  tc-control users create NAME [-operator] [-password] | list | delete NAME
  tc-control users passwd NAME | approve NAME | suspend NAME | activate NAME
  tc-control users role NAME operator|tenant | machine-approval NAME on|off
  tc-control users domain NAME [DOMAIN|default]
  tc-control invites create [-expiration 168h] | list | revoke ID
  tc-control shares list [-user NAME] | create NODE_ID ACCOUNT | link NODE_ID [-expiration 168h]
  tc-control shares accept ID | revoke ID
  tc-control keys create -user NAME [-reusable] [-ephemeral] [-preapproved] [-expiration 24h]
  tc-control keys list [-user NAME] | revoke ID
  tc-control nodes list [-user NAME] | delete ID | rename ID NEWNAME
  tc-control nodes approve ID | expiry ID never|DURATION | tag ID TAG[,TAG...]
  tc-control nodes exit-node ID on|off
  tc-control rules list [-user NAME] | add -user NAME FROM TO [PORTS] | delete ID
  tc-control relays create NAME | list | delete NAME   (tokens for standalone tc-relay servers)
  tc-control version

Every subcommand accepts -db PATH (default: $TC_CONTROL_DB, else
/var/lib/tc-control/control.db if it exists, else ./control.db).
Run "tc-control <command> -h" for command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "admin-token":
		err = cmdAdminToken(args)
	case "invites":
		err = cmdInvites(args)
	case "shares":
		err = cmdShares(args)
	case "rules":
		err = cmdRules(args)
	case "relays":
		err = cmdRelays(args)
	case "users":
		err = cmdUsers(args)
	case "keys":
		err = cmdKeys(args)
	case "nodes":
		err = cmdNodes(args)
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(os.Stderr, "%s\n\n%s", err, usage)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type usageError string

func (e usageError) Error() string { return string(e) }

// installedDB is where the packaged systemd unit keeps the database.
const installedDB = "/var/lib/tc-control/control.db"

// defaultDBPath is $TC_CONTROL_DB, else the packaged location if it exists
// (so `sudo tc-control users list` works on an installed server), else
// ./control.db.
func defaultDBPath() string {
	if p := os.Getenv("TC_CONTROL_DB"); p != "" {
		return p
	}
	if _, err := os.Stat(installedDB); err == nil {
		return installedDB
	}
	return "control.db"
}

// parseArgs parses flags anywhere among the arguments, so both
// `users create -db X alice` and `users create alice -db X` work.
func parseArgs(fs *flag.FlagSet, args []string) {
	var pos []string
	for {
		fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	fs.Parse(append([]string{"--"}, pos...))
}

// flags creates a FlagSet with the shared -db flag.
func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath(), "path to the SQLite database")
	return fs, dbPath
}

func openDB(path string) (*db.DB, error) {
	d, err := db.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return d, nil
}

// ---- serve ----

func cmdServe(args []string) error {
	fs, dbPath := flags("serve")
	listen := fs.String("listen", ":7740", "client-facing control API address")
	adminListen := fs.String("admin-listen", ":7741", `web portal and API address: ":7741" for every network, "127.0.0.1:7741" for this machine only (reach it with an SSH tunnel), "" to turn it off`)
	domain := fs.String("domain", "tc.internal", "MagicDNS base domain")
	tenantSuffixes := fs.String("tenant-domain-suffixes", "internal", `comma-separated suffixes accounts may choose their own MagicDNS domain under in the portal ("internal" allows acme.internal); "" lets only operators set account domains`)
	keyExpiry := fs.String("key-expiry", "180d", `how long machines stay authorised before they must re-authenticate ("never", or e.g. 90d, 720h)`)
	ephemeralTimeout := fs.Duration("ephemeral-timeout", 30*time.Minute, "remove ephemeral machines offline this long (0 = keep them)")
	signup := fs.String("signup", admin.SignupApproval, "who may create accounts in the web portal: off, approval (operator approves), invite (needs an invite code) or open")
	magicDNS := fs.Bool("magic-dns", true, "clients resolve <node>.<domain> names in-tunnel and point the OS at them")
	nameservers := fs.String("dns-nameservers", "", "comma-separated upstream resolvers for all other names; clients then send all DNS through MagicDNS (default: clients keep their own resolvers)")
	publicURL := fs.String("public-url", "", "URL clients use to reach this server (shown in the web portal)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS on both listeners)")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	acmeDomain := fs.String("acme-domain", "", "get HTTPS certificates from Let's Encrypt for this DNS name (comma-separated for several); the name must point at this server, and port 443 (or -acme-http-listen) be reachable from the internet")
	acmeEmail := fs.String("acme-email", "", "contact address for the Let's Encrypt account (optional)")
	acmeHTTP := fs.String("acme-http-listen", "", `also serve Let's Encrypt's checks on this address, e.g. ":80" (needed unless -listen is on port 443; it redirects other requests to HTTPS)`)
	acmeStaging := fs.Bool("acme-staging", false, "use Let's Encrypt's test service (untrusted certificates, for trying a setup)")
	metricsListen := fs.String("metrics-listen", "", `serve metrics (Prometheus text format) at /metrics on this address, e.g. "127.0.0.1:7743" ("" = off)`)
	logJSON := fs.Bool("log-json", false, "log in JSON format")
	embedRelay := fs.Bool("relay", true, "serve the built-in relay at /relay on the control listener")
	relayMapFile := fs.String("relay-map", "", "JSON relay map to advertise instead of the built-in relay (see docs)")
	stunListen := fs.String("stun-listen", ":3478", `UDP address for the built-in STUN server ("" disables; clients use it to find their public address)`)
	fs.Parse(args)

	var h slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logJSON {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(h)

	if (*tlsCert == "") != (*tlsKey == "") {
		return usageError("-tls-cert and -tls-key must be given together")
	}
	var certs *autotls.Manager
	if *acmeDomain != "" {
		if *tlsCert != "" {
			return usageError("-acme-domain and -tls-cert exclude each other")
		}
		domains, err := autotls.ParseDomains(*acmeDomain)
		if err != nil {
			return usageError("-acme-domain: " + err.Error())
		}
		cfg := autotls.Config{Domains: domains, Email: *acmeEmail, HTTPListen: *acmeHTTP, TLSListen: *listen,
			CacheDir: filepath.Join(filepath.Dir(*dbPath), "acme")}
		if *acmeStaging {
			cfg.DirectoryURL = autotls.StagingURL
		}
		if certs, err = autotls.New(cfg); err != nil {
			return usageError("-acme-domain: " + err.Error())
		}
		if *publicURL == "" {
			*publicURL = "https://" + domains[0]
			if _, port, _ := net.SplitHostPort(*listen); port != "443" {
				*publicURL += ":" + port
			}
		}
	} else if *acmeHTTP != "" || *acmeEmail != "" || *acmeStaging {
		return usageError("-acme-http-listen, -acme-email and -acme-staging need -acme-domain")
	}
	if !admin.ValidSignupMode(*signup) {
		return usageError("-signup must be off, approval, invite or open")
	}
	keyLife, err := parseLongDuration(*keyExpiry)
	if err != nil {
		return usageError("-key-expiry: " + err.Error())
	}
	*domain = strings.TrimSuffix(strings.ToLower(*domain), ".")
	if err := control.ValidDomain(*domain); err != nil {
		return usageError("-domain: " + err.Error())
	}
	var suffixes []string
	for _, f := range strings.Split(*tenantSuffixes, ",") {
		if f = strings.Trim(strings.ToLower(strings.TrimSpace(f)), "."); f == "" {
			continue
		}
		for _, l := range strings.Split(f, ".") {
			if l == "" || db.SanitizeName(l) != l {
				return usageError("-tenant-domain-suffixes: " + strconv.Quote(f) + ": labels must be lowercase letters, digits and '-'")
			}
		}
		suffixes = append(suffixes, f)
	}
	var upstream []netip.Addr
	for _, f := range strings.Split(*nameservers, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return usageError("-dns-nameservers: " + err.Error())
		}
		upstream = append(upstream, a)
	}
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	// The admin CLI checks account domains against the base domain.
	if err := d.SetSetting(context.Background(), baseDomainSetting, *domain); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var relays protocol.RelayMap
	switch {
	case *relayMapFile != "":
		b, err := os.ReadFile(*relayMapFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &relays); err != nil {
			return fmt.Errorf("parse %s: %w", *relayMapFile, err)
		}
	case *embedRelay:
		stunPort := 0
		if *stunListen != "" {
			_, p, err := net.SplitHostPort(*stunListen)
			if err != nil {
				return usageError("bad -stun-listen: " + err.Error())
			}
			stunPort, _ = strconv.Atoi(p)
		}
		relays = control.EmbeddedRelayMap(stunPort)
	}
	if *stunListen != "" {
		pc, err := net.ListenPacket("udp", *stunListen)
		if err != nil {
			return fmt.Errorf("STUN listener: %w", err)
		}
		defer pc.Close()
		go stun.Serve(pc)
		log.Info("listening", "server", "stun", "addr", "udp://"+pc.LocalAddr().String())
	}
	var relaySrv *relay.Server
	if *embedRelay {
		if relaySrv, err = control.NewEmbeddedRelay(ctx, d, log); err != nil {
			return err
		}
		defer relaySrv.Close()
	}

	ctl, err := control.New(ctx, d, control.Config{
		BaseDomain: *domain, Relays: relays, DisableMagicDNS: !*magicDNS, Nameservers: upstream,
		KeyExpiry: keyLife, EphemeralTimeout: *ephemeralTimeout,
	}, log)
	if err != nil {
		return err
	}
	defer ctl.Close()
	if relaySrv != nil {
		relaySrv.SetAllow(ctl.RelayAllowed) // tenants' packets never cross
	}
	if *tlsCert == "" && !isLoopback(*listen) {
		log.Warn("control API is plain HTTP: traffic is protected by Noise, but clients fetch the server key "+
			"trust-on-first-use. Use TLS, or have clients pin it with `tc up --server-key`.",
			"server_key", ctl.MachinePublic().String())
	}

	scheme := "http"
	if *tlsCert != "" || certs != nil {
		scheme = "https"
	}
	if *publicURL == "" {
		*publicURL = scheme + "://" + *listen
	}

	var ctlHandler http.Handler = ctl.Handler()
	if relaySrv != nil {
		mux := http.NewServeMux()
		mux.Handle(control.EmbeddedRelayPath, relaySrv)
		mux.Handle("/", ctl.Handler())
		ctlHandler = mux
	}
	servers := []*http.Server{{
		Addr: *listen, Handler: ctlHandler,
		ReadHeaderTimeout: control.ReadHeaderTimeout, IdleTimeout: control.IdleTimeout,
	}}
	names := []string{"control"}

	if *adminListen != "" {
		ok, err := admin.HasToken(ctx, d)
		if err != nil {
			return err
		}
		if !ok {
			users, err := d.ListUsers(ctx)
			if err != nil {
				return err
			}
			canSignIn := false
			for _, u := range users {
				canSignIn = canSignIn || (u.Operator() && u.Active() && u.HasPassword())
			}
			if !canSignIn {
				log.Warn("nobody can sign in to the web portal as operator yet: run `tc-control users create NAME -operator -password` (or `tc-control admin-token`)")
			}
		}
		if !isLoopback(*adminListen) && *tlsCert == "" && certs == nil {
			log.Warn("the web portal is reachable over plain HTTP: passwords and session cookies cross the network unencrypted; "+
				"turn on HTTPS (-acme-domain), or keep the portal on this machine (-admin-listen 127.0.0.1:7741)",
				"listen", *adminListen)
		}
		if *signup != admin.SignupOff && isLoopback(*adminListen) {
			log.Info("sign-up is enabled but the web portal only listens on loopback; tenants need -admin-listen on a reachable address (with TLS)",
				"signup", *signup)
		}
		adm := admin.New(d, admin.Info{
			MachineKey: ctl.MachinePublic().String(), BaseDomain: *domain, TenantDomainSuffixes: suffixes, ControlURL: *publicURL, Version: version, Signup: *signup, KeyExpiry: keyLife,
			Traffic: ctl.Traffic,
		}, log)
		servers = append(servers, &http.Server{
			Addr: *adminListen, Handler: adm.Handler(),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		})
		names = append(names, "admin")
	}

	if certs != nil {
		for _, srv := range servers {
			srv.TLSConfig = certs.TLSConfig()
		}
	}
	tlsOn := len(servers) // servers[:tlsOn] use TLS when it's on
	if certs != nil && *acmeHTTP != "" {
		servers = append(servers, &http.Server{Addr: *acmeHTTP, Handler: certs.HTTPHandler(), ReadHeaderTimeout: 10 * time.Second})
		names = append(names, "certificate checks")
	}

	if *metricsListen != "" {
		reg := metrics.NewRegistry()
		ctl.RegisterMetrics(reg)
		if relaySrv != nil {
			relaySrv.RegisterMetrics(reg)
		}
		addBuildInfo(reg, "tc-control")
		mmux := http.NewServeMux()
		mmux.Handle("GET /metrics", reg)
		servers = append(servers, &http.Server{Addr: *metricsListen, Handler: mmux, ReadHeaderTimeout: 10 * time.Second})
		names = append(names, "metrics")
		if !isLoopback(*metricsListen) {
			log.Warn("metrics are served without authentication; keep -metrics-listen on a private address", "listen", *metricsListen)
		}
	}

	errc := make(chan error, len(servers))
	for i, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("%s listener: %w", names[i], err)
		}
		sch := scheme
		if i >= tlsOn {
			sch = "http"
		}
		log.Info("listening", "server", names[i], "addr", sch+"://"+ln.Addr().String())
		go func(srv *http.Server, ln net.Listener, useTLS bool) {
			var err error
			switch {
			case !useTLS:
				err = srv.Serve(ln)
			case certs != nil:
				err = srv.ServeTLS(ln, "", "")
			case *tlsCert != "":
				err = srv.ServeTLS(ln, *tlsCert, *tlsKey)
			default:
				err = srv.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(srv, ln, i < tlsOn)
	}
	log.Info("tc-control started", "version", version, "domain", *domain, "machine_key", ctl.MachinePublic().ShortString(),
		"relay", relaySrv != nil, "relay_regions", len(relays.Regions))

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-errc:
		log.Error("server failed", "err", err)
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctl.Close() // Noise and relay connections are hijacked, so Shutdown doesn't track them
	if relaySrv != nil {
		relaySrv.Close()
	}
	for _, srv := range servers {
		_ = srv.Shutdown(shutCtx)
	}
	return err
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ---- admin-token ----

func cmdAdminToken(args []string) error {
	fs, dbPath := flags("admin-token")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Create a new admin token (for scripts and break-glass operator sign-in), replacing any previous one.")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	tok, err := admin.ResetToken(context.Background(), d)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "New admin token (store it safely; it is not shown again):")
	fmt.Println(tok)
	return nil
}

// ---- users ----

// baseDomainSetting stores serve's -domain, for the admin CLI.
const baseDomainSetting = "base_domain"

func cmdUsers(args []string) error {
	sub, rest, err := subcommand(args, "users")
	if err != nil {
		return err
	}
	fs, dbPath := flags("users " + sub)
	asJSON := fs.Bool("json", false, "output JSON")
	operator := fs.Bool("operator", false, "users create: make the account an operator")
	setPassword := fs.Bool("password", false, "users create: also set a password (prompted, or read from stdin)")
	parseArgs(fs, rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()

	switch sub {
	case "create":
		name, err := oneArg(fs, "users create NAME [-operator] [-password]")
		if err != nil {
			return err
		}
		acct := db.NewAccount{Name: name}
		if *operator {
			acct.Role = db.RoleOperator
		}
		if *setPassword {
			if acct.PasswordHash, err = readNewPassword(name); err != nil {
				return err
			}
		}
		u, err := d.CreateAccount(ctx, acct)
		if err != nil {
			return err
		}
		fmt.Printf("created %s %s (id %d)\n", u.Role, u.Name, u.ID)
	case "list":
		users, err := d.ListUsers(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(users)
		}
		tw := table("ID", "NAME", "ROLE", "STATUS", "PASSWORD", "DOMAIN", "CREATED")
		for _, u := range users {
			pw := "no"
			if u.HasPassword() {
				pw = "yes"
			}
			dom := u.DNSDomain
			if dom == "" {
				dom = "(default)"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", u.ID, u.Name, u.Role, u.Status, pw, dom, u.CreatedAt.Local().Format(time.DateTime))
		}
		return tw.Flush()
	case "delete":
		name, err := oneArg(fs, "users delete NAME")
		if err != nil {
			return err
		}
		if err := d.DeleteUser(ctx, name); err != nil {
			return err
		}
		fmt.Printf("deleted user %s and all their machines and keys\n", name)
	case "passwd":
		name, err := oneArg(fs, "users passwd NAME")
		if err != nil {
			return err
		}
		if _, err := d.GetUser(ctx, name); err != nil {
			return err
		}
		hash, err := readNewPassword(name)
		if err != nil {
			return err
		}
		if err := d.SetPassword(ctx, name, hash); err != nil {
			return err
		}
		fmt.Printf("password set for %s (their other web sessions are signed out)\n", name)
	case "approve", "activate", "suspend":
		name, err := oneArg(fs, "users "+sub+" NAME")
		if err != nil {
			return err
		}
		status := db.StatusActive
		if sub == "suspend" {
			status = db.StatusSuspended
		}
		if err := d.SetUserStatus(ctx, name, status); err != nil {
			return err
		}
		if status == db.StatusSuspended {
			fmt.Printf("suspended %s: their machines are cut off and they are signed out\n", name)
		} else {
			fmt.Printf("%s is active\n", name)
		}
	case "machine-approval":
		if fs.NArg() != 2 || (fs.Arg(1) != "on" && fs.Arg(1) != "off") {
			return usageError("usage: tc-control users machine-approval NAME on|off")
		}
		if err := d.SetMachineApproval(ctx, fs.Arg(0), fs.Arg(1) == "on"); err != nil {
			return err
		}
		fmt.Printf("new machines in %s %s\n", fs.Arg(0), map[string]string{"on": "need approval", "off": "are approved automatically"}[fs.Arg(1)])
	case "domain":
		if fs.NArg() < 1 || fs.NArg() > 2 {
			return usageError("usage: tc-control users domain NAME [DOMAIN|default]")
		}
		base, err := d.GetSetting(ctx, baseDomainSetting)
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return err
		}
		if fs.NArg() == 2 {
			dom := fs.Arg(1)
			if dom == "default" || base != "" && dom == db.TenantDomain(fs.Arg(0), "", base) {
				dom = ""
			}
			if err := d.SetUserDNSDomain(ctx, fs.Arg(0), dom, base); err != nil {
				return err
			}
		}
		u, err := d.GetUser(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		switch {
		case u.DNSDomain != "":
			fmt.Printf("%s's machines are <machine>.%s\n", u.Name, u.DNSDomain)
		case base != "":
			fmt.Printf("%s's machines are <machine>.%s (the default)\n", u.Name, db.TenantDomain(u.Name, "", base))
		default:
			fmt.Printf("%s's machines are <machine>.%s.<base domain> (the default)\n", u.Name, db.TenantLabel(u.Name))
		}
	case "role":
		if fs.NArg() != 2 || (fs.Arg(1) != db.RoleOperator && fs.Arg(1) != db.RoleTenant) {
			return usageError("usage: tc-control users role NAME operator|tenant")
		}
		if err := d.SetUserRole(ctx, fs.Arg(0), fs.Arg(1)); err != nil {
			return err
		}
		article := "a"
		if fs.Arg(1) == db.RoleOperator {
			article = "an"
		}
		fmt.Printf("%s is now %s %s\n", fs.Arg(0), article, fs.Arg(1))
	default:
		return usageError("unknown users command " + strconv.Quote(sub))
	}
	return nil
}

// readNewPassword prompts twice on a terminal (no echo), or reads one line
// from stdin when it isn't a terminal (for scripts), and returns its hash.
func readNewPassword(name string) (string, error) {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "New password for %s: ", name)
		a, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(os.Stderr, "Repeat it: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("the passwords don't match")
		}
		pw = string(a)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	return password.Hash(pw)
}

func cmdShares(args []string) error {
	sub, rest, err := subcommand(args, "shares")
	if err != nil {
		return err
	}
	fs, dbPath := flags("shares " + sub)
	asJSON := fs.Bool("json", false, "output JSON")
	user := fs.String("user", "", "shares list: only shares of or to this account")
	expiration := fs.Duration("expiration", 7*24*time.Hour, "shares link: how long the link stays valid")
	parseArgs(fs, rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()

	switch sub {
	case "list":
		var f db.ShareFilter
		if *user != "" {
			u, err := d.GetUser(ctx, *user)
			if err != nil {
				return err
			}
			f.OwnerID, f.RecipientID = u.ID, u.ID
		}
		list, err := d.ListShares(ctx, f)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(list)
		}
		tw := table("ID", "MACHINE", "OWNER", "SHARED WITH", "STATUS")
		for _, sh := range list {
			with, status := sh.RecipientName, sh.Status
			if sh.RecipientID == 0 {
				with = sh.LinkPrefix + "… (link)"
				status = "unused, expires " + sh.ExpiresAt.Local().Format(time.DateTime)
			} else if sh.Status == db.ShareAccepted && !sh.InEffect() {
				status = "accepted (an account is not active)"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", sh.ID, sh.NodeName, sh.OwnerName, with, status)
		}
		return tw.Flush()
	case "create":
		if fs.NArg() != 2 {
			return usageError("usage: tc-control shares create NODE_ID ACCOUNT")
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return usageError("bad node ID " + strconv.Quote(fs.Arg(0)))
		}
		sh, err := d.ShareWith(ctx, id, fs.Arg(1))
		if err != nil {
			return err
		}
		fmt.Printf("offered %s (owner %s) to %s as share %d; it takes effect when they accept\n", sh.NodeName, sh.OwnerName, sh.RecipientName, sh.ID)
	case "link":
		id, err := idArg(fs, "shares link NODE_ID [-expiration 168h]")
		if err != nil {
			return err
		}
		code, sh, err := d.CreateShareLink(ctx, id, *expiration)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "share link for %s, single use, expires %s (shown once):\n", sh.NodeName, sh.ExpiresAt.Local().Format(time.DateTime))
		fmt.Println(code)
	case "accept":
		id, err := idArg(fs, "shares accept ID")
		if err != nil {
			return err
		}
		sh, err := d.GetShare(ctx, id)
		if err != nil {
			return err
		}
		if err := d.AcceptShare(ctx, id, sh.RecipientID); err != nil {
			return err
		}
		fmt.Printf("accepted share %d on behalf of %s: %s's machines can now reach %s\n", id, sh.RecipientName, sh.RecipientName, sh.NodeName)
	case "revoke":
		id, err := idArg(fs, "shares revoke ID")
		if err != nil {
			return err
		}
		if err := d.DeleteShare(ctx, id, 0); err != nil {
			return err
		}
		fmt.Printf("revoked share %d\n", id)
	default:
		return usageError("unknown shares command " + strconv.Quote(sub))
	}
	return nil
}

func cmdRules(args []string) error {
	sub, rest, err := subcommand(args, "rules")
	if err != nil {
		return err
	}
	fs, dbPath := flags("rules " + sub)
	user := fs.String("user", "", "account (required for add)")
	asJSON := fs.Bool("json", false, "output JSON")
	parseArgs(fs, rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()
	var uid int64
	if *user != "" {
		u, err := d.GetUser(ctx, *user)
		if err != nil {
			return err
		}
		uid = u.ID
	}

	switch sub {
	case "list":
		rules, err := d.ListRules(ctx, uid)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(rules)
		}
		tw := table("ID", "ACCOUNT", "FROM", "TO", "PORTS")
		for _, r := range rules {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.ID, r.UserName, r.Src, r.Dst, r.Ports)
		}
		return tw.Flush()
	case "add":
		if uid == 0 || fs.NArg() < 2 || fs.NArg() > 3 {
			return usageError("usage: tc-control rules add -user NAME FROM TO [PORTS]   (e.g. tag:staff tag:server tcp:22,443)")
		}
		src, dst, ports := strings.ToLower(fs.Arg(0)), strings.ToLower(fs.Arg(1)), "*"
		if fs.NArg() == 3 {
			ports = fs.Arg(2)
		}
		if err := acl.CheckSelector(src); err != nil {
			return usageError("from: " + err.Error())
		}
		if err := acl.CheckSelector(dst); err != nil {
			return usageError("to: " + err.Error())
		}
		access, err := acl.ParsePorts(ports)
		if err != nil {
			return usageError("ports: " + err.Error())
		}
		existing, _ := d.ListRules(ctx, uid)
		r, err := d.AddRule(ctx, uid, src, dst, acl.FormatPorts(access))
		if err != nil {
			return err
		}
		fmt.Printf("added rule %d: %s → %s on %s\n", r.ID, r.Src, r.Dst, r.Ports)
		if len(existing) == 0 {
			fmt.Fprintf(os.Stderr, "note: this is %s's first rule; from now on only what the rules allow is reachable\n", *user)
		}
	case "delete":
		id, err := idArg(fs, "rules delete ID")
		if err != nil {
			return err
		}
		if err := d.DeleteRule(ctx, id, 0); err != nil {
			return err
		}
		fmt.Printf("deleted rule %d\n", id)
	default:
		return usageError("unknown rules command " + strconv.Quote(sub))
	}
	return nil
}

func cmdInvites(args []string) error {
	sub, rest, err := subcommand(args, "invites")
	if err != nil {
		return err
	}
	fs, dbPath := flags("invites " + sub)
	asJSON := fs.Bool("json", false, "output JSON")
	expiration := fs.Duration("expiration", 7*24*time.Hour, "invites create: how long the code stays valid")
	parseArgs(fs, rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()

	switch sub {
	case "create":
		code, inv, err := d.CreateInvite(ctx, *expiration)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "invite %d, single use, expires %s (shown once):\n", inv.ID, inv.ExpiresAt.Local().Format(time.DateTime))
		fmt.Println(code)
	case "list":
		list, err := d.ListInvites(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(list)
		}
		now := time.Now()
		tw := table("ID", "CODE", "EXPIRES", "STATUS")
		for _, i := range list {
			status := "unused"
			switch {
			case i.Revoked:
				status = "revoked"
			case i.UsedBy != "" || !i.UsedAt.IsZero():
				status = "used by " + i.UsedBy
			case !i.Usable(now):
				status = "expired"
			}
			fmt.Fprintf(tw, "%d\t%s…\t%s\t%s\n", i.ID, i.Prefix, i.ExpiresAt.Local().Format(time.DateTime), status)
		}
		return tw.Flush()
	case "revoke":
		id, err := idArg(fs, "invites revoke ID")
		if err != nil {
			return err
		}
		if err := d.RevokeInvite(ctx, id); err != nil {
			return err
		}
		fmt.Printf("revoked invite %d\n", id)
	default:
		return usageError("unknown invites command " + strconv.Quote(sub))
	}
	return nil
}

// ---- keys ----

func cmdKeys(args []string) error {
	sub, rest, err := subcommand(args, "keys")
	if err != nil {
		return err
	}
	fs, dbPath := flags("keys " + sub)
	user := fs.String("user", "", "user name")
	asJSON := fs.Bool("json", false, "output JSON")
	reusable := fs.Bool("reusable", false, "allow the key to register more than one machine")
	ephemeral := fs.Bool("ephemeral", false, "machines registered with this key are ephemeral")
	preapproved := fs.Bool("preapproved", false, "machines registered with this key skip the account's machine approval")
	expiration := fs.Duration("expiration", 24*time.Hour, "key lifetime")
	parseArgs(fs, rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()

	switch sub {
	case "create":
		if *user == "" {
			return usageError("keys create: -user is required")
		}
		u, err := d.GetUser(ctx, *user)
		if err != nil {
			return err
		}
		secret, k, err := d.CreatePreAuthKey(ctx, db.CreatePreAuthKeyParams{
			UserID: u.ID, Reusable: *reusable, Ephemeral: *ephemeral, Preapproved: *preapproved, TTL: *expiration,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "auth key %d for %s, expires %s (shown once):\n", k.ID, u.Name, k.ExpiresAt.Local().Format(time.DateTime))
		fmt.Println(secret)
	case "list":
		var uid int64
		if *user != "" {
			u, err := d.GetUser(ctx, *user)
			if err != nil {
				return err
			}
			uid = u.ID
		}
		keys, err := d.ListPreAuthKeys(ctx, uid)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(keys)
		}
		now := time.Now()
		tw := table("ID", "KEY", "USER", "REUSABLE", "EPHEMERAL", "USES", "EXPIRES", "STATUS")
		for _, k := range keys {
			status := "active"
			switch {
			case k.Revoked:
				status = "revoked"
			case !now.Before(k.ExpiresAt):
				status = "expired"
			case !k.Usable(now):
				status = "used"
			}
			fmt.Fprintf(tw, "%d\t%s…\t%s\t%v\t%v\t%d\t%s\t%s\n", k.ID, k.Prefix, k.UserName, k.Reusable, k.Ephemeral,
				k.Uses, k.ExpiresAt.Local().Format(time.DateTime), status)
		}
		return tw.Flush()
	case "revoke", "expire":
		id, err := idArg(fs, "keys revoke ID")
		if err != nil {
			return err
		}
		if err := d.RevokePreAuthKey(ctx, id); err != nil {
			return err
		}
		fmt.Printf("revoked auth key %d\n", id)
	default:
		return usageError("unknown keys command " + strconv.Quote(sub))
	}
	return nil
}

// ---- nodes ----

func cmdNodes(args []string) error {
	sub, rest, err := subcommand(args, "nodes")
	if err != nil {
		return err
	}
	fs, dbPath := flags("nodes " + sub)
	user := fs.String("user", "", "only list this user's machines")
	asJSON := fs.Bool("json", false, "output JSON")
	parseArgs(fs, rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()

	switch sub {
	case "list":
		var uid int64
		if *user != "" {
			u, err := d.GetUser(ctx, *user)
			if err != nil {
				return err
			}
			uid = u.ID
		}
		nodes, err := d.ListNodes(ctx, uid)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(nodes)
		}
		tw := table("ID", "NAME", "USER", "IPV4", "HOSTNAME", "LAST SEEN", "KEY EXPIRES", "STATUS")
		now := time.Now()
		for _, n := range nodes {
			seen := "never"
			if !n.LastSeen.IsZero() {
				seen = time.Since(n.LastSeen).Truncate(time.Second).String() + " ago"
			}
			expires := "never"
			if !n.ExpiresAt.IsZero() {
				expires = n.ExpiresAt.Local().Format("2006-01-02")
			}
			status := "ok"
			switch {
			case n.UserStatus != db.StatusActive:
				status = "account " + n.UserStatus
			case !n.Approved:
				status = "needs approval"
			case n.Expired(now):
				status = "key expired"
			}
			if n.Ephemeral {
				status += ", ephemeral"
			}
			if n.ExitNode {
				status += ", exit node"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.GivenName, n.UserName, n.IPv4, n.Hostname, seen, expires, status)
		}
		return tw.Flush()
	case "tag":
		if fs.NArg() != 2 {
			return usageError(`usage: tc-control nodes tag ID TAG[,TAG...]   ("" removes all tags)`)
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return usageError("bad node ID " + strconv.Quote(fs.Arg(0)))
		}
		tags := []string{}
		for _, t := range strings.Split(fs.Arg(1), ",") {
			t = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(t, "tag:")))
			if t == "" {
				continue
			}
			if !acl.ValidTag(t) {
				return usageError("bad tag " + strconv.Quote(t) + ": use lowercase letters, digits and '-'")
			}
			tags = append(tags, t)
		}
		slices.Sort(tags)
		tags = slices.Compact(tags)
		if err := d.SetNodeTags(ctx, id, tags); err != nil {
			return err
		}
		fmt.Printf("node %d tags: %s\n", id, strings.Join(tags, ","))
	case "exit-node":
		if fs.NArg() != 2 || (fs.Arg(1) != "on" && fs.Arg(1) != "off") {
			return usageError("usage: tc-control nodes exit-node ID on|off")
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return usageError("bad node ID " + strconv.Quote(fs.Arg(0)))
		}
		on := fs.Arg(1) == "on"
		if on {
			n, err := d.GetNode(ctx, id)
			if err != nil {
				return err
			}
			if err := db.CanBeExitNode(n); err != nil {
				return err
			}
		}
		if err := d.SetNodeExitNode(ctx, id, on); err != nil {
			return err
		}
		fmt.Printf("node %d exit node: %s\n", id, fs.Arg(1))
	case "approve":
		id, err := idArg(fs, "nodes approve ID")
		if err != nil {
			return err
		}
		if err := d.ApproveNode(ctx, id); err != nil {
			return err
		}
		fmt.Printf("approved node %d\n", id)
	case "expiry":
		if fs.NArg() != 2 {
			return usageError("usage: tc-control nodes expiry ID never|DURATION (e.g. 180d)")
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return usageError("bad node ID " + strconv.Quote(fs.Arg(0)))
		}
		d2, err := parseLongDuration(fs.Arg(1))
		if err != nil {
			return usageError(err.Error())
		}
		var at time.Time
		if d2 > 0 {
			at = time.Now().Add(d2)
		}
		if err := d.SetNodeExpiry(ctx, id, at); err != nil {
			return err
		}
		if at.IsZero() {
			fmt.Printf("node %d's key never expires\n", id)
		} else {
			fmt.Printf("node %d's key expires %s\n", id, at.Local().Format(time.DateTime))
		}
	case "delete":
		id, err := idArg(fs, "nodes delete ID")
		if err != nil {
			return err
		}
		if err := d.DeleteNode(ctx, id); err != nil {
			return err
		}
		fmt.Printf("deleted node %d\n", id)
	case "rename":
		if fs.NArg() != 2 {
			return usageError("usage: tc-control nodes rename ID NEWNAME")
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return usageError("bad node ID " + strconv.Quote(fs.Arg(0)))
		}
		if err := d.RenameNode(ctx, id, fs.Arg(1)); err != nil {
			return err
		}
		fmt.Printf("renamed node %d to %s\n", id, fs.Arg(1))
	default:
		return usageError("unknown nodes command " + strconv.Quote(sub))
	}
	return nil
}

// ---- helpers ----

func subcommand(args []string, group string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, usageError(group + ": missing subcommand")
	}
	return args[0], args[1:], nil
}

func oneArg(fs *flag.FlagSet, use string) (string, error) {
	if fs.NArg() != 1 {
		return "", usageError("usage: tc-control " + use)
	}
	return fs.Arg(0), nil
}

func idArg(fs *flag.FlagSet, use string) (int64, error) {
	s, err := oneArg(fs, use)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, usageError("bad ID " + strconv.Quote(s))
	}
	return id, nil
}

func table(headers ...string) *tabwriter.Writer {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	return tw
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// parseLongDuration accepts Go durations plus days ("180d"); "never" and
// "0" mean no limit (0).
func parseLongDuration(v string) (time.Duration, error) {
	switch v {
	case "never", "0", "":
		return 0, nil
	}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad duration %q", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad duration %q (use e.g. 180d, 720h or never)", v)
	}
	return d, nil
}

func cmdRelays(args []string) error {
	sub, rest, err := subcommand(args, "relays")
	if err != nil {
		return err
	}
	fs, dbPath := flags("relays " + sub)
	asJSON := fs.Bool("json", false, "output JSON")
	parseArgs(fs, rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()
	switch sub {
	case "create":
		name, err := oneArg(fs, "relays create NAME")
		if err != nil {
			return err
		}
		secret, _, err := d.CreateRelayToken(ctx, name)
		if err != nil {
			return err
		}
		fmt.Println(secret)
		fmt.Fprintf(os.Stderr, "Relay token for %q (shown once). On the relay host:\n"+
			"  TC_RELAY_TOKEN=%s tc-relay -control-url https://THIS-SERVER\n"+
			"then add the relay to the relay map (tc-control serve -relay-map FILE).\n", name, secret)
		return nil
	case "list":
		ts, err := d.ListRelayTokens(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(ts)
		}
		tw := table("ID", "NAME", "CREATED", "LAST USED")
		for _, t := range ts {
			used := "never"
			if !t.LastUsed.IsZero() {
				used = time.Since(t.LastUsed).Truncate(time.Second).String() + " ago"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", t.ID, t.Name, t.CreatedAt.Local().Format("2006-01-02 15:04"), used)
		}
		return tw.Flush()
	case "delete":
		name, err := oneArg(fs, "relays delete NAME")
		if err != nil {
			return err
		}
		if err := d.DeleteRelayToken(ctx, name); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Relay %q can no longer check machines; it refuses new connections and unknown pairs.\n", name)
		return nil
	default:
		return usageError("relays: unknown subcommand " + sub)
	}
}

// addBuildInfo adds the conventional build-info metric.
func addBuildInfo(r *metrics.Registry, program string) {
	r.Collect("tc_build_info", "The running program and version (always 1).", "gauge", func(emit func([]string, float64)) {
		emit([]string{"program", program, "version", version}, 1)
	})
	start := time.Now()
	r.GaugeFunc("tc_uptime_seconds", "Seconds since the program started.", func() float64 { return time.Since(start).Seconds() })
}
