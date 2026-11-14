// Command tc-control is the TailConnect coordination server and its admin CLI.
//
//	tc-control serve                     run the control + admin web servers
//	tc-control admin-token               create/replace the admin web token
//	tc-control users create|list|delete  manage users
//	tc-control keys create|list|revoke   manage pre-auth keys
//	tc-control nodes list|delete|rename  manage registered machines
//
// Admin subcommands operate on the SQLite database directly, so they work
// whether or not the server is running.
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
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"tailconnect/internal/admin"
	"tailconnect/internal/control"
	"tailconnect/internal/db"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `tc-control: TailConnect coordination server

Usage:
  tc-control serve [flags]
  tc-control admin-token [-db PATH]
  tc-control users create NAME | list | delete NAME
  tc-control keys create -user NAME [-reusable] [-ephemeral] [-expiration 24h]
  tc-control keys list [-user NAME] | revoke ID
  tc-control nodes list [-user NAME] | delete ID | rename ID NEWNAME
  tc-control version

Every subcommand accepts -db PATH (default $TC_CONTROL_DB or ./control.db).
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

func defaultDBPath() string {
	if p := os.Getenv("TC_CONTROL_DB"); p != "" {
		return p
	}
	return "control.db"
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
	listen := fs.String("listen", "127.0.0.1:8080", "client-facing control API address")
	adminListen := fs.String("admin-listen", "127.0.0.1:8081", `admin web UI/API address ("" disables)`)
	domain := fs.String("domain", "tc.internal", "MagicDNS base domain")
	publicURL := fs.String("public-url", "", "URL clients use to reach this server (shown in the admin UI)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS on both listeners)")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	logJSON := fs.Bool("log-json", false, "log in JSON format")
	fs.Parse(args)

	var h slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logJSON {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(h)

	if (*tlsCert == "") != (*tlsKey == "") {
		return usageError("-tls-cert and -tls-key must be given together")
	}
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctl, err := control.New(ctx, d, control.Config{BaseDomain: *domain}, log)
	if err != nil {
		return err
	}
	if !isLoopback(*listen) {
		log.Warn("control API is listening on a non-loopback address; until the Noise transport lands (milestone 2) "+
			"/machine/* requests are unauthenticated. Only expose it on trusted networks.", "listen", *listen)
	}

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	if *publicURL == "" {
		*publicURL = scheme + "://" + *listen
	}

	servers := []*http.Server{{
		Addr: *listen, Handler: ctl.Handler(),
		ReadHeaderTimeout: control.ReadHeaderTimeout, IdleTimeout: control.IdleTimeout,
	}}
	names := []string{"control"}

	if *adminListen != "" {
		ok, err := admin.HasToken(ctx, d)
		if err != nil {
			return err
		}
		if !ok {
			log.Warn("no admin token configured; run `tc-control admin-token` to create one before signing in")
		}
		if !isLoopback(*adminListen) && *tlsCert == "" {
			log.Warn("admin web server is on a non-loopback address without TLS; the admin token and session cookie travel in clear text",
				"listen", *adminListen)
		}
		adm := admin.New(d, admin.Info{
			MachineKey: ctl.MachinePublic().String(), BaseDomain: *domain, ControlURL: *publicURL, Version: version,
		}, log)
		servers = append(servers, &http.Server{
			Addr: *adminListen, Handler: adm.Handler(),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		})
		names = append(names, "admin")
	}

	errc := make(chan error, len(servers))
	for i, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("%s listener: %w", names[i], err)
		}
		log.Info("listening", "server", names[i], "addr", scheme+"://"+ln.Addr().String())
		go func(srv *http.Server, ln net.Listener) {
			var err error
			if *tlsCert != "" {
				err = srv.ServeTLS(ln, *tlsCert, *tlsKey)
			} else {
				err = srv.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(srv, ln)
	}
	log.Info("tc-control started", "version", version, "domain", *domain, "machine_key", ctl.MachinePublic().ShortString())

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-errc:
		log.Error("server failed", "err", err)
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
		fmt.Fprintln(fs.Output(), "Create a new admin web token, replacing (and logging out) any previous one.")
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

func cmdUsers(args []string) error {
	sub, rest, err := subcommand(args, "users")
	if err != nil {
		return err
	}
	fs, dbPath := flags("users " + sub)
	asJSON := fs.Bool("json", false, "output JSON")
	fs.Parse(rest)
	d, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()

	switch sub {
	case "create":
		name, err := oneArg(fs, "users create NAME")
		if err != nil {
			return err
		}
		u, err := d.CreateUser(ctx, name)
		if err != nil {
			return err
		}
		fmt.Printf("created user %s (id %d)\n", u.Name, u.ID)
	case "list":
		users, err := d.ListUsers(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(users)
		}
		tw := table("ID", "NAME", "CREATED")
		for _, u := range users {
			fmt.Fprintf(tw, "%d\t%s\t%s\n", u.ID, u.Name, u.CreatedAt.Local().Format(time.DateTime))
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
	default:
		return usageError("unknown users command " + strconv.Quote(sub))
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
	expiration := fs.Duration("expiration", 24*time.Hour, "key lifetime")
	fs.Parse(rest)
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
			UserID: u.ID, Reusable: *reusable, Ephemeral: *ephemeral, TTL: *expiration,
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
	fs.Parse(rest)
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
		tw := table("ID", "NAME", "USER", "IPV4", "IPV6", "HOSTNAME", "LAST SEEN")
		for _, n := range nodes {
			seen := "never"
			if !n.LastSeen.IsZero() {
				seen = time.Since(n.LastSeen).Truncate(time.Second).String() + " ago"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.GivenName, n.UserName, n.IPv4, n.IPv6, n.Hostname, seen)
		}
		return tw.Flush()
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
