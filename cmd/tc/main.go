// Command tc is the TailConnect command-line client. It controls the local
// tcd daemon.
//
//	tc up [--server URL] [--authkey KEY] [--hostname NAME] [--exit-node NAME]
//	tc down
//	tc status [--json]
//	tc ip [-4|-6] [PEER]
//	tc logout
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"tailconnect/internal/acl"
	"tailconnect/internal/key"
	"tailconnect/internal/localapi"
)

var version = "dev"

const usage = `tc: TailConnect client

Usage:
  tc up [--server URL] [--authkey KEY] [--hostname NAME] [--server-key mkey:...]
        [--exit-node NAME]   send internet traffic through exit node NAME ("" = stop)
  tc down
  tc status [--json]
  tc ip [-4|-6] [PEER]
  tc logout
  tc version

Global: --socket PATH (default $TC_SOCKET or ` + localapi.DefaultSocket + `)
`

func main() {
	args := os.Args[1:]
	socket := os.Getenv("TC_SOCKET")
	if socket == "" {
		socket = localapi.DefaultSocket
	}
	// Accept --socket before the subcommand.
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		name, val, hasVal := strings.Cut(strings.TrimLeft(args[0], "-"), "=")
		if name != "socket" {
			break
		}
		if !hasVal {
			if len(args) < 2 {
				die(2, "--socket needs a value")
			}
			val, args = args[1], args[1:]
		}
		socket, args = val, args[1:]
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	c := localapi.NewClient(socket)
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "up":
		err = cmdUp(c, rest)
	case "down":
		_, err = c.Down(context.Background())
		if err == nil {
			fmt.Println("Tunnel stopped. Run `tc up` to reconnect.")
		}
	case "status":
		err = cmdStatus(c, rest)
	case "ip":
		err = cmdIP(c, rest)
	case "logout":
		_, err = c.Logout(context.Background())
		if err == nil {
			fmt.Println("Logged out. This machine has been removed from the network.")
		}
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		die(2, "unknown command %q\n\n%s", cmd, usage)
	}
	if err != nil {
		die(1, "%v", err)
	}
}

func die(code int, f string, a ...any) {
	fmt.Fprintf(os.Stderr, "tc: "+f+"\n", a...)
	os.Exit(code)
}

func cmdUp(c *localapi.Client, args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	server := fs.String("server", "", "control server URL, e.g. https://ctl.example.com (needed on first login)")
	authKey := fs.String("authkey", "", "pre-auth key (needed to register this machine)")
	hostname := fs.String("hostname", "", "name for this machine (default: OS hostname)")
	serverKey := fs.String("server-key", "", "pin the server's machine key (mkey:...) instead of fetching it")
	timeout := fs.Duration("timeout", 20*time.Second, "how long to wait for the tunnel to come up")
	exitNode := fs.String("exit-node", "", `send all internet traffic through this exit node (name or tunnel IP); "" stops (default: unchanged, off on a new machine)`)
	fs.Parse(args)

	req := localapi.UpRequest{ControlURL: *server, AuthKey: *authKey, Hostname: *hostname}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "exit-node" {
			req.ExitNode = exitNode
		}
	})
	if *serverKey != "" {
		k, err := key.ParsePublic[key.MachineKind](*serverKey)
		if err != nil {
			return fmt.Errorf("--server-key: %w", err)
		}
		req.ServerKey = k
	}
	if *authKey == "" {
		if v := os.Getenv("TC_AUTHKEY"); v != "" {
			req.AuthKey = v
		}
	}
	ctx := context.Background()
	if _, err := c.Up(ctx, req); err != nil {
		return err
	}
	deadline := time.Now().Add(*timeout)
	for {
		st, err := c.Status(ctx)
		if err != nil {
			return err
		}
		switch {
		case st.State == localapi.StateRunning:
			if st.Self != nil {
				fmt.Printf("Connected as %s (%s)\n", st.Self.Name, addrList(st.Self.Addresses))
			} else {
				fmt.Println("Connected.")
			}
			if req.ExitNode != nil {
				printExitNode(&st)
				if *req.ExitNode == "" {
					fmt.Println("Internet traffic goes direct (no exit node).")
				}
			}
			return nil
		case st.State == localapi.StateNeedsLogin || st.State == localapi.StateStopped:
			return fmt.Errorf("tunnel did not start: %s", orDefault(st.Error, st.State))
		case time.Now().After(deadline):
			return fmt.Errorf("still %s after %v: %s", st.State, *timeout, orDefault(st.Error, "waiting for control server"))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func cmdStatus(c *localapi.Client, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	fs.Parse(args)
	st, err := c.Status(context.Background())
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	switch st.State {
	case localapi.StateNeedsLogin:
		fmt.Println("Logged out. Run: tc up --server URL --authkey KEY")
		if st.Error != "" {
			fmt.Println("Note:", st.Error)
		}
		return nil
	case localapi.StateStopped:
		fmt.Println("Stopped. Run: tc up")
		if st.Error != "" {
			fmt.Println("Error:", st.Error)
		}
		return nil
	}
	relay := "none"
	if st.HomeRelay != 0 {
		relay = fmt.Sprintf("%d", st.HomeRelay)
		if !st.RelayConnected {
			relay += " (connecting)"
		}
	}
	fmt.Printf("State: %s   control: %s   relay: %s\n", st.State, st.ControlURL, relay)
	if st.Error != "" {
		fmt.Println("Warning:", st.Error)
	}
	if st.Notice != "" {
		fmt.Println("Notice:", st.Notice)
	}
	if st.Self != nil && st.Self.KeyExpiry != nil {
		if left := time.Until(*st.Self.KeyExpiry); left > 0 && left < 14*24*time.Hour {
			fmt.Printf("Warning: this machine's key expires %s (in %s); renew with: sudo tc up --authkey KEY\n",
				st.Self.KeyExpiry.Local().Format("2006-01-02 15:04"), humanDays(left))
		}
	}
	printExitNode(&st)
	if d := st.DNS; d != nil {
		how := d.HostConfig
		switch {
		case d.HostConfig == "off":
			how = "host DNS not configured; query " + d.Resolver.String()
		case d.SplitDNS:
			base := d.Base
			if base == "" {
				base = d.Domain
			}
			how += ", only ." + base + " names"
		default:
			how += ", all names"
		}
		fmt.Printf("MagicDNS: %s (%s)\n", d.Domain, how)
		if d.Error != "" {
			fmt.Println("Warning: DNS:", d.Error)
		}
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', 0)
	if st.Self != nil {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", first4(st.Self.Addresses), shortName(st.Self.Name, &st), st.Self.User, st.Self.OS, "(this machine)")
	}
	for _, p := range st.Peers {
		state := "idle"
		if p.Active {
			state = "active"
		}
		detail := state
		switch {
		case p.Shared && p.NoInitiate:
			detail = "shared with you; " + state
		case p.Shared:
			detail = "has access to this machine; " + state
		case p.NoInitiate && len(p.Inbound) == 0:
			detail = "rules: can't open connections here; " + state
		case p.NoInitiate:
			detail = "rules: can open " + acl.FormatPorts(acl.Access{Ranges: p.Inbound}) + " here; " + state
		}
		switch {
		case p.CurrentEndpoint.IsValid():
			detail += "; direct " + p.CurrentEndpoint.String()
			if p.LatencyMS > 0 {
				detail += fmt.Sprintf(" (%.1fms)", p.LatencyMS)
			}
		case p.Relay != 0:
			detail += fmt.Sprintf("; relay %d", p.Relay)
		case len(p.Endpoints) == 0:
			detail += "; no endpoints reported"
		}
		if p.ExitNode {
			detail = "exit node; " + detail
			if st.ExitNode != nil && st.ExitNode.Using == p.Name {
				detail = "exit node (in use); " + strings.TrimPrefix(detail, "exit node; ")
			}
		}
		if p.RxBytes+p.TxBytes > 0 {
			detail += fmt.Sprintf("; rx %s tx %s", bytesStr(p.RxBytes), bytesStr(p.TxBytes))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", first4(p.Addresses), shortName(p.Name, &st), p.User, p.OS, detail)
	}
	return tw.Flush()
}

// printExitNode says which exit node carries this machine's internet
// traffic, and whether it is one.
func printExitNode(st *localapi.Status) {
	e := st.ExitNode
	if e == nil {
		return
	}
	switch {
	case e.Using != "":
		fmt.Printf("Exit node: internet traffic goes through %s\n", shortName(e.Using, st))
	case e.Chosen != "":
		fmt.Printf("Warning: exit node %s not in use (%s); internet traffic goes direct\n", e.Chosen, orDefault(e.Error, "not connected yet"))
	}
	if e.Serving {
		if e.ServingError != "" {
			fmt.Println("Warning: this machine should be an exit node but can't forward traffic:", e.ServingError)
		} else {
			fmt.Println("Exit node: this machine forwards internet traffic for its account")
		}
	}
}

func cmdIP(c *localapi.Client, args []string) error {
	fs := flag.NewFlagSet("ip", flag.ExitOnError)
	only4 := fs.Bool("4", false, "only IPv4")
	only6 := fs.Bool("6", false, "only IPv6")
	fs.Parse(args)
	st, err := c.Status(context.Background())
	if err != nil {
		return err
	}
	addrs := []netip.Prefix(nil)
	if fs.NArg() == 0 {
		if st.Self == nil {
			return errors.New("not logged in")
		}
		addrs = st.Self.Addresses
	} else {
		want := fs.Arg(0)
		for _, p := range st.Peers {
			if p.Name == want || shortName(p.Name, &st) == want || p.HostName == want {
				addrs = p.Addresses
				break
			}
		}
		if addrs == nil {
			return fmt.Errorf("no peer named %q", want)
		}
	}
	for _, a := range addrs {
		if (*only4 && !a.Addr().Is4()) || (*only6 && !a.Addr().Is6()) {
			continue
		}
		fmt.Println(a.Addr())
	}
	return nil
}

func addrList(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.Addr().String())
	}
	return strings.Join(s, ", ")
}

func first4(ps []netip.Prefix) string {
	for _, p := range ps {
		if p.Addr().Is4() {
			return p.Addr().String()
		}
	}
	if len(ps) > 0 {
		return ps[0].Addr().String()
	}
	return "-"
}

// shortName drops this machine's own domain ("laptop"), or else the base
// domain, leaving the tenant for other tenants' shared machines ("nas.acme").
func shortName(fqdn string, st *localapi.Status) string {
	if st.Domain != "" && strings.HasSuffix(fqdn, "."+st.Domain) {
		return strings.TrimSuffix(fqdn, "."+st.Domain)
	}
	if st.DNS != nil && st.DNS.Base != "" {
		return strings.TrimSuffix(fqdn, "."+st.DNS.Base)
	}
	return fqdn
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func bytesStr(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanDays(d time.Duration) string {
	if d < 48*time.Hour {
		return d.Round(time.Hour).String()
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
