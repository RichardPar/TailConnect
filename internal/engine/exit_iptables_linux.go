//go:build linux && !android

package engine

import (
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"tailconnect/internal/dns"
	"tailconnect/internal/ipam"
)

// Another firewall's forward chain that drops by default (Docker's, or
// ufw's) drops forwarded traffic whatever tailconnect-exit's own forward
// chain accepts: a packet must get through every base chain. So an exit
// node also inserts, through iptables, two rules into the chain meant for
// such exceptions:
//
//	-i tc0 -j ACCEPT
//	-o tc0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
//
// into DOCKER-USER where Docker is installed (Docker keeps that chain for
// the user and jumps to it first), or else into FORWARD when its policy is
// DROP. Likewise, when the INPUT policy is DROP (ufw), the exit node's DNS
// server for its clients (dns.ExitPort, UDP and TCP) is allowed from tc0.
// Where nftables doesn't work (forwarder.nftOff), iptables also does what
// the tailconnect-exit nftables table would:
//
//	nat POSTROUTING  -s <tunnel range> ! -o tc0 -j MASQUERADE
//	FORWARD          -i tc0 -o tc0 -j DROP
//	FORWARD          -i tc0 -j ACCEPT
//	FORWARD          -o tc0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
//
// (iptables can't match the input interface in POSTROUTING, hence the
// source range.) Each rule carries the comment iptComment, so it's removed
// on stop and after a crash. Without iptables nothing is done.
const iptComment = "tailconnect-exit"

type iptRule struct {
	bin, table, chain string // table "" = filter
	spec              []string
	required          bool // NAT and forwarding without nftables: failing fails the exit node
	nat               bool // part of that NAT and forwarding setup (logged as a whole)
}

func haveIptables() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func (f *forwarder) iptRules() []iptRule {
	var out []iptRule
	bins := []string{"iptables"}
	if f.v6 {
		bins = append(bins, "ip6tables")
	}
	for _, bin := range bins {
		comment := []string{"-m", "comment", "--comment", iptComment}
		c := append(slices.Clone(comment), "-j", "ACCEPT")
		if f.nftOff {
			src := ipam.DefaultV4.String()
			if bin == "ip6tables" {
				src = ipam.DefaultV6.String()
			}
			out = append(out,
				iptRule{bin, "nat", "POSTROUTING", append([]string{"-s", src, "!", "-o", f.ifname}, append(slices.Clone(comment), "-j", "MASQUERADE")...), bin == "iptables", true},
				iptRule{bin, "", "FORWARD", append([]string{"-i", f.ifname, "-o", f.ifname}, append(slices.Clone(comment), "-j", "DROP")...), bin == "iptables", true},
				iptRule{bin, "", "FORWARD", append([]string{"-i", f.ifname}, c...), bin == "iptables", true},
				iptRule{bin, "", "FORWARD", append([]string{"-o", f.ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, c...), bin == "iptables", true})
		}
		if chain := forwardExceptionChain(bin); chain != "" && !(f.nftOff && chain == "FORWARD") {
			out = append(out,
				iptRule{bin, "", chain, append([]string{"-i", f.ifname}, c...), false, false},
				iptRule{bin, "", chain, append([]string{"-o", f.ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, c...), false, false})
		}
		if bin == "iptables" && policyDrop(bin, "INPUT") { // the DNS server listens on IPv4 only
			port := strconv.Itoa(dns.ExitPort)
			for _, proto := range []string{"udp", "tcp"} {
				out = append(out, iptRule{bin, "", "INPUT", append([]string{"-i", f.ifname, "-p", proto, "--dport", port}, c...), false, false})
			}
		}
	}
	return out
}

// policyDrop reports whether chain's policy is DROP.
func policyDrop(bin, chain string) bool {
	if _, err := exec.LookPath(bin); err != nil {
		return false
	}
	out, err := exec.Command(bin, "-w", "-S", chain).Output()
	return err == nil && strings.Contains(string(out), "-P "+chain+" DROP")
}

// forwardExceptionChain is the chain to allow forwarding in: DOCKER-USER if
// it exists, FORWARD if its policy is DROP, else "" (nothing in the way, or
// no iptables).
func forwardExceptionChain(bin string) string {
	if _, err := exec.LookPath(bin); err != nil {
		return ""
	}
	if exec.Command(bin, "-w", "-S", "DOCKER-USER").Run() == nil {
		return "DOCKER-USER"
	}
	if policyDrop(bin, "FORWARD") {
		return "FORWARD"
	}
	return ""
}

// addIptables inserts the rules, each chain's in the order listed, at its
// top. A failing exception is logged (the chain may well accept the
// traffic anyway); a failing required rule (NAT without nftables) is an
// error.
func (f *forwarder) addIptables() error {
	f.removeIptables() // no duplicates
	rules := f.iptRules()
	for i := len(rules) - 1; i >= 0; i-- { // inserting at 1 reverses the order
		r := rules[i]
		args := []string{"-w"}
		if r.table != "" {
			args = append(args, "-t", r.table)
		}
		args = append(append(args, "-I", r.chain, "1"), r.spec...)
		if out, err := exec.Command(r.bin, args...).CombinedOutput(); err != nil {
			err = fmt.Errorf("%s %s: %v: %s", r.bin, strings.Join(args[1:], " "), err, strings.TrimSpace(string(out)))
			if r.required {
				f.removeIptables() // none half set up
				return err
			}
			if r.nat {
				f.logf("exit node: %v (IPv6 isn't forwarded)", err)
				continue
			}
			f.logf("exit node: %v", err)
			continue
		}
		switch {
		case r.nat:
		case r.chain == "INPUT":
			f.logf("exit node: allowed %s DNS for clients from %s in %s chain INPUT, which would drop it otherwise", r.spec[3], f.ifname, r.bin)
		default:
			f.logf("exit node: allowed forwarding from %s in %s chain %s, which would drop it otherwise", f.ifname, r.bin, r.chain)
		}
	}
	if f.nftOff {
		f.logf("exit node: NAT and forwarding set up with iptables")
	}
	return nil
}

// removeIptables deletes every rule tagged iptComment, from any chain it may
// have been put in (also those of a tcd that crashed).
func (f *forwarder) removeIptables() {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		for _, tc := range [][2]string{{"filter", "DOCKER-USER"}, {"filter", "FORWARD"}, {"filter", "INPUT"}, {"nat", "POSTROUTING"}} {
			table, chain := tc[0], tc[1]
			out, err := exec.Command(bin, "-w", "-t", table, "-S", chain).Output()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, iptComment) {
					continue
				}
				// "-A CHAIN spec..." → "-D CHAIN spec..."; the comment is a
				// single word, so splitting on spaces is safe.
				args := append([]string{"-w", "-t", table, "-D"}, strings.Fields(line)[1:]...)
				if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
					f.logf("exit node: remove %s rule: %v: %s", bin, err, strings.TrimSpace(string(out)))
				}
			}
		}
	}
}
