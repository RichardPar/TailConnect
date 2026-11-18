//go:build linux && !android

package engine

import (
	"os/exec"
	"strings"
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
// DROP. Each rule carries the comment iptComment, so it's removed on stop
// and after a crash. Without iptables nothing is done.
const iptComment = "tailconnect-exit"

type iptRule struct {
	bin, chain string
	spec       []string
}

func (f *forwarder) iptRules() []iptRule {
	var out []iptRule
	bins := []string{"iptables"}
	if f.v6 {
		bins = append(bins, "ip6tables")
	}
	for _, bin := range bins {
		chain := forwardExceptionChain(bin)
		if chain == "" {
			continue
		}
		c := []string{"-m", "comment", "--comment", iptComment, "-j", "ACCEPT"}
		out = append(out,
			iptRule{bin, chain, append([]string{"-i", f.ifname}, c...)},
			iptRule{bin, chain, append([]string{"-o", f.ifname, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, c...)})
	}
	return out
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
	out, err := exec.Command(bin, "-w", "-S", "FORWARD").Output()
	if err == nil && strings.Contains(string(out), "-P FORWARD DROP") {
		return "FORWARD"
	}
	return ""
}

// addIptables inserts the rules, logging (not failing) when it can't: the
// forward chain may well accept the traffic anyway.
func (f *forwarder) addIptables() {
	f.removeIptables() // no duplicates
	for _, r := range f.iptRules() {
		args := append([]string{"-w", "-I", r.chain, "1"}, r.spec...)
		if out, err := exec.Command(r.bin, args...).CombinedOutput(); err != nil {
			f.logf("exit node: allow forwarding in %s %s: %v: %s", r.bin, r.chain, err, strings.TrimSpace(string(out)))
			continue
		}
		f.logf("exit node: allowed forwarding from %s in %s chain %s, which would drop it otherwise", f.ifname, r.bin, r.chain)
	}
}

// removeIptables deletes every rule tagged iptComment, from any chain it may
// have been put in (also those of a tcd that crashed).
func (f *forwarder) removeIptables() {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		for _, chain := range []string{"DOCKER-USER", "FORWARD"} {
			out, err := exec.Command(bin, "-w", "-S", chain).Output()
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.HasPrefix(line, "-A ") || !strings.Contains(line, iptComment) {
					continue
				}
				// "-A CHAIN spec..." → "-D CHAIN spec..."; the comment is a
				// single word, so splitting on spaces is safe.
				args := append([]string{"-w", "-D"}, strings.Fields(line)[1:]...)
				if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
					f.logf("exit node: remove %s rule: %v: %s", bin, err, strings.TrimSpace(string(out)))
				}
			}
		}
	}
}
