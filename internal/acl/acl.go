// Package acl evaluates an account's access rules: which of its machines
// may open connections to which, on which ports.
//
// A rule is "from → to on ports". Selectors are "*" (any machine of the
// account), "tag:NAME" (machines with that tag) or a machine name. Ports
// are "*" (everything, including ping) or a comma-separated list of
// "22", "8000-8100", "tcp:22", "udp:53", "udp:1000-2000" or "icmp" (ping).
// A bare port means TCP and UDP.
//
// Rules only add permissions: an account with no rules allows everything
// (Policy is nil); with rules, only what some rule allows is permitted.
package acl

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"tailconnect/internal/protocol"
)

// Rule is one access rule as stored and edited.
type Rule struct {
	ID    int64
	Src   string
	Dst   string
	Ports string // "" means "*"
}

// Machine is what selectors match against.
type Machine struct {
	ID   int64
	Name string
	Tags []string
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidTag reports whether t can be a tag (a DNS-label-like name).
func ValidTag(t string) bool { return labelRE.MatchString(t) }

// CheckSelector validates a selector.
func CheckSelector(s string) error {
	switch {
	case s == "*":
		return nil
	case strings.HasPrefix(s, "tag:"):
		if !ValidTag(strings.TrimPrefix(s, "tag:")) {
			return fmt.Errorf("bad tag in %q: use lowercase letters, digits and '-'", s)
		}
		return nil
	case labelRE.MatchString(s):
		return nil
	}
	return fmt.Errorf("bad selector %q: use *, tag:NAME or a machine name", s)
}

func selectorMatches(sel string, m Machine) bool {
	switch {
	case sel == "*":
		return true
	case strings.HasPrefix(sel, "tag:"):
		return slices.Contains(m.Tags, strings.TrimPrefix(sel, "tag:"))
	}
	return sel == m.Name
}

// Access is what one machine may open on another.
type Access struct {
	All    bool                 // everything, including ping
	Ranges []protocol.PortRange // otherwise these; empty = nothing
}

func (a Access) None() bool { return !a.All && len(a.Ranges) == 0 }

// ParsePorts parses a ports field into an Access.
func ParsePorts(spec string) (Access, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return Access{All: true}, nil
	}
	var a Access
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}
		if item == "*" {
			return Access{All: true}, nil
		}
		if item == "icmp" {
			a.Ranges = append(a.Ranges, protocol.PortRange{Proto: "icmp"})
			continue
		}
		proto := ""
		if p, rest, ok := strings.Cut(item, ":"); ok {
			if p != "tcp" && p != "udp" {
				return Access{}, fmt.Errorf("bad protocol %q in %q (tcp, udp or icmp)", p, item)
			}
			proto, item = p, rest
		}
		lo, hi, isRange := strings.Cut(item, "-")
		first, err1 := strconv.ParseUint(lo, 10, 16)
		last := first
		var err2 error
		if isRange {
			last, err2 = strconv.ParseUint(hi, 10, 16)
		}
		if err1 != nil || err2 != nil || first == 0 || last < first {
			return Access{}, fmt.Errorf("bad port or range %q", item)
		}
		a.Ranges = append(a.Ranges, protocol.PortRange{Proto: proto, First: uint16(first), Last: uint16(last)})
	}
	if len(a.Ranges) == 0 {
		return Access{}, errors.New("no ports given (use * for everything)")
	}
	return a, nil
}

// FormatPorts is the canonical text for an Access.
func FormatPorts(a Access) string {
	if a.All {
		return "*"
	}
	var parts []string
	for _, r := range a.Ranges {
		var s string
		switch {
		case r.Proto == "icmp":
			parts = append(parts, "icmp")
			continue
		case r.First == r.Last:
			s = strconv.Itoa(int(r.First))
		default:
			s = fmt.Sprintf("%d-%d", r.First, r.Last)
		}
		if r.Proto != "" {
			s = r.Proto + ":" + s
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

type compiled struct {
	src, dst string
	access   Access
}

// Policy is an account's compiled rules. A nil Policy allows everything.
type Policy struct {
	rules []compiled
}

// Compile checks and compiles rules; no rules gives a nil Policy.
func Compile(rules []Rule) (*Policy, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	p := &Policy{}
	for _, r := range rules {
		if err := CheckSelector(r.Src); err != nil {
			return nil, err
		}
		if err := CheckSelector(r.Dst); err != nil {
			return nil, err
		}
		a, err := ParsePorts(r.Ports)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, compiled{r.Src, r.Dst, a})
	}
	return p, nil
}

// DenyAll is a policy that allows nothing.
func DenyAll() *Policy { return &Policy{} }

// Allowed is what src may open on dst: the union of matching rules.
func (p *Policy) Allowed(src, dst Machine) Access {
	if p == nil {
		return Access{All: true}
	}
	var out Access
	for _, r := range p.rules {
		if !selectorMatches(r.src, src) || !selectorMatches(r.dst, dst) {
			continue
		}
		if r.access.All {
			return Access{All: true}
		}
		out.Ranges = append(out.Ranges, r.access.Ranges...)
	}
	return out
}

// Connected reports whether a and b may talk at all (either direction).
func (p *Policy) Connected(a, b Machine) bool {
	if p == nil {
		return true
	}
	return !p.Allowed(a, b).None() || !p.Allowed(b, a).None()
}
