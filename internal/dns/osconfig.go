package dns

import (
	"bufio"
	"bytes"
	"net/netip"
	"slices"
	"strings"
)

// OSConfig is the DNS configuration to apply to the host.
type OSConfig struct {
	// Nameservers to use (the in-tunnel resolver). Empty: revert to the
	// host's original configuration.
	Nameservers []netip.Addr
	// SearchDomains are appended to single-label names ("laptop").
	SearchDomains []string
	// MatchDomains are the only domains sent to Nameservers (split DNS);
	// other queries keep using the host's resolvers. Empty: send everything.
	MatchDomains []string
}

func (c OSConfig) Equal(o OSConfig) bool {
	return slices.Equal(c.Nameservers, o.Nameservers) && slices.Equal(c.SearchDomains, o.SearchDomains) &&
		slices.Equal(c.MatchDomains, o.MatchDomains)
}

// OSConfigurator applies OSConfig to the host.
type OSConfigurator interface {
	Set(OSConfig) error
	// SupportsSplitDNS reports whether MatchDomains can be honoured. If not,
	// all queries go to the resolver, which forwards non-MagicDNS names to
	// HostResolvers.
	SupportsSplitDNS() bool
	// HostResolvers are the host's own resolvers, needed for forwarding when
	// split DNS is unsupported.
	HostResolvers() []netip.Addr
	// Mode names the mechanism, for status ("systemd-resolved", ...).
	Mode() string
	// Close reverts the host to its original configuration.
	Close() error
}

// NoopConfigurator leaves the host's DNS alone.
type NoopConfigurator struct{}

func (NoopConfigurator) Set(OSConfig) error          { return nil }
func (NoopConfigurator) SupportsSplitDNS() bool      { return true }
func (NoopConfigurator) HostResolvers() []netip.Addr { return nil }
func (NoopConfigurator) Mode() string                { return "off" }
func (NoopConfigurator) Close() error                { return nil }

// resolvConf is the part of resolv.conf(5) we care about.
type resolvConf struct {
	Nameservers []netip.Addr
	Search      []string
	Other       []string // remaining lines (options, sortlist, ...)
}

func parseResolvConf(b []byte) resolvConf {
	var rc resolvConf
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		switch f[0] {
		case "nameserver":
			if len(f) > 1 {
				// Zone suffixes ("fe80::1%eth0") are dropped by ParseAddr failing.
				if a, err := netip.ParseAddr(f[1]); err == nil {
					rc.Nameservers = append(rc.Nameservers, a)
				}
			}
		case "search", "domain":
			rc.Search = append(rc.Search, f[1:]...)
		default:
			rc.Other = append(rc.Other, line)
		}
	}
	return rc
}

func (rc resolvConf) marshal(header string) []byte {
	var b bytes.Buffer
	b.WriteString(header)
	for _, ns := range rc.Nameservers {
		b.WriteString("nameserver " + ns.String() + "\n")
	}
	if len(rc.Search) > 0 {
		b.WriteString("search " + strings.Join(rc.Search, " ") + "\n")
	}
	for _, o := range rc.Other {
		b.WriteString(o + "\n")
	}
	return b.Bytes()
}
