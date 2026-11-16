package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"tailconnect/internal/winnet"
)

// On Windows, queries are routed to MagicDNS by Name Resolution Policy
// Table (NRPT) rules: registry keys the DNS client reads, each sending some
// name suffixes to given servers. That gives split DNS without touching the
// host's own resolvers; a rule for "." sends everything. Search domains go
// on the tunnel adapter, so single-label names ("laptop") are completed.

const (
	nrptPath = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// nrptGPOPath holds rules set by Group Policy. When it has any, the DNS
	// client ignores the local rules in nrptPath.
	nrptGPOPath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// nrptKeyPrefix starts the names of tcd's rule keys; the rule number
	// follows.
	nrptKeyPrefix = "{7c7c0e1a-7c0e-4a1e-8a5c-6e72707400"
	// nrptMaxNames is the most names tcd puts in one rule (the DNS client
	// handles large rules poorly).
	nrptMaxNames = 50
)

type nrpt struct {
	guid    windows.GUID // tunnel adapter
	logf    func(string, ...any)
	applied bool
}

// NewOSConfigurator returns the DNS configurator for this host: NRPT rules
// (mode auto or "nrpt"), or nothing (off).
func NewOSConfigurator(o OSOptions) (OSConfigurator, error) {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	switch o.Mode {
	case ModeOff:
		return NoopConfigurator{}, nil
	case "", ModeAuto, ModeNRPT:
	default:
		return nil, fmt.Errorf("dns: unknown mode %q (want auto, %s or off)", o.Mode, ModeNRPT)
	}
	luid, err := winnet.InterfaceAliasToLUID(o.Interface)
	if err != nil {
		return nil, fmt.Errorf("dns: find %s: %w", o.Interface, err)
	}
	guid, err := winnet.LUIDToGUID(luid)
	if err != nil {
		return nil, fmt.Errorf("dns: find %s: %w", o.Interface, err)
	}
	n := &nrpt{guid: guid, logf: o.Logf}
	// Rules left by a tcd that crashed would send names to a resolver that
	// is no longer there.
	if err := n.writeRules(nil, nil); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *nrpt) Mode() string                { return ModeNRPT }
func (n *nrpt) SupportsSplitDNS() bool      { return true }
func (n *nrpt) HostResolvers() []netip.Addr { return nil }

func (n *nrpt) Set(c OSConfig) error {
	if len(c.Nameservers) == 0 {
		return n.Close()
	}
	if gpoRulesPresent() {
		n.logf("dns: Group Policy sets NRPT rules on this machine, so Windows ignores tcd's; MagicDNS names may not resolve")
	}
	names := []string{"."}
	if len(c.MatchDomains) > 0 {
		names = names[:0]
		for _, d := range c.MatchDomains {
			names = append(names, "."+strings.TrimSuffix(d, "."))
		}
	}
	if err := n.writeRules(names, c.Nameservers); err != nil {
		return err
	}
	n.applied = true
	if err := n.setSearch(c.SearchDomains); err != nil {
		n.logf("dns: search domains: %v (use full names, e.g. laptop.%s)", err, firstOr(c.SearchDomains, "DOMAIN"))
	}
	flush(n.logf)
	return nil
}

func (n *nrpt) Close() error {
	if !n.applied {
		return nil
	}
	n.applied = false
	err := n.writeRules(nil, nil)
	// The adapter is usually gone by now, and its settings with it.
	_ = n.setSearch(nil)
	flush(n.logf)
	return err
}

// writeRules replaces tcd's NRPT rules with ones sending names to servers
// (none: just remove them).
func (n *nrpt) writeRules(names []string, servers []netip.Addr) error {
	base, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("dns: open NRPT: %w", err)
	}
	defer base.Close()

	var srv []string
	for _, s := range servers {
		srv = append(srv, s.String())
	}
	keep := map[string]bool{}
	for i := 0; len(names) > 0; i++ {
		chunk := names[:min(nrptMaxNames, len(names))]
		names = names[len(chunk):]
		name := fmt.Sprintf("%s%02x}", nrptKeyPrefix, i)
		keep[strings.ToLower(name)] = true
		if err := writeRule(base, name, chunk, strings.Join(srv, ";")); err != nil {
			return fmt.Errorf("dns: write NRPT rule: %w", err)
		}
	}

	existing, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return fmt.Errorf("dns: list NRPT rules: %w", err)
	}
	var errs []error
	for _, k := range existing {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, nrptKeyPrefix) && !keep[lk] {
			if err := registry.DeleteKey(base, k); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				errs = append(errs, fmt.Errorf("dns: remove NRPT rule %s: %w", k, err))
			}
		}
	}
	return errors.Join(errs...)
}

func writeRule(base registry.Key, name string, names []string, servers string) error {
	k, _, err := registry.CreateKey(base, name, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	for _, set := range []func() error{
		func() error { return k.SetDWordValue("Version", 2) },
		func() error { return k.SetStringsValue("Name", names) },
		func() error { return k.SetStringValue("GenericDNSServers", servers) },
		func() error { return k.SetDWordValue("ConfigOptions", 8) }, // use GenericDNSServers
		func() error { return k.SetStringValue("IPSECCARestriction", "") },
	} {
		if err := set(); err != nil {
			return err
		}
	}
	return nil
}

// setSearch puts the search domains on the tunnel adapter: the first as its
// DNS suffix, all as its search list. It also stops Windows registering the
// adapter's addresses in the LAN's DNS.
func (n *nrpt) setSearch(search []string) error {
	domain, err := windows.UTF16PtrFromString(firstOr(search, ""))
	if err != nil {
		return err
	}
	list, err := windows.UTF16PtrFromString(strings.Join(search, ","))
	if err != nil {
		return err
	}
	return winnet.SetInterfaceDNSSettings(n.guid, &winnet.DNSInterfaceSettings{
		Flags:  winnet.DNSSettingDomain | winnet.DNSSettingSearchList | winnet.DNSSettingRegistrationEnabled,
		Domain: domain, SearchList: list,
	})
}

func gpoRulesPresent() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptGPOPath, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(1)
	return len(names) > 0
}

func flush(logf func(string, ...any)) {
	if err := winnet.FlushResolverCache(); err != nil {
		logf("dns: flush cache: %v", err)
	}
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}
