//go:build linux && !android

package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

var resolvedStub = netip.MustParseAddr("127.0.0.53")

// NewOSConfigurator picks and returns the DNS configurator for this host.
func NewOSConfigurator(o OSOptions) (OSConfigurator, error) {
	if o.ResolvConf == "" {
		o.ResolvConf = "/etc/resolv.conf"
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Backup == "" {
		return nil, errors.New("dns: Backup path is required")
	}
	// Undo a resolv.conf rewrite left behind by a crash, before deciding
	// anything based on resolv.conf's contents.
	if b, err := os.ReadFile(o.Backup); err == nil {
		if err := os.WriteFile(o.ResolvConf, b, 0o644); err != nil {
			return nil, fmt.Errorf("dns: restore %s from %s: %w", o.ResolvConf, o.Backup, err)
		}
		os.Remove(o.Backup)
		o.Logf("dns: restored %s left modified by a previous run", o.ResolvConf)
	}
	mode := o.Mode
	if mode == "" || mode == ModeAuto {
		mode = ModeFile
		if usesResolvedStub(o.ResolvConf) {
			switch {
			case !sameNetns():
				// resolved runs in the host's network namespace and would
				// apply our settings to whichever host interface has our
				// tunnel's index; resolv.conf is the host's too.
				o.Logf("dns: not in the host's network namespace; leaving DNS alone (use -dns file with a private resolv.conf)")
				mode = ModeOff
			case resolvedActive():
				mode = ModeResolved
			}
		}
	}
	switch mode {
	case ModeOff:
		return NoopConfigurator{}, nil
	case ModeResolved:
		if !sameNetns() {
			return nil, errors.New("dns: systemd-resolved mode: tcd is not in the host's network namespace")
		}
		if o.Interface == "" {
			return nil, errors.New("dns: systemd-resolved mode needs an interface")
		}
		if _, err := exec.LookPath("resolvectl"); err != nil {
			return nil, fmt.Errorf("dns: systemd-resolved mode: %w", err)
		}
		return &resolved{ifname: o.Interface, logf: o.Logf}, nil
	case ModeFile:
		f := &fileConfig{path: o.ResolvConf, backup: o.Backup, logf: o.Logf}
		b, err := os.ReadFile(o.ResolvConf)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("dns: %w", err)
		}
		f.orig, f.origRaw = parseResolvConf(b), b
		return f, nil
	}
	return nil, fmt.Errorf("dns: unknown mode %q (want auto, %s, %s or off)", o.Mode, ModeResolved, ModeFile)
}

// usesResolvedStub reports whether resolv.conf points at systemd-resolved.
func usesResolvedStub(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && slices.Contains(parseResolvConf(b).Nameservers, resolvedStub)
}

// resolvedActive reports whether systemd-resolved is answering on D-Bus.
func resolvedActive() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "resolvectl", "--no-pager", "status").Run() == nil
}

// sameNetns reports whether we share PID 1's network namespace (where
// system services like resolved run). If it can't tell, it assumes so.
func sameNetns() bool {
	self, err1 := os.Readlink("/proc/self/ns/net")
	init, err2 := os.Readlink("/proc/1/ns/net")
	return err1 != nil || err2 != nil || self == init
}

// ---- systemd-resolved ----

type resolved struct {
	ifname  string
	logf    func(string, ...any)
	applied bool
}

func (r *resolved) Mode() string                { return ModeResolved }
func (r *resolved) SupportsSplitDNS() bool      { return true }
func (r *resolved) HostResolvers() []netip.Addr { return nil }

func (r *resolved) run(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "resolvectl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("resolvectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *resolved) Set(c OSConfig) error {
	if len(c.Nameservers) == 0 {
		return r.Close()
	}
	dnsArgs := []string{"dns", r.ifname}
	for _, ns := range c.Nameservers {
		dnsArgs = append(dnsArgs, ns.String())
	}
	// Search domains also route queries; "~" marks routing-only domains.
	domArgs := append([]string{"domain", r.ifname}, c.SearchDomains...)
	for _, d := range c.MatchDomains {
		if !slices.Contains(c.SearchDomains, d) {
			domArgs = append(domArgs, "~"+d)
		}
	}
	defaultRoute := "false"
	if len(c.MatchDomains) == 0 {
		domArgs = append(domArgs, "~.")
		defaultRoute = "true"
	}
	for _, args := range [][]string{dnsArgs, domArgs, {"default-route", r.ifname, defaultRoute}} {
		if err := r.run(args...); err != nil {
			return err
		}
	}
	r.applied = true
	// The resolver answers from the network map: plain DNS, unsigned, no
	// multicast name protocols on this link. Older resolved versions lack
	// some of these settings, so failures are only logged.
	for _, args := range [][]string{
		{"llmnr", r.ifname, "no"}, {"mdns", r.ifname, "no"},
		{"dnssec", r.ifname, "no"}, {"dnsovertls", r.ifname, "no"},
	} {
		if err := r.run(args...); err != nil {
			r.logf("dns: %v", err)
		}
	}
	if err := r.run("flush-caches"); err != nil {
		r.logf("dns: %v", err)
	}
	return nil
}

func (r *resolved) Close() error {
	if !r.applied {
		return nil
	}
	r.applied = false
	err := r.run("revert", r.ifname)
	if err != nil && strings.Contains(err.Error(), "No such device") {
		return nil // the interface is already gone, and its settings with it
	}
	return err
}

// ---- resolv.conf rewriting ----

const fileHeader = "# Written by tcd (TailConnect MagicDNS). The original is restored when tcd stops.\n"

type fileConfig struct {
	path, backup string
	logf         func(string, ...any)
	orig         resolvConf
	origRaw      []byte
	applied      bool
}

func (f *fileConfig) Mode() string           { return ModeFile }
func (f *fileConfig) SupportsSplitDNS() bool { return false }

func (f *fileConfig) HostResolvers() []netip.Addr { return slices.Clone(f.orig.Nameservers) }

func (f *fileConfig) Set(c OSConfig) error {
	if len(c.Nameservers) == 0 {
		return f.Close()
	}
	if !f.applied {
		// Keep a copy outside resolv.conf so a crash can be undone at the next start.
		if err := os.WriteFile(f.backup, f.origRaw, 0o600); err != nil {
			return fmt.Errorf("dns: back up %s: %w", f.path, err)
		}
	}
	rc := resolvConf{Nameservers: c.Nameservers, Search: slices.Clone(c.SearchDomains), Other: f.orig.Other}
	for _, s := range f.orig.Search {
		if !slices.Contains(rc.Search, s) {
			rc.Search = append(rc.Search, s)
		}
	}
	// WriteFile follows a symlinked resolv.conf and rewrites the target in
	// place, which also works when it is a bind mount.
	if err := os.WriteFile(f.path, rc.marshal(fileHeader), 0o644); err != nil {
		if !f.applied {
			os.Remove(f.backup)
		}
		return fmt.Errorf("dns: write %s: %w", f.path, err)
	}
	f.applied = true
	return nil
}

func (f *fileConfig) Close() error {
	if !f.applied {
		return nil
	}
	if err := os.WriteFile(f.path, f.origRaw, 0o644); err != nil {
		return fmt.Errorf("dns: restore %s: %w", f.path, err)
	}
	f.applied = false
	os.Remove(f.backup)
	return nil
}
