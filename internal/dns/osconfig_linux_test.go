//go:build linux && !android

package dns

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFileConfigurator(t *testing.T) {
	dir := t.TempDir()
	rc, backup := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "backup")
	orig := "nameserver 192.168.1.1\nsearch lan\noptions edns0\n"
	os.WriteFile(rc, []byte(orig), 0o644)

	c, err := NewOSConfigurator(OSOptions{Mode: ModeFile, ResolvConf: rc, Backup: backup})
	if err != nil {
		t.Fatal(err)
	}
	if c.SupportsSplitDNS() || !slices.Equal(c.HostResolvers(), []netip.Addr{netip.MustParseAddr("192.168.1.1")}) {
		t.Fatalf("split=%v host resolvers=%v", c.SupportsSplitDNS(), c.HostResolvers())
	}
	cfg := OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("100.100.100.100")}, SearchDomains: []string{"tc.internal"}}
	if err := c.Set(cfg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(rc)
	if !strings.HasSuffix(string(b), "nameserver 100.100.100.100\nsearch tc.internal lan\noptions edns0\n") {
		t.Fatalf("rewritten resolv.conf:\n%s", b)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("no backup while active: %v", err)
	}

	// Simulate a crash: a new configurator restores the original first.
	c2, err := NewOSConfigurator(OSOptions{Mode: ModeFile, ResolvConf: rc, Backup: backup})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(rc); string(b) != orig {
		t.Fatalf("not restored after crash:\n%s", b)
	}
	if !slices.Equal(c2.HostResolvers(), c.HostResolvers()) {
		t.Fatalf("host resolvers after recovery: %v", c2.HostResolvers())
	}
	if err := c2.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if err := c2.Close(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(rc); string(b) != orig {
		t.Fatalf("not restored on close:\n%s", b)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup left behind: %v", err)
	}
}

func TestAutoPicksFile(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, "resolv.conf")
	os.WriteFile(rc, []byte("nameserver 10.0.0.1\n"), 0o644)
	c, err := NewOSConfigurator(OSOptions{ResolvConf: rc, Backup: filepath.Join(dir, "b"), Interface: "tc0"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode() != ModeFile {
		t.Fatalf("mode %s, want file for a resolv.conf not managed by systemd-resolved", c.Mode())
	}
}
