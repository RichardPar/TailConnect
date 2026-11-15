package acl

import (
	"testing"

	"tailconnect/internal/protocol"
)

func TestParseFormatPorts(t *testing.T) {
	for in, want := range map[string]string{
		"*": "*", "": "*", "22": "22", "22, 443": "22,443", "8000-8100": "8000-8100",
		"tcp:22,udp:53": "tcp:22,udp:53", "UDP:1000-2000": "udp:1000-2000", "icmp,22": "icmp,22", "22,*": "*",
	} {
		a, err := ParsePorts(in)
		if err != nil {
			t.Errorf("ParsePorts(%q): %v", in, err)
			continue
		}
		if got := FormatPorts(a); got != want {
			t.Errorf("ParsePorts(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"0", "70000", "100-50", "sctp:5", "abc", ",", "22-", "tcp:"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) accepted", bad)
		}
	}
}

func TestSelectors(t *testing.T) {
	for _, ok := range []string{"*", "tag:server", "laptop", "db-1"} {
		if CheckSelector(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "tag:", "tag:Bad", "Laptop", "a b", "group:x"} {
		if CheckSelector(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPolicy(t *testing.T) {
	laptop := Machine{Name: "laptop", Tags: []string{"staff"}}
	server := Machine{Name: "server", Tags: []string{"web", "db"}}
	printer := Machine{Name: "printer"}

	var none *Policy
	if !none.Allowed(laptop, server).All || !none.Connected(laptop, printer) {
		t.Fatal("no rules must allow everything")
	}
	p, err := Compile([]Rule{
		{Src: "tag:staff", Dst: "tag:web", Ports: "tcp:443"},
		{Src: "tag:staff", Dst: "server", Ports: "22,icmp"},
		{Src: "*", Dst: "printer", Ports: "tcp:631"},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := p.Allowed(laptop, server)
	want := []protocol.PortRange{{Proto: "tcp", First: 443, Last: 443}, {First: 22, Last: 22}, {Proto: "icmp"}}
	if a.All || len(a.Ranges) != 3 || a.Ranges[0] != want[0] || a.Ranges[1] != want[1] || a.Ranges[2] != want[2] {
		t.Fatalf("laptop → server: %+v", a)
	}
	if !p.Allowed(server, laptop).None() {
		t.Fatal("server → laptop should be denied (no rule)")
	}
	if !p.Connected(server, laptop) {
		t.Fatal("server and laptop are connected (laptop → server allowed)")
	}
	if FormatPorts(p.Allowed(server, printer)) != "tcp:631" {
		t.Fatalf("anyone → printer: %+v", p.Allowed(server, printer))
	}
	if p.Connected(server, Machine{Name: "other"}) {
		t.Fatal("server and an unmentioned machine must not be connected")
	}
	if _, err := Compile([]Rule{{Src: "tag:", Dst: "*"}}); err == nil {
		t.Fatal("bad selector compiled")
	}
	if all, _ := Compile([]Rule{{Src: "*", Dst: "*"}}); !all.Allowed(printer, laptop).All {
		t.Fatal("* → * on * must allow everything")
	}
}
