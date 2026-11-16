package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"tailconnect/internal/localapi"
	"tailconnect/internal/trayicon"
)

func TestMakeView(t *testing.T) {
	st := &localapi.Status{
		State: localapi.StateRunning, ControlURL: "https://tc.example:8443", Domain: "richard.home.internal",
		DNS: &localapi.DNSStatus{Domain: "richard.home.internal", Base: "home.internal"},
		Self: &localapi.PeerStatus{Name: "pc.richard.home.internal", Addresses: []netip.Prefix{
			netip.MustParsePrefix("fd7c::8/128"), netip.MustParsePrefix("100.64.0.8/32")}},
		Peers: []localapi.PeerStatus{
			{Name: "devbox.richard.home.internal", OS: "linux", Active: true,
				Addresses:       []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7c::1/128")},
				CurrentEndpoint: netip.MustParseAddrPort("192.168.10.205:41641"), LatencyMS: 4.6},
			{Name: "nas.alice.home.internal", Shared: true, NoInitiate: true, Relay: 1,
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")}},
		},
	}
	v := makeView(st, nil)
	if v.Icon != trayicon.Connected || v.Title != "Connected" || !v.CanDown || v.CanUp {
		t.Errorf("running: %+v", v)
	}
	if v.Self != "pc  100.64.0.8" || v.SelfIP != "100.64.0.8" {
		t.Errorf("self %q %q", v.Self, v.SelfIP)
	}
	if p := v.Peers[0]; p.Name != "devbox" || p.Addr() != "100.64.0.1" || p.IPv6 != "fd7c::1" || p.Connection != "direct, 5 ms" {
		t.Errorf("peer 0: %+v", p)
	}
	if p := v.Peers[1]; p.Name != "nas.alice" || p.Connection != "via relay; idle; shared with you" {
		t.Errorf("peer 1: %+v", p)
	}
	if !strings.Contains(v.Tip(), "pc  100.64.0.8") {
		t.Errorf("tip %q", v.Tip())
	}

	st.Notice = "this machine is waiting for approval"
	if v := makeView(st, nil); v.Icon != trayicon.Problem || v.Detail != st.Notice {
		t.Errorf("notice: %+v", v)
	}
	st.Notice, st.State = "", localapi.StateStopped
	if v := makeView(st, nil); v.Icon != trayicon.Disconnected || !v.CanUp || v.CanDown {
		t.Errorf("stopped: %+v", v)
	}
	st.Domain, st.DNS = "", nil // as when stopped
	if v := makeView(st, nil); v.Self != "pc  100.64.0.8" {
		t.Errorf("stopped self %q", v.Self)
	}
	st.State = localapi.StateNeedsLogin
	if v := makeView(st, nil); v.LoggedIn || v.CanUp {
		t.Errorf("needs login: %+v", v)
	}
	if v := makeView(nil, errors.New("no pipe")); v.Icon != trayicon.Problem {
		t.Errorf("error: %+v", v)
	}
	long := makeView(&localapi.Status{State: localapi.StateRunning, Notice: strings.Repeat("x", 300)}, nil)
	if n := len([]rune(long.Tip())); n > 127 {
		t.Errorf("tip is %d runes", n)
	}
}
