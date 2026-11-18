package main

import (
	"fmt"
	"net/netip"
	"strings"

	"tailconnect/internal/acl"
	"tailconnect/internal/localapi"
	"tailconnect/internal/trayicon"
)

// titleNoService is the title when tcd can't be reached.
const titleNoService = "TailConnect service not running"

// view is what the tray and the window show for one status, worked out
// without any Win32 so it can be tested anywhere.
type view struct {
	Icon     trayicon.State
	Title    string // "Connected", "Disconnected", ...
	Detail   string // why, when something needs attention ("" if nothing)
	Self     string // "surfacebook  100.64.0.8"
	SelfIP   string // "100.64.0.8"
	Server   string
	DNS      string // "richard.home.internal"
	CanUp    bool   // Connect makes sense
	CanDown  bool   // Disconnect makes sense
	LoggedIn bool
	Peers    []peerRow
}

type peerRow struct {
	Name, IPv4, IPv6, OS, User, Connection string
	Active                                 bool
}

// Addr is the address to copy for the peer: IPv4 if it has one.
func (p peerRow) Addr() string {
	if p.IPv4 != "" {
		return p.IPv4
	}
	return p.IPv6
}

func makeView(st *localapi.Status, err error) view {
	if err != nil || st == nil {
		return view{Icon: trayicon.Problem, Title: titleNoService, Detail: serviceHint}
	}
	v := view{Server: st.ControlURL, LoggedIn: st.State != localapi.StateNeedsLogin}
	if st.DNS != nil {
		v.DNS = st.DNS.Domain
	}
	switch st.State {
	case localapi.StateRunning:
		v.Icon, v.Title, v.CanDown = trayicon.Connected, "Connected", true
	case localapi.StateStarting:
		v.Icon, v.Title, v.CanDown = trayicon.Disconnected, "Connecting…", true
	case localapi.StateStopped:
		v.Icon, v.Title, v.CanUp = trayicon.Disconnected, "Disconnected", true
	case localapi.StateNeedsLogin:
		v.Icon, v.Title = trayicon.Disconnected, "Not logged in"
		v.Detail = "Log in with your network's server address and an auth key."
	default:
		v.Icon, v.Title = trayicon.Disconnected, st.State
	}
	switch {
	case st.Notice != "":
		v.Icon, v.Detail = trayicon.Problem, st.Notice
	case st.Error != "":
		v.Icon, v.Detail = trayicon.Problem, st.Error
	case st.DNS != nil && st.DNS.Error != "":
		v.Detail = "DNS: " + st.DNS.Error
	}
	if st.Self != nil {
		v.SelfIP = firstAddr(st.Self.Addresses, true)
		name := shortName(st.Self.Name, st)
		if st.Domain == "" { // not connected: the domain isn't known, but this is our own name
			name, _, _ = strings.Cut(name, ".")
		}
		v.Self = strings.TrimSpace(name + "  " + v.SelfIP)
	}
	for _, p := range st.Peers {
		v.Peers = append(v.Peers, peerRow{
			Name: shortName(p.Name, st), IPv4: firstAddr(p.Addresses, true), IPv6: firstAddr(p.Addresses, false),
			OS: p.OS, User: p.User, Connection: connection(p), Active: p.Active,
		})
	}
	return v
}

// Tip is the tray icon's tooltip (at most 127 characters).
func (v view) Tip() string {
	t := "TailConnect: " + v.Title
	if v.Self != "" && v.Title == "Connected" {
		t += "\n" + v.Self
	} else if v.Detail != "" {
		t += "\n" + v.Detail
	}
	if r := []rune(t); len(r) > 127 {
		t = string(r[:126]) + "…"
	}
	return t
}

func connection(p localapi.PeerStatus) string {
	var parts []string
	switch {
	case p.CurrentEndpoint.IsValid():
		s := "direct"
		if p.LatencyMS > 0 {
			s += fmt.Sprintf(", %.0f ms", p.LatencyMS)
		}
		parts = append(parts, s)
	case p.Relay != 0:
		parts = append(parts, "via relay")
	case len(p.Endpoints) == 0:
		parts = append(parts, "offline")
	}
	if !p.Active {
		parts = append(parts, "idle")
	}
	switch {
	case p.Shared && p.NoInitiate && len(p.Inbound) > 0:
		parts = append(parts, "has access to this machine on "+acl.FormatPorts(acl.Access{Ranges: p.Inbound}))
	case p.Shared && p.NoInitiate:
		parts = append(parts, "shared with you")
	case p.Shared:
		parts = append(parts, "has access to this machine")
	}
	return strings.Join(parts, "; ")
}

func firstAddr(ps []netip.Prefix, v4 bool) string {
	for _, p := range ps {
		if p.Addr().Is4() == v4 {
			return p.Addr().String()
		}
	}
	return ""
}

// shortName drops this machine's own domain ("laptop"), or else the base
// domain ("nas.acme" for another account's shared machine), as tc does.
func shortName(fqdn string, st *localapi.Status) string {
	if st.Domain != "" && strings.HasSuffix(fqdn, "."+st.Domain) {
		return strings.TrimSuffix(fqdn, "."+st.Domain)
	}
	if st.DNS != nil && st.DNS.Base != "" {
		return strings.TrimSuffix(fqdn, "."+st.DNS.Base)
	}
	return fqdn
}
