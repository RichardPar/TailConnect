package engine

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"tailconnect/internal/protocol"
)

func node(id int, name, host, addr string, exit bool) protocol.Node {
	return protocol.Node{
		ID: protocol.NodeID(id), Name: name, Hostinfo: protocol.Hostinfo{Hostname: host},
		Addresses: []netip.Prefix{netip.MustParsePrefix(addr + "/32")}, ExitNode: exit,
	}
}

func TestFindExitNode(t *testing.T) {
	nm := &protocol.MapResponse{
		Self: node(1, "laptop.acme.tc.internal", "laptop", "100.64.0.1", false),
		Peers: []protocol.Node{
			node(2, "gw.acme.tc.internal", "raspberrypi", "100.64.0.2", true),
			node(3, "nas.acme.tc.internal", "nas", "100.64.0.3", false),
		},
	}
	for _, pref := range []string{"gw", "GW", "gw.acme.tc.internal", "gw.acme.tc.internal.", "raspberrypi", "100.64.0.2"} {
		if n, err := FindExitNode(nm, pref); err != nil || n.ID != 2 {
			t.Errorf("%q: %v, %v", pref, n.ID, err)
		}
	}
	if _, err := FindExitNode(nm, "nas"); err == nil || !strings.Contains(err.Error(), "not an exit node") {
		t.Errorf("nas: %v", err)
	}
	if _, err := FindExitNode(nm, "printer"); !errors.Is(err, ErrNoSuchMachine) {
		t.Errorf("printer: %v", err)
	}
	nm.Self.ExitNode = true
	if _, err := FindExitNode(nm, "gw"); err == nil || !strings.Contains(err.Error(), "itself an exit node") {
		t.Errorf("from an exit node: %v", err)
	}
}
