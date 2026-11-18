// Package protocol defines the wire types exchanged between TailConnect
// clients (tcd) and the coordination server (tc-control).
//
// Messages are JSON, exchanged over HTTP/2 inside a Noise IK channel (see
// internal/noise) that authenticates the client's machine key. Only GET /key
// and the /machine/noise upgrade are served in the clear.
package protocol

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"tailconnect/internal/key"
)

// CurrentVersion is the protocol version spoken by this build.
//
//	1  initial version
//	2  map streams may send deltas (MapResponse.Delta)
const CurrentVersion = 2

// DeltaVersion is the first version whose clients understand delta maps.
const DeltaVersion = 2

// MagicDNSAddr is the in-tunnel resolver address every client serves, and
// MagicDNSAddr6 its IPv6 equivalent (in the reserved part of the ULA range).
var (
	MagicDNSAddr  = netip.MustParseAddr("100.100.100.100")
	MagicDNSAddr6 = netip.MustParseAddr("fd7c:7c0e:a1e0::6464:6464")
)

type NodeID int64

// Hostinfo is self-reported, informational data about a device.
type Hostinfo struct {
	Hostname      string `json:",omitempty"`
	OS            string `json:",omitempty"` // "linux", "windows", "android"
	OSVersion     string `json:",omitempty"`
	ClientVersion string `json:",omitempty"`
}

// ServerKeyResponse is returned by GET /key.
type ServerKeyResponse struct {
	Version    int
	MachineKey key.MachinePublic
}

// RegisterRequest is sent to POST /machine/register to join the network or
// to rotate a node key.
type RegisterRequest struct {
	Version int
	// MachineKey is optional: the server takes the machine key from the Noise
	// channel and rejects a request whose MachineKey disagrees.
	MachineKey key.MachinePublic
	NodeKey    key.NodePublic
	DiscoKey   key.DiscoPublic
	AuthKey    string `json:",omitempty"` // pre-auth key; required for new (or deleted) machines
	Hostinfo   Hostinfo
}

type RegisterResponse struct {
	Node Node
}

// MapRequest is sent to POST /machine/map to report the client's current
// state and fetch the network map.
type MapRequest struct {
	Version   int
	NodeKey   key.NodePublic
	DiscoKey  key.DiscoPublic
	Endpoints []netip.AddrPort `json:",omitempty"`
	Hostinfo  *Hostinfo        `json:",omitempty"`
	// HomeRelay is the relay region where this node can be reached (0 = none).
	HomeRelay int `json:",omitempty"`
	// Stream asks the server to keep the response open and push a new
	// newline-delimited MapResponse whenever the map changes.
	Stream bool `json:",omitempty"`
	// OmitPeers (with Stream=false) is a "lite" update: the server records the
	// reported endpoints/hostinfo and replies with an empty body.
	OmitPeers bool `json:",omitempty"`
}

// LogoutRequest is sent to POST /machine/logout to remove the node from the network.
type LogoutRequest struct {
	NodeKey key.NodePublic
}

// MapResponse is the network map: who this node is, which peers it may talk
// to, and how to resolve names and reach relays.
type MapResponse struct {
	// KeepAlive messages carry no other fields; they only keep the stream alive.
	KeepAlive bool `json:",omitempty"`
	// Notice is a message for the device's user, e.g. that the account is
	// suspended (and therefore the map has no peers).
	Notice string `json:",omitempty"`

	Self   Node
	Peers  []Node
	DNS    DNSConfig
	Relays RelayMap

	// Delta marks an update to the previous map on the same stream (sent
	// only to clients of DeltaVersion or later): peers in PeersChanged were
	// added or replaced, peers in PeersRemoved are gone, and every other
	// field is unchanged and absent. The first map on a stream, and any map
	// whose self, DNS, relays or notice change, is a full map.
	Delta        bool     `json:",omitempty"`
	PeersChanged []Node   `json:",omitempty"`
	PeersRemoved []NodeID `json:",omitempty"`
}

// ApplyDelta returns the full map that delta d makes of the previous map
// prev. Peers stay ordered by ID, as in full maps.
func ApplyDelta(prev *MapResponse, d *MapResponse) *MapResponse {
	out := *prev
	gone := make(map[NodeID]bool, len(d.PeersRemoved)+len(d.PeersChanged))
	for _, id := range d.PeersRemoved {
		gone[id] = true
	}
	for _, n := range d.PeersChanged {
		gone[n.ID] = true
	}
	peers := make([]Node, 0, len(prev.Peers)+len(d.PeersChanged))
	for _, n := range prev.Peers {
		if !gone[n.ID] {
			peers = append(peers, n)
		}
	}
	peers = append(peers, d.PeersChanged...)
	slices.SortStableFunc(peers, func(a, b Node) int { return cmp.Compare(a.ID, b.ID) })
	out.Peers = peers
	return &out
}

// Node describes one device in the network as seen by a client.
type Node struct {
	ID   NodeID
	Name string // fully-qualified MagicDNS name, e.g. "laptop.acme.home.internal"
	// Aliases are further fully-qualified names that resolve to the machine
	// (e.g. "nas.acme.home.internal"). Reverse lookups give Name.
	Aliases   []string `json:",omitempty"`
	User      string
	NodeKey   key.NodePublic
	DiscoKey  key.DiscoPublic
	Addresses []netip.Prefix   // single-address prefixes (/32 and /128)
	Endpoints []netip.AddrPort `json:",omitempty"`
	HomeRelay int              `json:",omitempty"` // relay region ID
	// Shared: the machine belongs to another tenant and is in this map
	// because of a share (it is shared with us, or we are shared with it).
	Shared bool `json:",omitempty"`
	// NoInitiate: the machine may only reply to connections this machine
	// starts, apart from what Inbound allows; tcd's packet filter drops
	// anything else from it. Set for machines shared with our tenant
	// (sharing is one-way) and for peers the account's access rules limit.
	NoInitiate bool `json:",omitempty"`
	// Inbound (with NoInitiate) lists what the peer may still open
	// connections to on this machine, from the account's access rules.
	// Empty: nothing.
	Inbound []PortRange `json:",omitempty"`
	// Tags are the machine's access-rule tags (e.g. "server").
	Tags []string `json:",omitempty"`
	// ExitNode: the machine forwards internet traffic for its account's
	// machines, which may choose to send theirs through it. On Self, it
	// tells the machine to forward (and NAT) its peers' traffic. Only set on
	// peers of the same account that this machine may send anything to.
	ExitNode  bool `json:",omitempty"`
	Hostinfo  Hostinfo
	Created   time.Time
	LastSeen  *time.Time `json:",omitempty"`
	KeyExpiry *time.Time `json:",omitempty"`
}

// DNSConfig tells clients how to resolve names. With MagicDNS on, each
// client answers names under Domain from the network map at Resolver, and
// the OS sends queries for Domain (and reverse lookups for tunnel addresses)
// there. If Nameservers is set, all other queries go there too (through the
// in-tunnel resolver); otherwise the OS keeps its own resolvers for them.
type DNSConfig struct {
	MagicDNS bool
	// Domain is the base domain, e.g. "home.internal". A machine is
	// <name>.<tenant>.<Domain>, unless its tenant set its own domain.
	Domain string
	// Domains are all the domains this client answers and routes to
	// MagicDNS: Domain plus the tenant domains outside it (e.g.
	// "acme.internal") of this machine and its peers. Empty: just Domain
	// (servers from before tenant domains).
	Domains []string `json:",omitempty"`
	// Search domains for short names; the first is this machine's tenant
	// domain (e.g. "acme.home.internal"), so "laptop" finds its own laptop,
	// then the base domain, so "nas.globex" finds a machine shared by globex.
	Search      []string     `json:",omitempty"`
	Resolver    netip.Addr   // in-tunnel resolver (MagicDNSAddr)
	Nameservers []netip.Addr `json:",omitempty"` // upstream resolvers; empty = keep OS defaults
}

type RelayMap struct {
	Regions []RelayRegion `json:",omitempty"`
}

type RelayRegion struct {
	ID    int
	Code  string // short code, e.g. "lon"
	Name  string
	Nodes []RelayNode
}

type RelayNode struct {
	Name string
	// URL of the relay endpoint. A URL without scheme and host (e.g. "/relay")
	// is relative to the control server URL: the relay embedded in tc-control.
	URL string
	// STUN server for this region: HostName (default: the relay URL's host)
	// and STUNPort (0 = the region has no STUN server).
	HostName string `json:",omitempty"`
	STUNPort int    `json:",omitempty"`
}

// PortRange is a protocol and port range a peer may open connections to.
// Proto is "tcp", "udp", "icmp" (ping; ports unused) or "" for both TCP
// and UDP.
type PortRange struct {
	Proto string `json:",omitempty"`
	First uint16 `json:",omitempty"`
	Last  uint16 `json:",omitempty"`
}

// ErrorResponse is the body of any non-2xx response.
type ErrorResponse struct {
	Error string
}
