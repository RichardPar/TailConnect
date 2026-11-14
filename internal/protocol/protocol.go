// Package protocol defines the wire types exchanged between TailConnect
// clients (tcd) and the coordination server (tc-control).
//
// Messages are JSON. In milestone 1 they travel over plain HTTP(S); milestone 2
// moves /machine/* onto a Noise IK channel authenticated by the machine key.
package protocol

import (
	"net/netip"
	"time"

	"tailconnect/internal/key"
)

// CurrentVersion is the protocol version spoken by this build.
const CurrentVersion = 1

// MagicDNSAddr is the in-tunnel resolver address every client serves.
var MagicDNSAddr = netip.MustParseAddr("100.100.100.100")

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
	Version    int
	MachineKey key.MachinePublic
	NodeKey    key.NodePublic
	DiscoKey   key.DiscoPublic
	AuthKey    string `json:",omitempty"` // pre-auth key; required for new machines
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
	// Stream asks the server to keep the response open and push updates.
	// Not yet implemented (milestone 2); the server currently returns one map.
	Stream bool `json:",omitempty"`
}

// MapResponse is the network map: who this node is, which peers it may talk
// to, and how to resolve names and reach relays.
type MapResponse struct {
	Self   Node
	Peers  []Node
	DNS    DNSConfig
	Relays RelayMap
}

// Node describes one device in the network as seen by a client.
type Node struct {
	ID        NodeID
	Name      string // fully-qualified MagicDNS name, e.g. "laptop.home.internal"
	User      string
	NodeKey   key.NodePublic
	DiscoKey  key.DiscoPublic
	Addresses []netip.Prefix   // single-address prefixes (/32 and /128)
	Endpoints []netip.AddrPort `json:",omitempty"`
	HomeRelay int              `json:",omitempty"` // relay region ID
	Hostinfo  Hostinfo
	Created   time.Time
	LastSeen  *time.Time `json:",omitempty"`
	KeyExpiry *time.Time `json:",omitempty"`
}

type DNSConfig struct {
	MagicDNS    bool
	Domain      string       // base domain, e.g. "home.internal"
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
	Name      string
	HostName  string
	STUNPort  int `json:",omitempty"` // 0 = default 3478
	RelayPort int `json:",omitempty"` // 0 = default 443
}

// ErrorResponse is the body of any non-2xx response.
type ErrorResponse struct {
	Error string
}
