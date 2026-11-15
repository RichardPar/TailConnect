// Package protocol defines the wire types exchanged between TailConnect
// clients (tcd) and the coordination server (tc-control).
//
// Messages are JSON, exchanged over HTTP/2 inside a Noise IK channel (see
// internal/noise) that authenticates the client's machine key. Only GET /key
// and the /machine/noise upgrade are served in the clear.
package protocol

import (
	"net/netip"
	"time"

	"tailconnect/internal/key"
)

// CurrentVersion is the protocol version spoken by this build.
const CurrentVersion = 1

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

// DNSConfig tells clients how to resolve names. With MagicDNS on, each
// client answers names under Domain from the network map at Resolver, and
// the OS sends queries for Domain (and reverse lookups for tunnel addresses)
// there. If Nameservers is set, all other queries go there too (through the
// in-tunnel resolver); otherwise the OS keeps its own resolvers for them.
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
	Name string
	// URL of the relay endpoint. A URL without scheme and host (e.g. "/relay")
	// is relative to the control server URL: the relay embedded in tc-control.
	URL string
	// STUN server for this region: HostName (default: the relay URL's host)
	// and STUNPort (0 = the region has no STUN server).
	HostName string `json:",omitempty"`
	STUNPort int    `json:",omitempty"`
}

// ErrorResponse is the body of any non-2xx response.
type ErrorResponse struct {
	Error string
}
