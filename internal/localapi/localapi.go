// Package localapi is the local control interface between the tc CLI (or a
// GUI) and the tcd daemon: HTTP over a Unix socket (named pipe on Windows,
// milestone 6).
//
//	GET  /localapi/v1/status   anyone with socket access
//	POST /localapi/v1/up       privileged
//	POST /localapi/v1/down     privileged
//	POST /localapi/v1/logout   privileged
//
// "Privileged" means the caller's UID (from SO_PEERCRED) is root or the
// daemon's own UID.
package localapi

import (
	"net/netip"
	"time"

	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// Daemon states.
const (
	StateNeedsLogin = "NeedsLogin" // not registered (or removed by the server)
	StateStopped    = "Stopped"    // registered but `tc down`
	StateStarting   = "Starting"   // connecting to control / bringing up the tunnel
	StateRunning    = "Running"    // receiving network maps; tunnel configured
)

type UpRequest struct {
	ControlURL string            `json:",omitempty"` // required on first login
	AuthKey    string            `json:",omitempty"` // required to register a new machine
	Hostname   string            `json:",omitempty"` // default: OS hostname
	ServerKey  key.MachinePublic `json:",omitempty"` // pin explicitly instead of fetching /key
	// ExitNode chooses the exit node for this machine's internet traffic:
	// a machine's name or tunnel address, "" for none. nil = unchanged.
	ExitNode *string `json:",omitempty"`
}

type Status struct {
	State      string
	Error      string `json:",omitempty"` // last error, if any
	Notice     string `json:",omitempty"` // message from the control server (e.g. account suspended)
	ControlURL string `json:",omitempty"`
	Domain     string `json:",omitempty"` // MagicDNS suffix
	TUN        string `json:",omitempty"`
	ListenPort uint16 `json:",omitempty"`
	// HomeRelay is the relay region this node is reachable through, and
	// RelayConnected whether that connection is up.
	HomeRelay      int        `json:",omitempty"`
	RelayConnected bool       `json:",omitempty"`
	DNS            *DNSStatus `json:",omitempty"`
	// FilterDropped counts packets refused because a shared machine tried to
	// open a connection to this one.
	FilterDropped int64       `json:",omitempty"`
	ExitNode      *ExitStatus `json:",omitempty"`
	Self          *PeerStatus
	Peers         []PeerStatus
}

// DNSStatus describes MagicDNS on this node.
type DNSStatus struct {
	Domain   string     // this machine's domain: short names are <host>.Domain
	Base     string     // all MagicDNS names end in Base (e.g. other tenants' shared machines)
	Resolver netip.Addr // in-tunnel resolver
	// HostConfig is how the OS is pointed at the resolver: "systemd-resolved",
	// "file" (resolv.conf) or "off" (query the resolver directly).
	HostConfig string
	SplitDNS   bool   // only MagicDNS names go to the resolver
	Error      string `json:",omitempty"` // last failure configuring the OS
}

// ExitStatus describes exit nodes on this machine (nil in Status when it
// neither uses nor is one).
type ExitStatus struct {
	Chosen       string `json:",omitempty"` // the exit node chosen with tc up --exit-node
	Using        string `json:",omitempty"` // MagicDNS name of the exit node in use
	Error        string `json:",omitempty"` // why Chosen isn't in use: internet traffic goes direct
	Serving      bool   `json:",omitempty"` // this machine is an exit node
	ServingError string `json:",omitempty"` // why it isn't forwarding although it should
}

type PeerStatus struct {
	Name      string // FQDN
	HostName  string
	User      string
	OS        string `json:",omitempty"`
	Addresses []netip.Prefix
	NodeKey   key.NodePublic
	// Endpoints are the addresses the peer reported. CurrentEndpoint is the
	// direct address in use; when there is none, traffic goes via relay
	// region Relay.
	Endpoints       []netip.AddrPort `json:",omitempty"`
	CurrentEndpoint netip.AddrPort   `json:",omitempty"`
	Relay           int              `json:",omitempty"`
	LatencyMS       float64          `json:",omitempty"` // round trip on the direct path
	LastHandshake   *time.Time       `json:",omitempty"`
	RxBytes         int64
	TxBytes         int64
	// Active means a WireGuard handshake completed within the last 3 minutes.
	Active bool
	// Shared: another tenant's machine, in this network because of a share.
	// NoInitiate: it may only reply to connections this machine opens.
	Shared     bool `json:",omitempty"`
	NoInitiate bool `json:",omitempty"`
	// Inbound (with NoInitiate) is what the peer may still open here.
	Inbound []protocol.PortRange `json:",omitempty"`
	Tags    []string             `json:",omitempty"`
	// ExitNode: this machine may send its internet traffic through the peer.
	ExitNode bool `json:",omitempty"`
	// KeyExpiry is when the machine must re-authenticate (nil = never).
	KeyExpiry *time.Time `json:",omitempty"`
}

// Backend is implemented by the daemon.
type Backend interface {
	Status() Status
	Up(UpRequest) error
	Down() error
	Logout() error
}
