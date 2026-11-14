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
}

type Status struct {
	State      string
	Error      string `json:",omitempty"` // last error, if any
	ControlURL string `json:",omitempty"`
	Domain     string `json:",omitempty"` // MagicDNS suffix
	TUN        string `json:",omitempty"`
	ListenPort uint16 `json:",omitempty"`
	Self       *PeerStatus
	Peers      []PeerStatus
}

type PeerStatus struct {
	Name      string // FQDN
	HostName  string
	User      string
	OS        string `json:",omitempty"`
	Addresses []netip.Prefix
	NodeKey   key.NodePublic
	// Endpoints are the addresses the peer reported; CurrentEndpoint is where
	// WireGuard is actually sending.
	Endpoints       []netip.AddrPort `json:",omitempty"`
	CurrentEndpoint netip.AddrPort   `json:",omitempty"`
	LastHandshake   *time.Time       `json:",omitempty"`
	RxBytes         int64
	TxBytes         int64
	// Active means a WireGuard handshake completed within the last 3 minutes.
	Active bool
}

// Backend is implemented by the daemon.
type Backend interface {
	Status() Status
	Up(UpRequest) error
	Down() error
	Logout() error
}
