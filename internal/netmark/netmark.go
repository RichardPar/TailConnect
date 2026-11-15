// Package netmark marks tcd's own sockets (WireGuard/disco UDP, relay and
// control server connections) so they bypass the tunnel when this machine
// sends its internet traffic through an exit node: the exit node's default
// route sends everything else into the tunnel, and these sockets carry the
// tunnel itself.
package netmark

import (
	"net"
	"time"
)

// Mark is the firewall mark (SO_MARK) on tcd's sockets; Mask is the part of
// the mark that is ours. The router's policy rules send marked packets to
// the main routing table.
const (
	Mark = 0x7c0000
	Mask = 0xff0000
)

// Dialer returns a dialer whose connections are marked.
func Dialer(timeout, keepAlive time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: keepAlive, Control: Control}
}

// ListenConfig returns a ListenConfig whose sockets are marked.
func ListenConfig() *net.ListenConfig {
	return &net.ListenConfig{Control: Control}
}
