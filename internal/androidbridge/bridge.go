//go:build linux

// Package androidbridge connects tcd, running as a child process of the
// Android app, to the app's VpnService: only the app can create the VPN
// interface, so tcd asks it for one and receives the interface's file
// descriptor over a Unix socket. The app also tells tcd about the
// underlying network (its DNS servers and local addresses), which an app
// process can't read itself on modern Android.
//
// Protocol: newline-delimited JSON messages over a stream socket that tcd
// listens on and the app connects to.
//
//	tcd → app  {"Type":"tun", "Addresses":[…], "Routes":[…], "DNS":[…], "Search":[…], "MTU":1280}
//	app → tcd  {"Type":"tun-reply", "OK":true}   with the interface's fd attached (SCM_RIGHTS)
//	tcd → app  {"Type":"close"}                  the tunnel stopped: close the interface
//	app → tcd  {"Type":"network", "DNS":[…], "Addresses":[…]}   the underlying network changed
package androidbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"

	"tailconnect/internal/protocol"
)

// Message is one protocol message (fields by type, see the package doc).
type Message struct {
	Type string

	// tun
	Addresses []netip.Prefix `json:",omitempty"`
	Routes    []netip.Prefix `json:",omitempty"`
	DNS       []netip.Addr   `json:",omitempty"` // tun: the VPN's DNS servers; network: the underlying ones
	Search    []string       `json:",omitempty"`
	MTU       int            `json:",omitempty"`

	// tun-reply
	OK    bool   `json:",omitempty"`
	Error string `json:",omitempty"`

	// network: DNS (above), and this device's addresses on the underlying
	// network in Addresses (e.g. 192.168.1.20/24)
}

// Network is what the app reports about the underlying network: its DNS
// servers, and this device's addresses on it, with their prefix length.
type Network struct {
	DNS       []netip.Addr
	Addresses []netip.Prefix
}

type Bridge struct {
	ln   *net.UnixListener
	logf func(string, ...any)

	mu      sync.Mutex
	conn    *net.UnixConn
	connCh  chan struct{} // closed (and replaced) when an app connects
	net     Network
	replies chan reply
}

type reply struct {
	msg Message
	fd  int // -1 if none
}

// Listen starts the bridge on a Unix socket at path.
func Listen(path string, logf func(string, ...any)) (*Bridge, error) {
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	b := &Bridge{ln: ln, logf: logf, connCh: make(chan struct{}), replies: make(chan reply, 1)}
	go b.accept()
	return b, nil
}

// SetNetwork sets the initial underlying network (before the app connects).
func (b *Bridge) SetNetwork(n Network) {
	b.mu.Lock()
	b.net = n
	b.mu.Unlock()
}

// updateNetwork records a network change the app reported. A report without
// usable DNS servers (Android sends some while a network is changing, and
// MagicDNS's own address is no use as an upstream) keeps the last known
// servers: with none, MagicDNS would refuse every name outside the tunnel.
func (b *Bridge) updateNetwork(n Network) {
	n.DNS = slices.DeleteFunc(n.DNS, func(a netip.Addr) bool {
		a = a.Unmap()
		return !a.IsValid() || a == protocol.MagicDNSAddr || a == protocol.MagicDNSAddr6
	})
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(n.DNS) == 0 && len(b.net.DNS) > 0 {
		b.logf("android: network update without DNS servers; keeping %v", b.net.DNS)
		n.DNS = b.net.DNS
	}
	b.net = n
}

// Network returns what the app last reported.
func (b *Bridge) Network() Network {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.net
}

func (b *Bridge) Close() error { return b.ln.Close() }

func (b *Bridge) accept() {
	for {
		c, err := b.ln.AcceptUnix()
		if err != nil {
			return
		}
		b.mu.Lock()
		if b.conn != nil {
			b.conn.Close() // the newest app connection wins
		}
		b.conn = c
		close(b.connCh)
		b.connCh = make(chan struct{})
		b.mu.Unlock()
		b.logf("android: app connected")
		go b.read(c)
	}
}

// read handles messages from the app, with any attached file descriptors.
func (b *Bridge) read(c *net.UnixConn) {
	defer func() {
		b.mu.Lock()
		if b.conn == c {
			b.conn = nil
		}
		b.mu.Unlock()
		c.Close()
	}()
	buf := make([]byte, 64<<10)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	var pending []byte
	var fds []int
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
		if err != nil {
			for _, fd := range fds {
				syscall.Close(fd)
			}
			return
		}
		if oobn > 0 {
			if cms, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
				for _, cm := range cms {
					if got, err := syscall.ParseUnixRights(&cm); err == nil {
						fds = append(fds, got...)
					}
				}
			}
		}
		pending = append(pending, buf[:n]...)
		for {
			i := indexByte(pending, '\n')
			if i < 0 {
				break
			}
			line := pending[:i]
			pending = pending[i+1:]
			var m Message
			if err := json.Unmarshal(line, &m); err != nil {
				b.logf("android: bad message from app: %v", err)
				continue
			}
			switch m.Type {
			case "network":
				b.updateNetwork(Network{DNS: m.DNS, Addresses: m.Addresses})
			case "tun-reply":
				fd := -1
				if m.OK && len(fds) > 0 {
					fd, fds = fds[0], fds[1:]
				}
				select {
				case b.replies <- reply{m, fd}:
				default:
					if fd >= 0 {
						syscall.Close(fd) // nobody asked
					}
				}
			}
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func (b *Bridge) send(m Message) error {
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return errors.New("the app is not connected")
	}
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Write(append(line, '\n'))
	return err
}

// RequestTUN asks the app for a VPN interface and returns its fd. It waits
// for the app to connect if it hasn't yet.
func (b *Bridge) RequestTUN(ctx context.Context, req Message) (int, error) {
	req.Type = "tun"
	for {
		b.mu.Lock()
		connected, ch := b.conn != nil, b.connCh
		b.mu.Unlock()
		if connected {
			break
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return -1, fmt.Errorf("waiting for the app: %w", ctx.Err())
		}
	}
	// Drop a stale reply, if any.
	select {
	case r := <-b.replies:
		if r.fd >= 0 {
			syscall.Close(r.fd)
		}
	default:
	}
	if err := b.send(req); err != nil {
		return -1, err
	}
	select {
	case r := <-b.replies:
		if !r.msg.OK || r.fd < 0 {
			if r.fd >= 0 {
				syscall.Close(r.fd)
			}
			msg := r.msg.Error
			if msg == "" {
				msg = "no interface received"
			}
			return -1, errors.New("the app could not create the VPN: " + msg)
		}
		return r.fd, nil
	case <-ctx.Done():
		return -1, fmt.Errorf("waiting for the VPN interface: %w", ctx.Err())
	}
}

// NotifyClosed tells the app the tunnel stopped.
func (b *Bridge) NotifyClosed() {
	if err := b.send(Message{Type: "close"}); err != nil {
		b.logf("android: tell the app the tunnel stopped: %v", err)
	}
}
