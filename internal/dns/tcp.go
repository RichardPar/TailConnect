package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DNS over TCP: TCP packets the host sends to the resolver addresses go
// into a small in-process TCP/IP stack (gVisor's, as used by userspace
// mode) that owns only those addresses; its replies are written back into
// the host. The stack is started on the first TCP packet.

const (
	tcpIdleTimeout = 10 * time.Second // per connection, between queries
	maxTCPConns    = 64
)

type tcpStack struct {
	dev  tun.Device
	tnet *netstack.Net
	lns  []net.Listener
	sem  chan struct{}
}

// isTCPToResolver reports whether pkt is a TCP segment for a resolver
// address (any port: the stack answers other ports with a reset).
func (t *TUN) isTCPToResolver(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		return len(pkt) >= 20 && t.addr4.IsValid() && pkt[9] == 6 && netip.AddrFrom4([4]byte(pkt[16:20])) == t.addr4
	case 6:
		return len(pkt) >= 40 && t.addr6.IsValid() && pkt[6] == 6 && netip.AddrFrom16([16]byte(pkt[24:40])) == t.addr6
	}
	return false
}

// toTCPStack hands pkt to the TCP stack, starting it if needed.
func (t *TUN) toTCPStack(pkt []byte) {
	s := t.tcp()
	if s == nil {
		return
	}
	buf := make([]byte, writeOffset+len(pkt))
	copy(buf[writeOffset:], pkt)
	if _, err := s.dev.Write([][]byte{buf}, writeOffset); err != nil && t.ctx.Err() == nil {
		t.logf("dns: tcp stack: %v", err)
	}
}

func (t *TUN) tcp() *tcpStack {
	t.tcpOnce.Do(func() {
		s, err := t.startTCP()
		if err != nil {
			t.logf("dns: DNS over TCP unavailable: %v", err)
			return
		}
		t.tcpStack = s
	})
	return t.tcpStack
}

func (t *TUN) startTCP() (*tcpStack, error) {
	var addrs []netip.Addr
	for _, a := range []netip.Addr{t.addr4, t.addr6} {
		if a.IsValid() {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("no resolver address")
	}
	mtu, err := t.Device.MTU()
	if err != nil || mtu <= 0 {
		mtu = 1280
	}
	dev, tnet, err := netstack.CreateNetTUN(addrs, nil, mtu)
	if err != nil {
		return nil, err
	}
	s := &tcpStack{dev: dev, tnet: tnet, sem: make(chan struct{}, maxTCPConns)}
	for _, a := range addrs {
		ln, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(a, 53))
		if err != nil {
			s.close()
			return nil, err
		}
		s.lns = append(s.lns, ln)
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.acceptTCP(s, ln)
		}()
	}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.pumpTCP(s)
	}()
	return s, nil
}

func (s *tcpStack) close() {
	for _, ln := range s.lns {
		ln.Close()
	}
	s.dev.Close()
}

// pumpTCP writes the stack's outgoing packets into the host.
func (t *TUN) pumpTCP(s *tcpStack) {
	bufs := [][]byte{make([]byte, writeOffset+65535)}
	sizes := []int{0}
	for {
		n, err := s.dev.Read(bufs, sizes, writeOffset)
		if err != nil {
			return // closed
		}
		if n == 0 {
			continue
		}
		pkt := bufs[0][:writeOffset+sizes[0]]
		if _, err := t.Device.Write([][]byte{pkt}, writeOffset); err != nil && t.ctx.Err() == nil {
			t.logf("dns: write tcp packet: %v", err)
		}
	}
}

func (t *TUN) acceptTCP(s *tcpStack, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
		default:
			c.Close() // too many connections
			continue
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer func() { <-s.sem }()
			t.serveTCP(c)
		}()
	}
}

// serveTCP answers length-prefixed queries on one connection, in order,
// until the client closes it or goes idle.
func (t *TUN) serveTCP(c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(t.ctx, func() { c.Close() })
	defer stop()
	for {
		c.SetDeadline(time.Now().Add(tcpIdleTimeout))
		q, err := readTCPMsg(c)
		if err != nil {
			return
		}
		resp := t.r.QueryTCP(t.ctx, q)
		if resp == nil {
			return
		}
		c.SetDeadline(time.Now().Add(tcpIdleTimeout))
		if err := writeTCPMsg(c, resp); err != nil {
			return
		}
	}
}
