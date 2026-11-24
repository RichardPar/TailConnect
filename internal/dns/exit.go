package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// An exit node resolves names for the machines that use it, so their DNS
// leaves from the exit node like the rest of their internet traffic rather
// than going to the resolvers of whatever network they are on.
//
// Clients (TUN.SetExitDNS) redirect the DNS queries their host sends to
// MagicDNS for names outside MagicDNS: the query packet is readdressed to
// the exit node's tunnel address, port ExitPort, and WireGuard carries it.
// The answer is readdressed back, so the host sees it come from MagicDNS.
// No socket of tcd's is involved, so this works where tcd's own sockets
// bypass the tunnel (Android excludes the app from its own VPN).
//
// The exit node (ExitServer) answers on its tunnel address, port ExitPort,
// for the machines allowed to use it as an exit node only.

// ExitPort is where exit nodes answer DNS. Not 53, which a DNS server on
// the exit node may already hold on every address.
const ExitPort = 41653

// ExitServer answers DNS queries from machines using this one as their
// exit node, forwarding them with its own resolver.
type ExitServer struct {
	r     *Resolver
	allow func(netip.Addr) bool
	logf  func(string, ...any)

	udp *net.UDPConn
	tcp *net.TCPListener

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ListenExit starts an ExitServer on addr (this machine's tunnel address),
// port ExitPort. allow reports whether a source address may ask.
func ListenExit(addr netip.Addr, r *Resolver, allow func(netip.Addr) bool, logf func(string, ...any)) (*ExitServer, error) {
	ap := netip.AddrPortFrom(addr, ExitPort)
	u, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	t, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(ap))
	if err != nil {
		u.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &ExitServer{r: r, allow: allow, logf: logf, udp: u, tcp: t, ctx: ctx, cancel: cancel}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s, nil
}

// Addr is where the server listens.
func (s *ExitServer) Addr() netip.AddrPort { return s.udp.LocalAddr().(*net.UDPAddr).AddrPort() }

func (s *ExitServer) Close() {
	s.cancel()
	s.udp.Close()
	s.tcp.Close()
	s.wg.Wait()
}

func (s *ExitServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.logf("dns: exit node: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		if !s.allow(from.Addr().Unmap()) {
			continue // not a machine that may use this exit node
		}
		q := append([]byte(nil), buf[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if resp := s.r.Query(s.ctx, q); resp != nil {
				s.udp.WriteToUDPAddrPort(resp, from)
			}
		}()
	}
}

func (s *ExitServer) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.logf("dns: exit node: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
		from, _ := netip.ParseAddrPort(c.RemoteAddr().String())
		if !s.allow(from.Addr().Unmap()) {
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			stop := context.AfterFunc(s.ctx, func() { c.Close() })
			defer stop()
			for {
				c.SetDeadline(time.Now().Add(30 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil {
					if !errors.Is(err, io.EOF) && s.ctx.Err() == nil {
						s.logf("dns: exit node: read from %v: %v", from, err)
					}
					return
				}
				resp := s.r.QueryTCP(s.ctx, q)
				if resp == nil || writeTCPMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}
