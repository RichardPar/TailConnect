// Package dns implements MagicDNS: a resolver that every client serves
// inside its own tunnel at 100.100.100.100, answering for names in the
// network map, plus the per-OS glue that points the system's DNS at it.
//
// The resolver is reached by intercepting packets on the TUN device (see
// TUN), so it needs no socket, works identically on every platform and can
// only be queried by the local host: peers' packets arrive on the other
// side of WireGuard and never reach it.
package dns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TTL of MagicDNS answers. Addresses are stable for a node's lifetime; names
// change only when an administrator renames a node.
const TTL = 300

// maxUDPSize bounds responses: the tunnel MTU (1280) minus IPv6 and UDP headers.
const maxUDPSize = 1232

// maxInflight bounds concurrently forwarded queries.
const maxInflight = 64

// forwardTimeout is how long each upstream gets to answer.
const forwardTimeout = 2 * time.Second

// Config is what the resolver answers.
type Config struct {
	// Domain is the MagicDNS suffix, e.g. "tc.internal" (no trailing dot).
	Domain string
	// Domains are further suffixes answered locally (tenants' own domains,
	// e.g. "acme.internal").
	Domains []string
	// Hosts maps lowercase fully-qualified names (no trailing dot) under
	// Domain or Domains to their addresses.
	Hosts map[string][]netip.Addr
	// Aliases are further names, like Hosts, that are not used to answer
	// reverse lookups (those give the Hosts name).
	Aliases map[string][]netip.Addr
	// ReversePrefixes are the address ranges whose reverse (PTR) lookups are
	// answered locally (the tunnel's address pools).
	ReversePrefixes []netip.Prefix
	// Upstream resolvers for every other name. Empty: HostUpstream is asked.
	Upstream []netip.AddrPort
	// HostUpstream (if set) returns the host's own resolvers, asked at each
	// forwarded query when Upstream is empty, so a network change (Android
	// reports one whenever Wi-Fi or mobile data changes) takes effect at
	// once rather than at the next network map. Neither: queries are refused.
	HostUpstream func() []netip.AddrPort
}

type Resolver struct {
	logf func(string, ...any)
	sem  chan struct{}
	// dial is used to reach upstream resolvers (tests override it).
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	warnedNoUpstream atomic.Bool // logged once until upstreams are known again

	mu      sync.RWMutex
	cfg     Config
	domains []string                // "tc.internal." etc., lowercase
	hosts   map[string][]netip.Addr // keys with trailing dot
	ptr     map[netip.Addr]string   // address → FQDN with trailing dot
}

func NewResolver(logf func(string, ...any)) *Resolver {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var d net.Dialer
	return &Resolver{logf: logf, sem: make(chan struct{}, maxInflight), dial: d.DialContext}
}

// SetConfig replaces what the resolver answers.
func (r *Resolver) SetConfig(c Config) {
	hosts := make(map[string][]netip.Addr, len(c.Hosts)+len(c.Aliases))
	for name, addrs := range c.Aliases {
		hosts[canonical(name)] = addrs
	}
	ptr := map[netip.Addr]string{}
	for name, addrs := range c.Hosts {
		fq := canonical(name)
		hosts[fq] = addrs
		for _, a := range addrs {
			ptr[a.Unmap()] = fq
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg, r.hosts, r.ptr = c, hosts, ptr
	r.domains = nil
	for _, d := range append([]string{c.Domain}, c.Domains...) {
		if d != "" && !slices.Contains(r.domains, canonical(d)) {
			r.domains = append(r.domains, canonical(d))
		}
	}
}

// canonical lowercases a name and gives it a trailing dot.
func canonical(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// Query answers one DNS message received over UDP. It returns nil when the
// query is not worth answering (unparseable, or a response). Answers too
// big for the client are truncated (TC bit), so it retries over TCP.
func (r *Resolver) Query(ctx context.Context, q []byte) []byte { return r.query(ctx, q, false) }

// QueryTCP answers one DNS message received over TCP: answers may be up to
// 64 KB, and forwarded queries go upstream over TCP too.
func (r *Resolver) QueryTCP(ctx context.Context, q []byte) []byte { return r.query(ctx, q, true) }

// maxTCPSize is the largest DNS message over TCP (16-bit length prefix).
const maxTCPSize = 65535

func (r *Resolver) query(ctx context.Context, q []byte, tcp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil
	}
	questions, err := p.AllQuestions()
	if err != nil {
		return errorReply(h, nil, dnsmessage.RCodeFormatError, false)
	}
	edns, size := clientUDPSize(&p)
	if tcp {
		size = maxTCPSize
	}
	if h.OpCode != 0 {
		return errorReply(h, questions, dnsmessage.RCodeNotImplemented, edns)
	}
	if len(questions) != 1 {
		return errorReply(h, questions, dnsmessage.RCodeFormatError, edns)
	}
	qn := questions[0]
	name := strings.ToLower(qn.Name.String())

	r.mu.RLock()
	local := r.isLocalLocked(name)
	var answers []dnsmessage.Resource
	rcode := dnsmessage.RCodeSuccess
	if local {
		answers, rcode = r.answerLocked(qn, name)
	}
	upstream, hostUpstream := r.cfg.Upstream, r.cfg.HostUpstream
	r.mu.RUnlock()

	if !local {
		if len(upstream) == 0 && hostUpstream != nil {
			upstream = hostUpstream()
		}
		if len(upstream) == 0 {
			if r.warnedNoUpstream.CompareAndSwap(false, true) {
				r.logf("dns: no upstream resolvers known; refusing names outside MagicDNS (like %s)", qn.Name)
			}
			return errorReply(h, questions, dnsmessage.RCodeRefused, edns)
		}
		r.warnedNoUpstream.Store(false)
		return r.forward(ctx, h, questions, q, upstream, size, edns, tcp)
	}
	return buildReply(h, questions, answers, rcode, edns, size)
}

// isLocalLocked reports whether name (lowercase, with trailing dot) is ours:
// under the MagicDNS domain, or a reverse lookup in a tunnel address pool.
func (r *Resolver) isLocalLocked(name string) bool {
	for _, d := range r.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	if a, ok := parseReverse(name); ok {
		for _, p := range r.cfg.ReversePrefixes {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

func (r *Resolver) answerLocked(q dnsmessage.Question, name string) ([]dnsmessage.Resource, dnsmessage.RCode) {
	hdr := func(t dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: q.Name, Type: t, Class: dnsmessage.ClassINET, TTL: TTL}
	}
	if a, ok := parseReverse(name); ok {
		target, found := r.ptr[a]
		if !found {
			return nil, dnsmessage.RCodeNameError
		}
		if q.Type != dnsmessage.TypePTR && q.Type != dnsmessage.TypeALL {
			return nil, dnsmessage.RCodeSuccess
		}
		n, err := dnsmessage.NewName(target)
		if err != nil {
			return nil, dnsmessage.RCodeServerFailure
		}
		return []dnsmessage.Resource{{Header: hdr(dnsmessage.TypePTR), Body: &dnsmessage.PTRResource{PTR: n}}}, dnsmessage.RCodeSuccess
	}
	addrs, found := r.hosts[name]
	if !found {
		if slices.Contains(r.domains, name) {
			return nil, dnsmessage.RCodeSuccess // the apex exists but has no records we serve
		}
		return nil, dnsmessage.RCodeNameError
	}
	var out []dnsmessage.Resource
	for _, a := range addrs {
		switch {
		case a.Is4() && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL):
			out = append(out, dnsmessage.Resource{Header: hdr(dnsmessage.TypeA), Body: &dnsmessage.AResource{A: a.As4()}})
		case a.Is6() && (q.Type == dnsmessage.TypeAAAA || q.Type == dnsmessage.TypeALL):
			out = append(out, dnsmessage.Resource{Header: hdr(dnsmessage.TypeAAAA), Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
		}
	}
	return out, dnsmessage.RCodeSuccess
}

// clientUDPSize reads the EDNS0 OPT record, if any, from the additional
// section and returns the response size the client accepts.
func clientUDPSize(p *dnsmessage.Parser) (edns bool, size int) {
	size = 512
	if err := p.SkipAllAnswers(); err != nil {
		return false, size
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return false, size
	}
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			return edns, size
		}
		if rh.Type == dnsmessage.TypeOPT {
			edns = true
			// The OPT record's class field carries the UDP payload size.
			size = max(512, min(int(rh.Class), maxUDPSize))
		}
		if err := p.SkipAdditional(); err != nil {
			return edns, size
		}
	}
}

func replyHeader(h dnsmessage.Header, rcode dnsmessage.RCode) dnsmessage.Header {
	return dnsmessage.Header{
		ID: h.ID, Response: true, OpCode: h.OpCode, Authoritative: true,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode,
	}
}

// errorReply answers with rcode. It echoes at most the first question
// (servers answer one per query), so a query stuffed with questions can't
// make it larger than the client accepts.
func errorReply(h dnsmessage.Header, qs []dnsmessage.Question, rcode dnsmessage.RCode, edns bool) []byte {
	hh := replyHeader(h, rcode)
	hh.Authoritative = false
	return build(hh, qs[:min(len(qs), 1)], nil, edns)
}

// buildReply builds a response, truncating (TC bit, no answers) if it would
// exceed the client's size limit.
func buildReply(h dnsmessage.Header, qs []dnsmessage.Question, ans []dnsmessage.Resource, rcode dnsmessage.RCode, edns bool, size int) []byte {
	hh := replyHeader(h, rcode)
	b := build(hh, qs, ans, edns)
	if len(b) > size {
		hh.Truncated = true
		b = build(hh, qs, nil, edns)
	}
	return b
}

func build(h dnsmessage.Header, qs []dnsmessage.Question, ans []dnsmessage.Resource, edns bool) []byte {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), h)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return nil
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil
	}
	for _, a := range ans {
		var err error
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(a.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(a.Header, *body)
		case *dnsmessage.PTRResource:
			err = b.PTRResource(a.Header, *body)
		}
		if err != nil {
			return nil
		}
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			return nil
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(maxUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
			return nil
		}
		if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// forward relays the query to each upstream in turn until one answers.
func (r *Resolver) forward(ctx context.Context, h dnsmessage.Header, qs []dnsmessage.Question, q []byte, upstream []netip.AddrPort, size int, edns, tcp bool) []byte {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		return errorReply(h, qs, dnsmessage.RCodeServerFailure, edns)
	}
	var lastErr error
	for _, up := range upstream {
		var resp []byte
		var err error
		if tcp {
			resp, err = r.exchangeTCP(ctx, up, q, h.ID)
		} else {
			resp, err = r.exchange(ctx, up, q, h.ID)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if len(resp) > size {
			return truncate(resp, size)
		}
		return resp
	}
	r.logf("dns: forward %s: %v", qs[0].Name, lastErr)
	return errorReply(h, qs, dnsmessage.RCodeServerFailure, edns)
}

func (r *Resolver) exchange(ctx context.Context, up netip.AddrPort, q []byte, id uint16) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	c, err := r.dial(ctx, "udp", up.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		var p dnsmessage.Parser
		rh, err := p.Start(buf[:n])
		if err != nil || !rh.Response || rh.ID != id {
			continue // stray or spoofed packet
		}
		return append([]byte(nil), buf[:n]...), nil
	}
}

// exchangeTCP asks up over TCP (length-prefixed messages, RFC 1035 4.2.2).
func (r *Resolver) exchangeTCP(ctx context.Context, up netip.AddrPort, q []byte, id uint16) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	c, err := r.dial(ctx, "tcp", up.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := writeTCPMsg(c, q); err != nil {
		return nil, err
	}
	resp, err := readTCPMsg(c)
	if err != nil {
		return nil, err
	}
	var p dnsmessage.Parser
	if rh, err := p.Start(resp); err != nil || !rh.Response || rh.ID != id {
		return nil, errors.New("bad response from upstream")
	}
	return resp, nil
}

// readTCPMsg reads one length-prefixed DNS message.
func readTCPMsg(c io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, int(l[0])<<8|int(l[1]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return b, nil
}

// writeTCPMsg writes one length-prefixed DNS message.
func writeTCPMsg(c io.Writer, b []byte) error {
	if len(b) > maxTCPSize {
		return errors.New("DNS message too long")
	}
	_, err := c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
	return err
}

// truncate turns an upstream response that is too big for the client into
// header + question with the TC bit set, so the client retries over TCP.
func truncate(resp []byte, size int) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil
	}
	h.Truncated = true
	b := build(h, qs, nil, false)
	if len(b) > size {
		return nil
	}
	return b
}

var errNotReverse = errors.New("not a reverse name")

// parseReverse parses "4.3.2.1.in-addr.arpa." or a full 32-nibble ip6.arpa
// name (lowercase, trailing dot) into an address.
func parseReverse(name string) (netip.Addr, bool) {
	a, err := parseReverseErr(name)
	return a, err == nil
}

func parseReverseErr(name string) (netip.Addr, error) {
	if s, ok := strings.CutSuffix(name, ".in-addr.arpa."); ok {
		parts := strings.Split(s, ".")
		if len(parts) != 4 {
			return netip.Addr{}, errNotReverse
		}
		var b [4]byte
		for i, p := range parts {
			v, err := strconv.ParseUint(p, 10, 8)
			if err != nil || (len(p) > 1 && p[0] == '0') {
				return netip.Addr{}, errNotReverse
			}
			b[3-i] = byte(v)
		}
		return netip.AddrFrom4(b), nil
	}
	if s, ok := strings.CutSuffix(name, ".ip6.arpa."); ok {
		parts := strings.Split(s, ".")
		if len(parts) != 32 {
			return netip.Addr{}, errNotReverse
		}
		var b [16]byte
		for i, p := range parts {
			if len(p) != 1 {
				return netip.Addr{}, errNotReverse
			}
			v, err := strconv.ParseUint(p, 16, 8)
			if err != nil {
				return netip.Addr{}, errNotReverse
			}
			nib := 31 - i
			if nib%2 == 0 {
				b[nib/2] |= byte(v) << 4
			} else {
				b[nib/2] |= byte(v)
			}
		}
		return netip.AddrFrom16(b), nil
	}
	return netip.Addr{}, errNotReverse
}

// ReverseZones returns the reverse-lookup domains covering p, for routing
// PTR queries to the resolver: /8, /16 or /24 boundaries for IPv4 (so a /10
// becomes 64 zones) and nibble boundaries for IPv6.
func ReverseZones(p netip.Prefix) []string {
	p = p.Masked()
	if p.Addr().Is4() {
		bits := max(8, min((p.Bits()+7)/8*8, 24))
		count := 1
		if bits > p.Bits() {
			count = 1 << (bits - p.Bits())
		}
		var out []string
		base := p.Addr().As4()
		start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
		for i := 0; i < count; i++ {
			v := start + uint32(i)<<(32-bits)
			octets := []string{}
			for o := 0; o < bits/8; o++ {
				octets = append([]string{strconv.Itoa(int(v >> (24 - 8*o) & 0xff))}, octets...)
			}
			out = append(out, strings.Join(octets, ".")+".in-addr.arpa")
		}
		return out
	}
	nibbles := (p.Bits() + 3) / 4
	b := p.Addr().As16()
	var parts []string
	for i := nibbles - 1; i >= 0; i-- {
		v := b[i/2]
		if i%2 == 0 {
			v >>= 4
		}
		parts = append(parts, strconv.FormatUint(uint64(v&0xf), 16))
	}
	// Prefixes that are not on a nibble boundary would need several zones;
	// TailConnect's pools (/48) are, so keep it simple.
	return []string{strings.Join(parts, ".") + ".ip6.arpa"}
}
