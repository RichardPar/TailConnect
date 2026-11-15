// Package iplimit limits how often, and how much at once, each client IP
// may do something: sign in, open a control connection, retry a failed
// registration.
//
// Client IPs come from the TCP connection, so behind a reverse proxy every
// client would share the proxy's address (TailConnect does not use one).
package iplimit

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxTracked bounds memory: past it the table is reset, which at worst
// gives every client a fresh burst.
const maxTracked = 10000

// IP returns the client address of r without its port.
func IP(r *http.Request) string { return HostOf(r.RemoteAddr) }

// Client returns the limiting key for r's client: its IPv4 address, or for
// IPv6 its /64 network. One subscriber usually gets a whole /64, so keying
// by address would hand them billions of fresh allowances.
func Client(r *http.Request) string {
	h := HostOf(r.RemoteAddr)
	a, err := netip.ParseAddr(h)
	if err != nil {
		return h
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.WithZone("").Prefix(64)
	return p.String()
}

// HostOf strips the port from a "host:port" address.
func HostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// Rate allows each IP a burst of events, refilling one every interval.
// A nil *Rate allows everything.
type Rate struct {
	mu      sync.Mutex
	clients map[string]*rate.Limiter
	every   time.Duration
	burst   int
}

func NewRate(every time.Duration, burst int) *Rate {
	return &Rate{clients: map[string]*rate.Limiter{}, every: every, burst: burst}
}

func (l *Rate) get(ip string) *rate.Limiter {
	if len(l.clients) > maxTracked {
		l.clients = map[string]*rate.Limiter{}
	}
	lim, ok := l.clients[ip]
	if !ok {
		lim = rate.NewLimiter(rate.Every(l.every), l.burst)
		l.clients[ip] = lim
	}
	return lim
}

// Allow uses up one event for ip, reporting whether it was allowed.
func (l *Rate) Allow(ip string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.get(ip).Allow()
}

// Blocked reports whether ip has no events left, without using one. With
// Allow called only on failures, it limits failures but not successes.
func (l *Rate) Blocked(ip string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.get(ip).Tokens() < 1
}

// Count caps how many things (connections) each IP, and everyone together,
// may hold at once. A nil *Count allows everything.
type Count struct {
	mu       sync.Mutex
	held     map[string]int
	total    int
	perIP    int
	maxTotal int
}

func NewCount(perIP, total int) *Count {
	return &Count{held: map[string]int{}, perIP: perIP, maxTotal: total}
}

// Acquire takes one slot for ip. If it reports true, call Release when done.
func (c *Count) Acquire(ip string) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held[ip] >= c.perIP || c.total >= c.maxTotal {
		return false
	}
	c.held[ip]++
	c.total++
	return true
}

// Release gives back a slot taken by Acquire.
func (c *Count) Release(ip string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held[ip]--; c.held[ip] <= 0 {
		delete(c.held, ip)
	}
	c.total--
}
