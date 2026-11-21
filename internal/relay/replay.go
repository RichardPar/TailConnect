package relay

import "sync"

// replayCache remembers the nonces of recent client hellos, so the same
// hello can't be accepted twice (what protects clients from before
// challenges). Each connection's hello has a fresh random nonce, so a
// repeat is a recording. It holds the last replayCacheSize nonces: enough
// for many hours of reconnects; a hello older than that, or one recorded
// before the relay restarted, could still be replayed, which is why
// clients ask for a challenge instead.
type replayCache struct {
	mu   sync.Mutex
	seen map[[24]byte]struct{}
	ring [][24]byte
	next int
}

const replayCacheSize = 1 << 16

// add records n, reporting false if it was already there.
func (c *replayCache) add(n [24]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[[24]byte]struct{})
		c.ring = make([][24]byte, replayCacheSize)
	}
	if _, ok := c.seen[n]; ok {
		return false
	}
	if len(c.seen) >= replayCacheSize {
		delete(c.seen, c.ring[c.next])
	}
	c.seen[n] = struct{}{}
	c.ring[c.next] = n
	c.next = (c.next + 1) % replayCacheSize
	return true
}
