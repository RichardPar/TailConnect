package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// RemotePolicy asks a control server whom a standalone relay may serve,
// through the relay API (protocol.RelayAPIPath). Answers are cached per
// pair of machines until the control server's policy changes, so the
// per-packet check is a map lookup; the first packet between a new pair
// waits for one request to the control server.
//
// If the control server is unreachable, cached answers stay in force and
// unknown pairs and new connections are refused (fail closed).
type RemotePolicy struct {
	base  string // control URL + RelayAPIPath
	token string
	hc    *http.Client
	log   *slog.Logger

	mu    sync.RWMutex
	gen   int64
	cache map[pairKey]bool

	flight   sync.Mutex
	inflight map[pairKey]*lookup

	requestsOK, requestsFailed atomic.Int64
}

// pairKey is an unordered pair of machines (the policy is symmetric).
type pairKey [64]byte

func makePair(a, b key.NodePublic) pairKey {
	ra, rb := a.Raw(), b.Raw()
	if bytes.Compare(ra[:], rb[:]) > 0 {
		ra, rb = rb, ra
	}
	var p pairKey
	copy(p[:32], ra[:])
	copy(p[32:], rb[:])
	return p
}

type lookup struct {
	done    chan struct{}
	allowed bool
}

// maxCachedPairs bounds the cache; it is cleared when full.
const maxCachedPairs = 200_000

// lookupTimeout bounds how long a packet between a new pair waits.
const lookupTimeout = 3 * time.Second

// NewRemotePolicy returns a policy backed by the control server at
// controlURL (e.g. https://ctl.example.com), authenticating with token.
func NewRemotePolicy(controlURL, token string, log *slog.Logger) *RemotePolicy {
	return &RemotePolicy{
		base:     strings.TrimRight(controlURL, "/") + protocol.RelayAPIPath,
		token:    token,
		hc:       &http.Client{Timeout: 40 * time.Second},
		log:      log,
		cache:    map[pairKey]bool{},
		inflight: map[pairKey]*lookup{},
	}
}

// errUnauthorized: the control server rejected the relay's token.
var errUnauthorized = errors.New("control server rejected the relay token")

func (p *RemotePolicy) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		p.requestsFailed.Add(1)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.requestsFailed.Add(1)
	} else {
		p.requestsOK.Add(1)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		var e protocol.ErrorResponse
		json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return fmt.Errorf("control server: %s: %s", resp.Status, e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Check verifies that the control server is reachable and accepts the
// token, and loads its policy version.
func (p *RemotePolicy) Check(ctx context.Context) error {
	var resp protocol.RelayAllowedResponse
	if err := p.call(ctx, http.MethodPost, "allowed", protocol.RelayAllowedRequest{Pairs: [][2]key.NodePublic{}}, &resp); err != nil {
		return err
	}
	p.observe(resp.Generation)
	return nil
}

// Authorize is a relay.AuthorizeFunc: the control server decides.
func (p *RemotePolicy) Authorize(ctx context.Context, nk key.NodePublic) error {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	var resp protocol.RelayAuthorizeResponse
	if err := p.call(ctx, http.MethodPost, "authorize", protocol.RelayAuthorizeRequest{Node: nk}, &resp); err != nil {
		p.log.Warn("relay: asking the control server failed", "err", err)
		return errors.New("control server unavailable")
	}
	p.observe(resp.Generation)
	if !resp.Allowed {
		return errors.New(resp.Reason)
	}
	return nil
}

// Allow is a relay.AllowFunc.
func (p *RemotePolicy) Allow(a, b key.NodePublic) bool {
	pk := makePair(a, b)
	p.mu.RLock()
	allowed, ok := p.cache[pk]
	p.mu.RUnlock()
	if ok {
		return allowed
	}
	return p.lookup(pk, a, b)
}

// lookup asks the control server about one pair; concurrent lookups of the
// same pair share one request.
func (p *RemotePolicy) lookup(pk pairKey, a, b key.NodePublic) bool {
	p.flight.Lock()
	if l := p.inflight[pk]; l != nil {
		p.flight.Unlock()
		<-l.done
		return l.allowed
	}
	l := &lookup{done: make(chan struct{})}
	p.inflight[pk] = l
	p.flight.Unlock()
	defer func() {
		p.flight.Lock()
		delete(p.inflight, pk)
		p.flight.Unlock()
		close(l.done)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	var resp protocol.RelayAllowedResponse
	err := p.call(ctx, http.MethodPost, "allowed", protocol.RelayAllowedRequest{Pairs: [][2]key.NodePublic{{a, b}}}, &resp)
	if err != nil || len(resp.Allowed) != 1 {
		p.log.Warn("relay: asking the control server failed; dropping", "err", err)
		return false // not cached: ask again on the next packet
	}
	l.allowed = resp.Allowed[0]
	p.observe(resp.Generation)
	p.mu.Lock()
	if resp.Generation == p.gen {
		if len(p.cache) >= maxCachedPairs {
			clear(p.cache)
		}
		p.cache[pk] = l.allowed
	}
	p.mu.Unlock()
	return l.allowed
}

// observe moves to a newer policy version, forgetting older answers.
func (p *RemotePolicy) observe(gen int64) {
	p.mu.Lock()
	if gen > p.gen {
		p.gen = gen
		clear(p.cache)
	}
	p.mu.Unlock()
}

// Run watches the control server for policy changes until ctx ends.
func (p *RemotePolicy) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		p.mu.RLock()
		gen := p.gen
		p.mu.RUnlock()
		var resp protocol.RelayWatchResponse
		err := p.call(ctx, http.MethodGet, "watch?generation="+strconv.FormatInt(gen, 10), nil, &resp)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log.Warn("relay: watching the control server failed", "err", err, "retry", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(2*backoff, 30*time.Second)
			continue
		}
		backoff = time.Second
		if resp.Generation != gen {
			// Newer, or older if the control server restarted with its
			// clock set back: either way, earlier answers are suspect.
			p.mu.Lock()
			p.gen = resp.Generation
			clear(p.cache)
			p.mu.Unlock()
		}
	}
}
