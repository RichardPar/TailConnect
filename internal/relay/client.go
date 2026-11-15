package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/box"

	"tailconnect/internal/key"
	"tailconnect/internal/netmark"
)

// RecvFunc is called for each packet received from the relay. pkt is only
// valid for the duration of the call.
type RecvFunc func(src key.NodePublic, pkt []byte)

type ClientOptions struct {
	URL     string // http(s)://host[:port]/relay
	NodeKey key.NodePrivate
	Recv    RecvFunc
	Logf    func(format string, args ...any)
	// Dial overrides how TCP connections are made (tests, socket protection on Android).
	Dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	TLSConfig *tls.Config
}

// Client maintains a connection to one relay server, reconnecting with
// backoff. Send never blocks. Packets sent while (re)connecting are queued
// and delivered once connected unless they are older than maxQueueAge;
// packets are dropped when the queue is full (WireGuard retransmits).
type Client struct {
	opts ClientOptions
	u    *url.URL

	sendq chan queued

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	connected atomic.Bool
	mu        sync.Mutex
	lastErr   error
}

// maxQueueAge bounds how stale a queued packet may be when it is finally sent.
const maxQueueAge = 3 * time.Second

type queued struct {
	frame []byte
	at    time.Time
}

func NewClient(opts ClientOptions) (*Client, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("relay: bad URL %q", opts.URL)
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Dial == nil {
		opts.Dial = netmark.Dialer(10*time.Second, 30*time.Second).DialContext
	}
	c := &Client{opts: opts, u: u, sendq: make(chan queued, 256), done: make(chan struct{})}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	go c.run()
	return c, nil
}

func (c *Client) URL() string { return c.opts.URL }

// Connected reports whether the client currently has a live relay connection.
func (c *Client) Connected() bool { return c.connected.Load() }

// LastError is the most recent connection error, if any.
func (c *Client) LastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// Close stops the client and waits for it to finish.
func (c *Client) Close() {
	c.cancel()
	<-c.done
}

// Send queues pkt for dst. It copies pkt.
func (c *Client) Send(dst key.NodePublic, pkt []byte) error {
	if c.ctx.Err() != nil {
		return errors.New("relay: client closed")
	}
	frame := make([]byte, 5+keyLen+len(pkt))
	frame[0] = byte(frameSendPacket)
	putLen(frame[1:5], keyLen+len(pkt))
	dk := dst.Raw()
	copy(frame[5:], dk[:])
	copy(frame[5+keyLen:], pkt)
	select {
	case c.sendq <- queued{frame, time.Now()}:
		return nil
	default:
		return errors.New("relay: send queue full")
	}
}

func (c *Client) run() {
	defer close(c.done)
	backoff := 500 * time.Millisecond
	for c.ctx.Err() == nil {
		start := time.Now()
		err := c.connectAndServe()
		c.connected.Store(false)
		if c.ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		c.lastErr = err
		c.mu.Unlock()
		if time.Since(start) > 30*time.Second {
			backoff = 500 * time.Millisecond // it was a healthy connection
		}
		c.opts.Logf("relay %s: %v (reconnecting in %v)", c.u.Host, err, backoff)
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (c *Client) dial(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	host := c.u.Host
	if c.u.Port() == "" {
		port := "80"
		if c.u.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(c.u.Hostname(), port)
	}
	conn, err := c.opts.Dial(ctx, "tcp", host)
	if err != nil {
		return nil, nil, err
	}
	if c.u.Scheme == "https" {
		cfg := c.opts.TLSConfig.Clone()
		if cfg == nil {
			cfg = &tls.Config{}
		}
		if cfg.ServerName == "" {
			cfg.ServerName = c.u.Hostname()
		}
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, nil, err
		}
		conn = tc
	}
	req, _ := http.NewRequest("GET", c.u.String(), nil)
	req.Header.Set("Upgrade", UpgradeProtocol)
	req.Header.Set("Connection", "Upgrade")
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		conn.Close()
		return nil, nil, fmt.Errorf("relay upgrade refused: %s: %s", resp.Status, b)
	}
	return conn, br, nil
}

func (c *Client) connectAndServe() error {
	ctx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	conn, br, err := c.dial(ctx)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(c.ctx, func() { conn.Close() })
	defer stop()

	// Handshake.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	t, b, err := readFrame(br, nil)
	if err != nil {
		return err
	}
	if t != frameServerKey || len(b) != len(magic)+keyLen || string(b[:len(magic)]) != magic {
		return errors.New("not a TailConnect relay")
	}
	var serverPub [32]byte
	copy(serverPub[:], b[len(magic):])

	info, _ := json.Marshal(clientInfo{Version: version})
	nonce, err := generateNonce()
	if err != nil {
		return err
	}
	priv := c.opts.NodeKey.Raw()
	sealed := box.Seal(nil, info, &nonce, &serverPub, &priv)
	pub := c.opts.NodeKey.Public().Raw()
	if err := writeFrame(conn, frameClientInfo, pub[:], nonce[:], sealed); err != nil {
		return err
	}
	t, b, err = readFrame(br, nil)
	if err != nil {
		return err
	}
	switch t {
	case frameServerInfo:
	case frameError:
		return fmt.Errorf("relay refused: %s", b)
	default:
		return fmt.Errorf("unexpected frame %d during handshake", t)
	}
	conn.SetReadDeadline(time.Time{})
	c.connected.Store(true)
	c.mu.Lock()
	c.lastErr = nil
	c.mu.Unlock()
	c.opts.Logf("relay %s: connected", c.u.Host)

	// Writer.
	werr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				werr <- nil
				return
			case q := <-c.sendq:
				if time.Since(q.at) > maxQueueAge {
					continue // queued during an outage; too stale to be useful
				}
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.Write(q.frame); err != nil {
					conn.Close()
					werr <- err
					return
				}
			}
		}
	}()

	// Reader. The server sends keep-alives every 60s; treat 3 minutes of
	// silence as a dead connection.
	var buf []byte
	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Minute))
		t, b, err := readFrame(br, buf)
		if err != nil {
			select {
			case e := <-werr:
				if e != nil {
					return e
				}
			default:
			}
			return err
		}
		buf = b[:0]
		switch t {
		case frameRecvPacket:
			if len(b) < keyLen {
				continue
			}
			var sk [32]byte
			copy(sk[:], b[:keyLen])
			if c.opts.Recv != nil {
				c.opts.Recv(key.PublicFromRaw[key.NodeKind](sk), b[keyLen:])
			}
		case frameError:
			return fmt.Errorf("relay error: %s", b)
		}
	}
}
