// Package controlclient is the client side of the tc-control protocol: it
// dials the server, upgrades to the Noise channel and speaks HTTP/2 over it.
package controlclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"tailconnect/internal/key"
	"tailconnect/internal/netmark"
	"tailconnect/internal/noise"
	"tailconnect/internal/protocol"
	"tailconnect/internal/tlspin"
)

// HTTPError is a non-2xx response from the server.
type HTTPError struct {
	Code int
	Msg  string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("control: %d %s", e.Code, e.Msg) }

// IsUnauthorized reports whether err means the node must re-register
// (e.g. it was deleted on the server, or the auth key was rejected).
func IsUnauthorized(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Code == http.StatusUnauthorized
}

// FetchServerKey retrieves the server's public machine key from GET /key.
// Over HTTPS this is authenticated by TLS; over plain HTTP it is trust-on-first-use.
func FetchServerKey(ctx context.Context, serverURL string, hc *http.Client) (key.MachinePublic, error) {
	if hc == nil {
		hc = HTTPClient(nil)
	}
	u, err := parseServerURL(serverURL)
	if err != nil {
		return key.MachinePublic{}, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", u.JoinPath("/key").String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		if u.Scheme == "https" {
			err = tlspin.Explain(ctx, err, hostPort(u), u.Hostname())
		}
		return key.MachinePublic{}, fmt.Errorf("fetch server key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return key.MachinePublic{}, fmt.Errorf("fetch server key: HTTP %d", resp.StatusCode)
	}
	var kr protocol.ServerKeyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&kr); err != nil {
		return key.MachinePublic{}, fmt.Errorf("fetch server key: %w", err)
	}
	if kr.MachineKey.IsZero() {
		return key.MachinePublic{}, errors.New("fetch server key: server returned no key")
	}
	return kr.MachineKey, nil
}

// HTTPClient is a client for the control server's plain HTTP endpoints
// (like /key), with tlsConfig for HTTPS (nil = the usual checks).
func HTTPClient(tlsConfig *tls.Config) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = netmark.Dialer(15*time.Second, 30*time.Second).DialContext
	tr.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}

// hostPort is u's host with its port, defaulting by scheme.
func hostPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

func parseServerURL(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(s, "/"))
	if err != nil {
		return nil, fmt.Errorf("bad server URL %q: %w", s, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("bad server URL %q: scheme must be http or https", s)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("bad server URL %q: missing host", s)
	}
	return u, nil
}

type Options struct {
	ServerURL  string
	ServerKey  key.MachinePublic // pinned server machine key (required)
	MachineKey key.MachinePrivate
	TLSConfig  *tls.Config // optional (e.g. custom roots in tests)
	// Dial overrides how TCP connections are made (optional).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client holds at most one Noise+HTTP/2 connection and redials as needed.
// It is safe for concurrent use; requests are multiplexed on the connection.
type Client struct {
	opts Options
	u    *url.URL

	mu sync.Mutex
	cc *http2.ClientConn
}

func New(opts Options) (*Client, error) {
	u, err := parseServerURL(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	if opts.ServerKey.IsZero() || opts.MachineKey.IsZero() {
		return nil, errors.New("controlclient: ServerKey and MachineKey are required")
	}
	if opts.Dial == nil {
		opts.Dial = netmark.Dialer(15*time.Second, 30*time.Second).DialContext
	}
	return &Client{opts: opts, u: u}, nil
}

// Close drops the current connection. The client can still be used afterwards.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil {
		c.cc.Close()
		c.cc = nil
	}
}

func (c *Client) conn(ctx context.Context) (*http2.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cc != nil && c.cc.CanTakeNewRequest() {
		return c.cc, nil
	}
	if c.cc != nil {
		c.cc.Close()
		c.cc = nil
	}
	cc, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.cc = cc
	return cc, nil
}

func (c *Client) dial(ctx context.Context) (*http2.ClientConn, error) {
	host := c.u.Host
	if c.u.Port() == "" {
		if c.u.Scheme == "https" {
			host = net.JoinHostPort(c.u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(c.u.Hostname(), "80")
		}
	}
	raw, err := c.opts.Dial(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("dial control: %w", err)
	}
	if c.u.Scheme == "https" {
		cfg := c.opts.TLSConfig.Clone()
		if cfg == nil {
			cfg = &tls.Config{}
		}
		if cfg.ServerName == "" {
			cfg.ServerName = c.u.Hostname()
		}
		cfg.NextProtos = []string{"http/1.1"} // Upgrade needs HTTP/1.1
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("control TLS: %w", tlspin.Explain(ctx, err, host, cfg.ServerName))
		}
		raw = tc
	}
	nc, err := c.upgrade(ctx, raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	t := &http2.Transport{ReadIdleTimeout: 45 * time.Second, PingTimeout: 15 * time.Second}
	cc, err := t.NewClientConn(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("control http2: %w", err)
	}
	return cc, nil
}

func (c *Client) upgrade(ctx context.Context, raw net.Conn) (net.Conn, error) {
	hs, init, err := noise.Initiate(c.opts.MachineKey, c.opts.ServerKey)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	} else {
		raw.SetDeadline(time.Now().Add(30 * time.Second))
	}
	defer raw.SetDeadline(time.Time{})
	// Cancelling ctx (shutting down) ends a stalled upgrade at once, not at
	// the deadline: Windows gives a stopping service only seconds.
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	req, _ := http.NewRequest("POST", c.u.JoinPath("/machine/noise").String(), nil)
	req.Header.Set("Upgrade", noise.UpgradeProtocol)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set(noise.HandshakeHeader, base64.StdEncoding.EncodeToString(init))
	if err := req.Write(raw); err != nil {
		return nil, fmt.Errorf("control upgrade: %w", err)
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("control upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		return nil, responseError(resp)
	}
	rw := struct {
		io.Reader
		io.Writer
	}{br, raw}
	nc, err := hs.Finish(raw, rw)
	if err != nil {
		return nil, err
	}
	return nc, nil
}

func responseError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var er protocol.ErrorResponse
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &er) == nil && er.Error != "" {
		msg = er.Error
	}
	return &HTTPError{Code: resp.StatusCode, Msg: msg}
}

// do sends a JSON POST over the Noise channel and returns the response,
// which the caller must close. Non-2xx responses become *HTTPError.
func (c *Client) do(ctx context.Context, path string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	cc, err := c.conn(ctx)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://tc-control"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		// The connection may be dead; drop it so the next call redials.
		c.mu.Lock()
		if c.cc == cc {
			c.cc.Close()
			c.cc = nil
		}
		c.mu.Unlock()
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, responseError(resp)
	}
	return resp, nil
}

func (c *Client) Register(ctx context.Context, req protocol.RegisterRequest) (protocol.RegisterResponse, error) {
	req.Version = protocol.CurrentVersion
	req.MachineKey = c.opts.MachineKey.Public()
	var out protocol.RegisterResponse
	resp, err := c.do(ctx, "/machine/register", req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// Map fetches a single network map.
func (c *Client) Map(ctx context.Context, req protocol.MapRequest) (protocol.MapResponse, error) {
	req.Version, req.Stream, req.OmitPeers = protocol.CurrentVersion, false, false
	var out protocol.MapResponse
	resp, err := c.do(ctx, "/machine/map", req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// StreamMap opens a map stream and calls fn for each network map (keep-alives
// are filtered out). It returns when ctx ends, the stream breaks, or fn errors.
func (c *Client) StreamMap(ctx context.Context, req protocol.MapRequest, fn func(*protocol.MapResponse) error) error {
	req.Version, req.Stream, req.OmitPeers = protocol.CurrentVersion, true, false
	resp, err := c.do(ctx, "/machine/map", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var last *protocol.MapResponse // for applying deltas
	for {
		m := &protocol.MapResponse{}
		if err := dec.Decode(m); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == io.EOF {
				return errors.New("control: map stream closed by server")
			}
			return fmt.Errorf("control: map stream: %w", err)
		}
		if m.KeepAlive {
			continue
		}
		if m.Delta {
			if last == nil {
				return errors.New("control: map stream: delta before the first map")
			}
			m = protocol.ApplyDelta(last, m)
		}
		last = m
		if err := fn(m); err != nil {
			return err
		}
	}
}

// UpdateStatus sends a lite map request reporting endpoints/hostinfo.
func (c *Client) UpdateStatus(ctx context.Context, req protocol.MapRequest) error {
	req.Version, req.Stream, req.OmitPeers = protocol.CurrentVersion, false, true
	resp, err := c.do(ctx, "/machine/map", req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ReportTraffic sends this machine's per-peer byte counters. A server
// without traffic reporting answers 404 (see IsNotFound).
func (c *Client) ReportTraffic(ctx context.Context, req protocol.TrafficRequest) error {
	resp, err := c.do(ctx, "/machine/traffic", req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// IsNotFound reports whether err is a 404 from the server (e.g. a call an
// older server doesn't know).
func IsNotFound(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.Code == http.StatusNotFound
}

// Logout removes the node from the network.
func (c *Client) Logout(ctx context.Context, nk key.NodePublic) error {
	resp, err := c.do(ctx, "/machine/logout", protocol.LogoutRequest{NodeKey: nk})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
