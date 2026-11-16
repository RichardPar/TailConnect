package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client talks to tcd over its Unix socket (named pipe on Windows).
type Client struct {
	Socket string
	hc     *http.Client
}

func NewClient(socket string) *Client {
	return &Client{
		Socket: socket,
		hc: &http.Client{
			Timeout: 60 * time.Second, // `up` waits for registration
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dial(ctx, socket)
				},
			},
		},
	}
}

func (c *Client) call(ctx context.Context, method, path string, body any) (Status, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return Status{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, "http://tcd"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) {
			return Status{}, fmt.Errorf("cannot reach tcd at %s (is it running?): %w", c.Socket, err)
		}
		if ue, ok := err.(*url.Error); ok {
			err = ue.Err // drop the meaningless "Get http://tcd/..."
		}
		return Status{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return Status{}, errors.New(e.Error)
		}
		return Status{}, fmt.Errorf("tcd: HTTP %d", resp.StatusCode)
	}
	var st Status
	return st, json.Unmarshal(b, &st)
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	return c.call(ctx, "GET", "/localapi/v1/status", nil)
}

func (c *Client) Up(ctx context.Context, req UpRequest) (Status, error) {
	return c.call(ctx, "POST", "/localapi/v1/up", req)
}

func (c *Client) Down(ctx context.Context) (Status, error) {
	return c.call(ctx, "POST", "/localapi/v1/down", struct{}{})
}

func (c *Client) Logout(ctx context.Context) (Status, error) {
	return c.call(ctx, "POST", "/localapi/v1/logout", struct{}{})
}
