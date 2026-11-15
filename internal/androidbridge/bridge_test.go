//go:build linux

package androidbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeApp plays the Android app's side of the bridge.
type fakeApp struct {
	t *testing.T
	c *net.UnixConn
	r *bufio.Reader
}

func connectApp(t *testing.T, path string) *fakeApp {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &fakeApp{t: t, c: c, r: bufio.NewReader(c)}
}

func (a *fakeApp) next() Message {
	a.t.Helper()
	a.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := a.r.ReadBytes('\n')
	if err != nil {
		a.t.Fatal(err)
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		a.t.Fatal(err)
	}
	return m
}

func (a *fakeApp) send(m Message, fd int) {
	a.t.Helper()
	b, _ := json.Marshal(m)
	var oob []byte
	if fd >= 0 {
		oob = syscall.UnixRights(fd)
	}
	if _, _, err := a.c.WriteMsgUnix(append(b, '\n'), oob, nil); err != nil {
		a.t.Fatal(err)
	}
}

func TestRequestTUN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge.sock")
	b, err := Listen(path, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	type result struct {
		fd  int
		err error
	}
	done := make(chan result, 1)
	req := Message{Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")}, MTU: 1280, Search: []string{"alice.home.internal"}}
	go func() {
		fd, err := b.RequestTUN(context.Background(), req)
		done <- result{fd, err}
	}()

	// The request waits for the app to connect.
	app := connectApp(t, path)
	app.send(Message{Type: "network", DNS: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")}}, -1)
	m := app.next()
	if m.Type != "tun" || m.MTU != 1280 || m.Addresses[0].String() != "100.64.0.7/32" || m.Search[0] != "alice.home.internal" {
		t.Fatalf("request: %+v", m)
	}
	// Any fd will do for the test: a pipe stands in for the VPN interface.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	app.send(Message{Type: "tun-reply", OK: true}, int(w.Fd()))
	res := <-done
	if res.err != nil || res.fd < 0 {
		t.Fatalf("RequestTUN: %d %v", res.fd, res.err)
	}
	// The received fd is the same pipe.
	f := os.NewFile(uintptr(res.fd), "received")
	defer f.Close()
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 1)
	if _, err := r.Read(got); err != nil || got[0] != 'x' {
		t.Fatalf("fd isn't the pipe: %q %v", got, err)
	}
	if n := b.Network(); len(n.DNS) != 1 || n.DNS[0].String() != "192.168.1.1" || n.Addresses[0].String() != "192.168.1.20/24" {
		t.Fatalf("network: %+v", n)
	}

	// A refusal comes back as an error.
	go func() {
		fd, err := b.RequestTUN(context.Background(), req)
		done <- result{fd, err}
	}()
	app.next()
	app.send(Message{Type: "tun-reply", Error: "VPN permission not granted"}, -1)
	if res := <-done; res.err == nil {
		t.Fatal("refusal not reported")
	}

	b.NotifyClosed()
	if m := app.next(); m.Type != "close" {
		t.Fatalf("got %+v", m)
	}
}
