//go:build !windows

package localapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DefaultSocket is where tcd listens by default.
const DefaultSocket = "/run/tailconnect/tcd.sock"

// ElevateHint says how to run a privileged command.
const ElevateHint = "run as root (e.g. sudo tc ...)"

// SudoPrefix goes before example privileged commands.
const SudoPrefix = "sudo "

func dial(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// Listen creates the Unix socket at path (replacing a stale one). The socket
// is world-accessible; privilege is checked per request via peer credentials.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("another tcd is already listening on %s", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// peerPrivileged reports whether the caller is root or the daemon's own user.
func peerPrivileged(c net.Conn) (bool, error) {
	uid, err := peerUID(c)
	if err != nil {
		return false, err
	}
	return uid == 0 || uid == os.Geteuid(), nil
}
