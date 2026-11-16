//go:build (!linux && !windows) || android

package engine

import (
	"fmt"
	"runtime"
)

// NewOSRouter is not implemented on this platform. (Android configures its
// interface through VpnService.)
func NewOSRouter(ifname string, logf func(string, ...any)) (Router, error) {
	return nil, fmt.Errorf("router: not supported on %s yet", runtime.GOOS)
}
