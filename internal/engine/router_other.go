//go:build !linux || android

package engine

import (
	"fmt"
	"runtime"
)

// NewOSRouter is not yet implemented on this platform (Windows: milestone 6;
// Android configures its interface through VpnService: milestone 7).
func NewOSRouter(ifname string, logf func(string, ...any)) (Router, error) {
	return nil, fmt.Errorf("router: not supported on %s yet", runtime.GOOS)
}
