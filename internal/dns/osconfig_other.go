//go:build (!linux && !windows) || android

package dns

import "fmt"

// NewOSConfigurator returns the DNS configurator for this host. There is no
// OS integration here (Android sets DNS through VpnService); MagicDNS can be
// queried at 100.100.100.100 directly.
func NewOSConfigurator(o OSOptions) (OSConfigurator, error) {
	switch o.Mode {
	case "", ModeAuto, ModeOff:
		return NoopConfigurator{}, nil
	}
	return nil, fmt.Errorf("dns: mode %q is not supported on this platform", o.Mode)
}
