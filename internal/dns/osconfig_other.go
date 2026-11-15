//go:build !linux || android

package dns

import "fmt"

// NewOSConfigurator returns the DNS configurator for this host. OS
// integration for Windows (NRPT) and Android (VpnService) comes with those
// ports; until then MagicDNS can be queried at 100.100.100.100 directly.
func NewOSConfigurator(o OSOptions) (OSConfigurator, error) {
	switch o.Mode {
	case "", ModeAuto, ModeOff:
		return NoopConfigurator{}, nil
	}
	return nil, fmt.Errorf("dns: mode %q is not supported on this platform", o.Mode)
}
