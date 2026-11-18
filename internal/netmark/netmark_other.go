//go:build (!linux && !windows) || android

package netmark

import "syscall"

// Control does nothing: exit nodes are only used on Linux. (The Android
// app is excluded from its own VPN, so its sockets bypass it anyway.)
func Control(network, address string, c syscall.RawConn) error { return nil }
