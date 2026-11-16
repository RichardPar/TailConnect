//go:build !windows

// Command tc-gui is the TailConnect tray app for Windows (TailConnect.exe).
// Elsewhere, use tc.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "tc-gui is the Windows tray app; on this system, use tc (tc status, tc up, tc down).")
	os.Exit(2)
}
