//go:build !windows && (!linux || android)

// Command tc-gui is the TailConnect tray app for Windows (TailConnect.exe)
// and Linux. Elsewhere, use tc.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "tc-gui is the Windows and Linux tray app; on this system, use tc (tc status, tc up, tc down).")
	os.Exit(2)
}

const serviceHint = "Start tcd."
