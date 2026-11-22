//go:build !windows

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const defaultTUN = "tc0"

const dnsModeHelp = `how to point the host's DNS at MagicDNS: auto, systemd-resolved, file (rewrite resolv.conf) or off`

func defaultStateDir() string { return "/var/lib/tailconnect" }

const platformUsage = ""

func platformCommand([]string) bool { return false }

func runningAsService() bool { return false }

func serviceContext() (ctx context.Context, stop, finish func()) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx, cancel, cancel
}

func logOutput(string) io.Writer { return os.Stderr }

// secureStateDir is left to the daemon, which creates the directory 0700.
func secureStateDir(string) ([]string, error) { return nil, nil }
