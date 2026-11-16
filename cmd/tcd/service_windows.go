package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/tun"
)

const serviceName = "TailConnect"

// defaultTUN is the Wintun adapter name.
const defaultTUN = "TailConnect"

const dnsModeHelp = `how to point the host's DNS at MagicDNS: auto (NRPT rules: MagicDNS names only) or off`

// adapterGUID gives the Wintun adapter the same identity every time, so
// Windows keeps one network entry for it rather than adding "TailConnect 2",
// "TailConnect 3", ... and its settings stick.
var adapterGUID = windows.GUID{Data1: 0x7c7c0e1a, Data2: 0x7c0e, Data3: 0x4a1e, Data4: [8]byte{0x8a, 0x5c, 0x74, 0x63, 0x6f, 0x6e, 0x6e, 0x31}}

func init() {
	tun.WintunTunnelType = "TailConnect"
	tun.WintunStaticRequestedGUID = &adapterGUID
}

func defaultStateDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		dir = os.Getenv("ProgramData")
	}
	return filepath.Join(dir, "TailConnect")
}

const platformUsage = `
Windows service (from an Administrator command prompt):
  tcd install [FLAGS]   copy tcd.exe, tc.exe and wintun.dll from this folder to
                        Program Files\TailConnect, add it to PATH, and install
                        (or upgrade) and start the TailConnect service, which
                        runs tcd FLAGS (default: the flags it had before)
  tcd uninstall         stop and remove the service and the installed files
                        (keys and settings stay in ProgramData\TailConnect)
`

// platformCommand runs `tcd install` and `tcd uninstall`.
func platformCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	var err error
	switch args[0] {
	case "install":
		err = installService(args[1:])
	case "uninstall":
		err = uninstallService()
	default:
		return false
	}
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			err = fmt.Errorf("%w (run from an Administrator command prompt)", err)
		}
		fmt.Fprintln(os.Stderr, "tcd:", err)
		os.Exit(1)
	}
	return true
}

func runningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// serviceContext returns a context that ends on Ctrl+C, on stop, or, when
// running as a service, when the service is stopped. finish must be called
// once tcd has shut down; it reports the stop to the service manager.
func serviceContext() (ctx context.Context, stop, finish func()) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	stop = cancel
	if !runningAsService() {
		return ctx, stop, stop
	}
	h := &serviceHandler{stop: stop, done: make(chan struct{})}
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		defer stop()
		if err := svc.Run(serviceName, h); err != nil {
			fmt.Fprintln(os.Stderr, "service:", err)
		}
	}()
	return ctx, stop, func() {
		close(h.done)
		<-exited
	}
}

type serviceHandler struct {
	stop func()        // starts tcd's shutdown
	done chan struct{} // closed when tcd has shut down
}

func (h *serviceHandler) Execute(_ []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-reqs:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				h.stop()
				<-h.done
				return false, 0
			}
		case <-h.done: // tcd stopped by itself
			return false, 0
		}
	}
}

// logOutput is stderr, or tcd.log in the state directory when running as a
// service (which has no console). The previous log is kept as tcd.log.1
// once it passes 10 MB.
func logOutput(stateDir string) io.Writer {
	if !runningAsService() {
		return os.Stderr
	}
	p := filepath.Join(stateDir, "tcd.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 10<<20 {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return os.Stderr
	}
	return f
}

// stateDirSDDL gives SYSTEM and Administrators full access to the state
// directory and everything in it, and nobody else any (it holds the node's
// private keys, and ProgramData is readable by all users by default).
const stateDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// secureStateDir creates the state directory and, when tcd runs elevated,
// restricts it to SYSTEM and Administrators. (Unelevated test runs with
// -tun userspace keep the default permissions of the -state they choose.)
func secureStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	sd, err := windows.SecurityDescriptorFromString(stateDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
