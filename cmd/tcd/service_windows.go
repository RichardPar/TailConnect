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
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "TailConnect"

// defaultTUN is the Wintun adapter name.
const defaultTUN = "TailConnect"

func defaultStateDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		dir = os.Getenv("ProgramData")
	}
	return filepath.Join(dir, "TailConnect")
}

const platformUsage = `
Windows service:
  tcd install [FLAGS]   install and start the TailConnect service (runs tcd FLAGS)
  tcd uninstall         stop and remove the service
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

func installService(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s is already installed (tcd uninstall removes it)", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "TailConnect",
		Description: "TailConnect mesh VPN client",
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		fmt.Fprintln(os.Stderr, "tcd: warning: cannot set restart-on-failure:", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("installed, but starting failed: %w", err)
	}
	fmt.Printf("Installed and started the %s service (%s).\nLog: %s\n", serviceName, exe,
		filepath.Join(defaultStateDir(), "tcd.log"))
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()
	if st, err := s.Control(svc.Stop); err == nil {
		for deadline := time.Now().Add(30 * time.Second); st.State != svc.Stopped && time.Now().Before(deadline); {
			time.Sleep(300 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				break
			}
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("Removed the %s service.\n", serviceName)
	return nil
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
