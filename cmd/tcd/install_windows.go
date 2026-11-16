package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"tailconnect/internal/engine"
)

// installFiles are what `tcd install` copies into the install directory.
var installFiles = []string{"tcd.exe", "tc.exe", "wintun.dll"}

// installDir is Program Files\TailConnect.
func installDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		dir = os.Getenv("ProgramFiles")
	}
	return filepath.Join(dir, "TailConnect")
}

// installService installs or upgrades: it stops the service if it exists,
// copies the files next to this tcd.exe into installDir, points the service
// there (with args, or the flags it had before), and starts it.
func installService(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	src, dst := filepath.Dir(exe), installDir()
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	upgrade := err == nil
	if upgrade {
		defer s.Close()
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		if len(args) == 0 { // keep the service's flags
			if old, err := windows.DecomposeCommandLine(cfg.BinaryPathName); err == nil && len(old) > 1 {
				args = old[1:]
			}
		}
		if err := stopService(s); err != nil {
			return err
		}
	}
	// An uninstall without a restart since would delete the new files.
	if err := cancelPendingDeletes(dst); err != nil {
		fmt.Fprintln(os.Stderr, "tcd: warning: cannot cancel the pending removal of the old install:", err)
	}
	if !strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		if err := copyFiles(src, dst); err != nil {
			return err
		}
	}
	target := filepath.Join(dst, "tcd.exe")

	if upgrade {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.BinaryPathName = commandLine(target, args)
		if err := s.UpdateConfig(cfg); err != nil {
			return err
		}
	} else {
		s, err = m.CreateService(serviceName, target, mgr.Config{
			DisplayName: "TailConnect",
			Description: "TailConnect mesh VPN client",
			StartType:   mgr.StartAutomatic,
		}, args...)
		if err != nil {
			return err
		}
		defer s.Close()
	}
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		fmt.Fprintln(os.Stderr, "tcd: warning: cannot set restart-on-failure:", err)
	}
	if err := addToPath(dst); err != nil {
		fmt.Fprintf(os.Stderr, "tcd: warning: cannot add %s to PATH: %v\n", dst, err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("installed, but starting the service failed: %w", err)
	}
	verb := "Installed"
	if upgrade {
		verb = "Upgraded"
	}
	fmt.Printf("%s and started the %s service (%s).\n", verb, serviceName, target)
	fmt.Printf("Log: %s\n", filepath.Join(defaultStateDir(), "tcd.log"))
	if !upgrade {
		fmt.Println("If this machine hasn't joined yet, open a new Administrator command prompt")
		fmt.Println("(so PATH is updated) and run: tc up --server URL --authkey KEY")
	}
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
	if err := stopService(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return err
	}
	engine.RemoveFirewallRules()
	dir := installDir()
	if err := removeFromPath(dir); err != nil {
		fmt.Fprintf(os.Stderr, "tcd: warning: cannot remove %s from PATH: %v\n", dir, err)
	}
	later := removeInstallDir(dir)
	fmt.Printf("Removed the %s service.\n", serviceName)
	if later {
		fmt.Printf("%s is removed at the next restart (it holds this running tcd.exe).\n", dir)
	}
	fmt.Printf("This machine's keys and settings are kept in %s;\ndelete that folder to make Windows forget it (it then joins as a new machine).\n", defaultStateDir())
	return nil
}

// stopService stops s and waits until its process has exited, so its files
// can be replaced.
func stopService(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if st, err = s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
	}
	pid := st.ProcessId
	for deadline := time.Now().Add(30 * time.Second); st.State != svc.Stopped; {
		if time.Now().After(deadline) {
			return errors.New("the service did not stop within 30s")
		}
		time.Sleep(200 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	// The service manager reports Stopped before the process has exited.
	if pid != 0 {
		if p, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid); err == nil {
			windows.WaitForSingleObject(p, 10000)
			windows.CloseHandle(p)
		}
	}
	return nil
}

func copyFiles(src, dst string) error {
	for _, f := range installFiles {
		if _, err := os.Stat(filepath.Join(src, f)); err != nil {
			return fmt.Errorf("%s is missing next to tcd.exe (run tcd install from the unpacked TailConnect folder)", f)
		}
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, f := range installFiles {
		if err := copyFile(filepath.Join(src, f), filepath.Join(dst, f)); err != nil {
			return err
		}
	}
	return nil
}

// copyFile writes a fresh copy (without the source's "downloaded from the
// internet" mark) and moves it into place.
func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	tmp := to + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	// A process that was just stopped may hold its files a moment longer.
	for deadline := time.Now().Add(10 * time.Second); ; {
		err = os.Rename(tmp, to)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", to, err)
	}
	return nil
}

// removeInstallDir deletes the installed files, scheduling for the next
// restart what can't be deleted now (the running tcd.exe, when uninstall
// runs from there). It reports whether anything was scheduled.
func removeInstallDir(dir string) (later bool) {
	for _, f := range append(slices.Clone(installFiles), "") {
		p := filepath.Join(dir, f)
		if f == "" {
			p = dir
		}
		if err := os.Remove(p); err == nil || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if pp, err := windows.UTF16PtrFromString(p); err == nil &&
			windows.MoveFileEx(pp, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT) == nil {
			later = true
		}
	}
	return later
}

const sessionManagerKey = `SYSTEM\CurrentControlSet\Control\Session Manager`

// cancelPendingDeletes drops restart-time deletions (MOVEFILE_DELAY_UNTIL_REBOOT,
// kept in PendingFileRenameOperations as source/target pairs) of dir and the
// files in it.
func cancelPendingDeletes(dir string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, sessionManagerKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	ops, _, err := k.GetStringsValue("PendingFileRenameOperations")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	ours := func(p string) bool {
		// Entries look like `\??\C:\...`, sometimes with a "*1" prefix.
		p = strings.ToLower(p)
		d := strings.ToLower(filepath.Clean(dir))
		i := strings.Index(p, d)
		return i >= 0 && (len(p) == i+len(d) || p[i+len(d)] == '\\')
	}
	var keep []string
	for i := 0; i+1 < len(ops); i += 2 {
		if ops[i+1] == "" && ours(ops[i]) { // a deletion of ours
			continue
		}
		keep = append(keep, ops[i], ops[i+1])
	}
	if len(keep) == len(ops) {
		return nil
	}
	if len(keep) == 0 {
		return k.DeleteValue("PendingFileRenameOperations")
	}
	return k.SetStringsValue("PendingFileRenameOperations", keep)
}

const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// addToPath adds dir to the system PATH.
func addToPath(dir string) error {
	return editPath(func(parts []string) []string {
		for _, p := range parts {
			if strings.EqualFold(filepath.Clean(p), filepath.Clean(dir)) {
				return parts
			}
		}
		return append(parts, dir)
	})
}

// removeFromPath removes dir from the system PATH.
func removeFromPath(dir string) error {
	return editPath(func(parts []string) []string {
		return slices.DeleteFunc(parts, func(p string) bool {
			return strings.EqualFold(filepath.Clean(p), filepath.Clean(dir))
		})
	})
}

func editPath(edit func([]string) []string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	old, _, err := k.GetStringValue("Path") // unexpanded: keeps %SystemRoot% etc.
	if err != nil {
		return err
	}
	var parts []string
	for _, p := range strings.Split(old, ";") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	n := len(parts)
	parts = edit(parts)
	if len(parts) == n && strings.Join(parts, ";") == strings.Trim(old, ";") {
		return nil
	}
	if err := k.SetExpandStringValue("Path", strings.Join(parts, ";")); err != nil {
		return err
	}
	broadcastEnvChange()
	return nil
}

// broadcastEnvChange tells running programs (Explorer, so new command
// prompts) that the environment changed.
func broadcastEnvChange() {
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x001a, 0x0002
	env, _ := windows.UTF16PtrFromString("Environment")
	var result uintptr
	windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW").Call(
		hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)),
		smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
}

// commandLine builds a service command line: the program and its flags,
// quoted as Windows expects.
func commandLine(exe string, args []string) string {
	parts := []string{windows.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, windows.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}
