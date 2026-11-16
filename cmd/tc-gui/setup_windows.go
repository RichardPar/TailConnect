package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailconnect/internal/localapi"
)

// The one-click installer is this program built with -tags setup, which
// embeds the Windows package (setupPayload, see payload_setup_windows.go).
// Run, it elevates itself, unpacks the package to a temporary folder, runs
// its `tcd install` (the same install or upgrade as from the zip), and then
// opens the login window if the PC hasn't joined a network yet.

const wmAppSetupDone = wmApp + 20

// hidden runs a console program without a console window.
func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd
}

func runSetup(c *localapi.Client) {
	if !isAdmin() {
		if _, err := runElevated(0, ""); err != nil {
			messageBox(0, "TailConnect Setup needs to run as Administrator: "+err.Error(), appTitle+" Setup", mbOK|mbIconError)
		}
		return
	}
	dpi := dpiFor(0)
	sc := func(v int32) int32 { return v * dpi / 96 }
	h := createWindow(0, classWindow, appTitle+" Setup", wsCaption|wsSysMenu, cwUseDefault, cwUseDefault, sc(440), sc(170), 0, 0)
	dpi = dpiFor(h)
	icons := makeIcons(systemMetric(smCxSmIcon, dpi))
	sendMessage(h, wmSetIcon, 0, uintptr(icons[0]))
	font := messageFont(dpi, 1.1, false)
	label := createWindow(0, "STATIC", "Installing TailConnect "+version+"…", wsChild|wsVisible|ssNoPrefix, sc(20), sc(20), sc(380), sc(24), h, 0)
	sendMessage(label, wmSetFont, uintptr(font), 1)
	bar := createWindow(0, "msctls_progress32", "", wsChild|wsVisible|0x08 /* PBS_MARQUEE */, sc(20), sc(56), sc(380), sc(20), h, 0)
	sendMessage(bar, 0x040A /* PBM_SETMARQUEE */, 1, 30)

	var (
		mu  sync.Mutex
		out string
		err error
	)
	handlers[h] = func(m uint32, w, l uintptr) (uintptr, bool) {
		switch m {
		case wmClose:
			return 0, true // not while installing
		case wmAppSetupDone:
			pDestroyWindow.Call(uintptr(h))
			mu.Lock()
			o, e := out, err
			mu.Unlock()
			setupFinished(c, o, e)
			return 0, true
		}
		return 0, false
	}
	show(h, swShow)
	pSetForegroundWindow.Call(uintptr(h))
	go func() {
		o, e := install()
		mu.Lock()
		out, err = o, e
		mu.Unlock()
		postMessage(h, wmAppSetupDone, 0, 0)
	}()
	messageLoop()
}

// install unpacks the package and runs its tcd install.
func install() (string, error) {
	dir, err := os.MkdirTemp("", "TailConnect-setup-")
	if err != nil {
		return "", err
	}
	defer func() {
		// Programs that were just started may hold the folder a moment.
		for i := 0; i < 10 && os.RemoveAll(dir) != nil; i++ {
			time.Sleep(300 * time.Millisecond)
		}
	}()
	zr, err := zip.NewReader(bytes.NewReader(setupPayload), int64(len(setupPayload)))
	if err != nil {
		return "", fmt.Errorf("damaged installer: %w", err)
	}
	for _, f := range zr.File {
		// Flatten "tailconnect-VERSION-windows-ARCH/x" to "x"; only the
		// top-level files are needed.
		_, name, ok := strings.Cut(f.Name, "/")
		if !ok || name == "" || strings.Contains(name, "/") || f.FileInfo().IsDir() {
			continue
		}
		if err := unpack(f, filepath.Join(dir, name)); err != nil {
			return "", err
		}
	}
	cmd := hidden(exec.Command(filepath.Join(dir, "tcd.exe"), "install"))
	cmd.Dir = os.TempDir() // a process it starts must not hold dir as its working directory
	b, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func unpack(f *zip.File, to string) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

// setupFinished reports the result and, for a PC that hasn't joined a
// network yet, opens the login window (this process is already elevated).
func setupFinished(c *localapi.Client, out string, err error) {
	if err != nil {
		messageBox(0, "TailConnect could not be installed.\n\n"+out+"\n\n"+err.Error(), appTitle+" Setup", mbOK|mbIconError)
		pPostQuitMessage.Call(1)
		return
	}
	var st localapi.Status
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		s, err := c.Status(ctx)
		cancel()
		if err == nil {
			st = s
			break
		}
	}
	if st.State == localapi.StateNeedsLogin {
		newLoginWindow(c, nil, true)
		return
	}
	verb := "installed"
	if strings.HasPrefix(out, "Upgraded") {
		verb = "upgraded"
	}
	messageBox(0, fmt.Sprintf("TailConnect %s is %s and running.\n\nIts icon is in the notification area, by the clock.", version, verb),
		appTitle+" Setup", mbOK|mbIconInfo)
	pPostQuitMessage.Call(0)
}

// runUninstall is what Settings → Apps runs: elevate, confirm, then the
// installed tcd uninstall.
func runUninstall() {
	if !isAdmin() {
		if _, err := runElevated(0, "-uninstall"); err != nil {
			messageBox(0, "Uninstalling TailConnect needs an Administrator: "+err.Error(), appTitle, mbOK|mbIconError)
		}
		return
	}
	if messageBox(0, "Uninstall TailConnect from this PC?\n\nThis PC disconnects from its network. Its keys are kept, so installing again later brings it back as the same machine.",
		appTitle, mbYesNo|mbIconWarning) != idYes {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		messageBox(0, err.Error(), appTitle, mbOK|mbIconError)
		return
	}
	b, err := hidden(exec.Command(filepath.Join(filepath.Dir(exe), "tcd.exe"), "uninstall")).CombinedOutput()
	if err != nil {
		messageBox(0, "Uninstall failed:\n\n"+strings.TrimSpace(string(b))+"\n\n"+err.Error(), appTitle, mbOK|mbIconError)
		return
	}
	messageBox(0, "TailConnect has been removed.", appTitle, mbOK|mbIconInfo)
}
