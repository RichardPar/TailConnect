// Command tc-gui is the TailConnect tray app for Windows, installed as
// TailConnect.exe. It shows the connection in the notification area and a
// status window, connects and disconnects for any signed-in user, and runs
// itself elevated (UAC) for logging in and out.
//
//	TailConnect.exe           the tray app (one per signed-in user)
//	TailConnect.exe -login    the login window (started elevated by the tray app)
//	TailConnect.exe -logout   confirm, then log out (likewise)
//	TailConnect.exe -uninstall  confirm, then uninstall (Settings → Apps runs this)
//
// Built with -tags setup it is instead the one-click installer
// (TailConnect-Setup-VERSION-ARCH.exe); see setup_windows.go.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"tailconnect/internal/localapi"
	"tailconnect/internal/trayicon"
)

var version = "dev"

var osExecutable = os.Executable

const appTitle = "TailConnect"

const serviceHint = "Start the TailConnect service (services.msc), or reinstall with tcd install."

// App messages.
const (
	wmAppStatus = wmApp + 1 // new status in app.st
	wmAppTray   = wmApp + 2 // tray icon mouse events
	wmAppShow   = wmApp + 3 // open the window (sent by a second instance)
	wmAppError  = wmApp + 4 // an action failed; message in app.errs
)

// Menu and control IDs.
const (
	idConnect = 100 + iota
	idDisconnect
	idOpen
	idLogin
	idLogout
	idCopySelf
	idExit
	idExitNone
	idPeerBase     = 1000 // + peer index: copy that peer's address
	idExitNodeBase = 2000 // + index in view.Exits: use that exit node
)

func main() {
	runtime.LockOSThread() // all windows live on this thread
	login := flag.Bool("login", false, "show the login window")
	logout := flag.Bool("logout", false, "log out after asking")
	uninstall := flag.Bool("uninstall", false, "uninstall TailConnect after asking")
	flag.Parse()

	if pSetProcessDpiAwarenessContext.Find() == nil {
		pSetProcessDpiAwarenessContext.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	}
	manifest := filepath.Join(os.TempDir(), "tailconnect-gui.manifest")
	if b, err := os.ReadFile(manifest); err != nil || string(b) != commonControlsManifest {
		_ = os.WriteFile(manifest, []byte(commonControlsManifest), 0o644)
	}
	enableVisualStyles(manifest)
	registerClasses()

	c := localapi.NewClient(localapi.DefaultSocket)
	switch {
	case len(setupPayload) > 0:
		runSetup(c)
	case *login:
		runLogin(c)
	case *logout:
		runLogout(c, 0)
	case *uninstall:
		runUninstall()
	default:
		runTray(c)
	}
}

// ---- window classes and message dispatch ----

// handlers maps each top-level window to its message handler; controls
// notify their parent through it.
var handlers = map[windows.Handle]func(m uint32, w, l uintptr) (uintptr, bool){}

var wndProcCallback = windows.NewCallback(func(h windows.Handle, m uint32, w, l uintptr) uintptr {
	if f := handlers[h]; f != nil {
		if r, done := f(m, w, l); done {
			return r
		}
	}
	if m == wmDestroy {
		delete(handlers, h)
		delete(dialogs, h)
	}
	r, _, _ := pDefWindowProcW.Call(uintptr(h), uintptr(m), w, l)
	return r
})

const (
	classTray   = "TailConnectTray"
	classWindow = "TailConnectWindow"
)

func registerClasses() {
	inst, _, _ := kernel32.NewProc("GetModuleHandleW").Call(0)
	cursor, _, _ := pLoadCursorW.Call(0, 32512) // IDC_ARROW
	bg, _, _ := pGetSysColorBrush.Call(colorBtnFace)
	for _, name := range []string{classTray, classWindow} {
		wc := wndClassEx{WndProc: wndProcCallback, Instance: windows.Handle(inst), Cursor: windows.Handle(cursor),
			Background: windows.Handle(bg), ClassName: str(name)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	}
}

// dialogs are the windows whose controls get dialog keyboard handling (Tab
// between fields, Enter and Esc for the default and cancel buttons).
var dialogs = map[windows.Handle]bool{}

// messageLoop runs until PostQuitMessage.
func messageLoop() {
	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		handled := false
		for d := range dialogs {
			if r, _, _ := pIsDialogMessageW.Call(uintptr(d), uintptr(unsafe.Pointer(&m))); r != 0 {
				handled = true
				break
			}
		}
		if !handled {
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}
}

// ---- the tray app ----

type app struct {
	c        *localapi.Client
	hwnd     windows.Handle // hidden window that owns the tray icon
	dpi      int32
	icons    map[trayicon.State]windows.Handle // tray size
	bigIcons map[trayicon.State]windows.Handle // window title bar / taskbar

	mu    sync.Mutex
	st    *localapi.Status
	stErr error
	errs  []string

	v              view // last shown, UI thread only
	shown          bool // the tray icon has been added
	win            *statusWindow
	kick           chan struct{}
	taskbarCreated uint32
}

func runTray(c *localapi.Client) {
	// One tray app per signed-in user: a second start opens the first's window.
	if _, err := windows.CreateMutex(nil, false, str(`Local\TailConnectTray`)); errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(str(classTray))), 0); h != 0 {
			postMessage(windows.Handle(h), wmAppShow, 0, 0)
		}
		return
	}
	a := &app{c: c, kick: make(chan struct{}, 1)}
	a.hwnd = createWindow(0, classTray, appTitle, 0, 0, 0, 0, 0, 0, 0)
	a.dpi = dpiFor(0)
	a.icons = makeIcons(systemMetric(smCxSmIcon, a.dpi))
	a.bigIcons = makeIcons(systemMetric(smCxIcon, a.dpi))
	r, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(str("TaskbarCreated"))))
	a.taskbarCreated = uint32(r)
	handlers[a.hwnd] = a.handle
	a.update(makeView(nil, errors.New("starting")))
	go a.poll()
	messageLoop()
	a.trayIcon(nimDelete)
}

func makeIcons(size int32) map[trayicon.State]windows.Handle {
	m := map[trayicon.State]windows.Handle{}
	for _, s := range []trayicon.State{trayicon.Connected, trayicon.Disconnected, trayicon.Problem} {
		m[s] = iconFromPNG(trayicon.PNG(s, int(size)), size)
	}
	return m
}

// poll fetches the status every 2s, or at once after an action.
func (a *app) poll() {
	t := time.NewTicker(2 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		st, err := a.c.Status(ctx)
		cancel()
		a.mu.Lock()
		if err != nil {
			a.st, a.stErr = nil, err
		} else {
			a.st, a.stErr = &st, nil
		}
		a.mu.Unlock()
		postMessage(a.hwnd, wmAppStatus, 0, 0)
		select {
		case <-t.C:
		case <-a.kick:
		}
	}
}

func (a *app) refresh() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// do runs an action off the UI thread, reporting failure in a message box.
func (a *app) do(what string, f func(context.Context) error) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		if err := f(ctx); err != nil {
			a.mu.Lock()
			a.errs = append(a.errs, what+": "+err.Error())
			a.mu.Unlock()
			postMessage(a.hwnd, wmAppError, 0, 0)
		}
		a.refresh()
	}()
}

func (a *app) handle(m uint32, w, l uintptr) (uintptr, bool) {
	switch m {
	case wmAppStatus:
		a.mu.Lock()
		st, err := a.st, a.stErr
		a.mu.Unlock()
		a.update(makeView(st, err))
		return 0, true
	case wmAppError:
		a.mu.Lock()
		errs := a.errs
		a.errs = nil
		a.mu.Unlock()
		for _, e := range errs {
			messageBox(a.owner(), e, appTitle, mbOK|mbIconError)
		}
		return 0, true
	case wmAppShow:
		a.openWindow()
		return 0, true
	case wmAppTray:
		switch uint32(l) {
		case wmLButtonUp:
			a.openWindow()
		case wmRButtonUp:
			a.menu()
		}
		return 0, true
	case a.taskbarCreated: // Explorer restarted: the icon must be added again
		a.shown = false
		a.update(a.v)
		return 0, true
	}
	return 0, false
}

func (a *app) owner() windows.Handle {
	if a.win != nil && visible(a.win.hwnd) {
		return a.win.hwnd
	}
	return 0
}

// update shows v in the tray and the window, with a notification when
// something starts needing attention.
func (a *app) update(v view) {
	prev := a.v
	a.v = v
	if !a.shown {
		a.trayIcon(nimAdd)
		a.shown = true
	} else {
		a.trayIcon(nimModify)
	}
	if v.Detail != "" && v.Icon == trayicon.Problem && v.Detail != prev.Detail && prev.Title != "" {
		a.notify(v.Title, v.Detail, niifWarning)
	}
	if a.win != nil {
		a.win.update(v)
	}
}

func (a *app) trayIcon(op uintptr) {
	nid := notifyIconData{Wnd: a.hwnd, ID: 1, Flags: nifMessage | nifIcon | nifTip, CallbackMessage: wmAppTray,
		Icon: a.icons[a.v.Icon]}
	nid.Size = uint32(unsafe.Sizeof(nid))
	copy(nid.Tip[:len(nid.Tip)-1], windows.StringToUTF16(a.v.Tip()))
	pShellNotifyIconW.Call(op, uintptr(unsafe.Pointer(&nid)))
}

func (a *app) notify(title, text string, flags uint32) {
	nid := notifyIconData{Wnd: a.hwnd, ID: 1, Flags: nifInfo, InfoFlags: flags}
	nid.Size = uint32(unsafe.Sizeof(nid))
	copy(nid.InfoTitle[:len(nid.InfoTitle)-1], windows.StringToUTF16(title))
	copy(nid.Info[:len(nid.Info)-1], windows.StringToUTF16(text))
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func (a *app) menu() {
	v := a.v
	m, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(m)
	add := func(menu uintptr, flags uint32, id uintptr, text string) {
		pAppendMenuW.Call(menu, uintptr(flags), id, uintptr(unsafe.Pointer(str(text))))
	}
	add(m, mfString|mfGrayed, 0, "TailConnect: "+v.Title)
	if v.Self != "" {
		add(m, mfString, idCopySelf, "This PC: "+v.Self+"  (copy)")
	}
	add(m, mfSeparator, 0, "")
	switch {
	case v.CanUp:
		add(m, mfString, idConnect, "Connect")
	case v.CanDown:
		add(m, mfString, idDisconnect, "Disconnect")
	}
	if len(v.Peers) > 0 {
		sub, _, _ := pCreatePopupMenu.Call()
		for i, p := range v.Peers {
			flags := uint32(mfString)
			if p.Active {
				flags |= mfChecked
			}
			add(sub, flags, uintptr(idPeerBase+i), p.Name+"\t"+p.Addr())
		}
		add(m, mfPopup, sub, "Copy address of")
	}
	if v.CanDown && (len(v.Exits) > 0 || v.ExitChose != "") {
		sub, _, _ := pCreatePopupMenu.Call()
		flags := uint32(mfString)
		if v.ExitChose == "" {
			flags |= mfChecked
		}
		add(sub, flags, idExitNone, "None")
		for i, name := range v.Exits {
			flags := uint32(mfString)
			if strings.EqualFold(name, v.ExitChose) || strings.HasPrefix(strings.ToLower(v.ExitChose), strings.ToLower(name)+".") {
				flags |= mfChecked
			}
			add(sub, flags, uintptr(idExitNodeBase+i), name)
		}
		label := "Exit node: None"
		switch {
		case v.ExitChose != "" && v.ExitInUse:
			label = "Exit node: " + v.ExitChose
		case v.ExitChose != "":
			label = "Exit node: " + v.ExitChose + " (not working)"
		}
		add(m, mfPopup, sub, label)
	}
	add(m, mfSeparator, 0, "")
	add(m, mfString, idOpen, "Open TailConnect")
	if v.LoggedIn {
		add(m, mfString, idLogin, "Change server or account…")
		add(m, mfString, idLogout, "Log out…")
	} else {
		add(m, mfString, idLogin, "Log in…")
	}
	add(m, mfSeparator, 0, "")
	add(m, mfString|mfGrayed, 0, "Version "+version)
	add(m, mfString, idExit, "Exit")
	pSetMenuDefaultItem.Call(m, idOpen, 0)

	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(uintptr(a.hwnd)) // so the menu closes when clicking elsewhere
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmRightButton|tpmReturnCmd|tpmBottomAlign, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(a.hwnd), 0)
	postMessage(a.hwnd, wmNull, 0, 0)
	a.command(int(cmd))
}

// command carries out a menu item or button.
func (a *app) command(id int) {
	v := a.v
	switch {
	case id == idConnect:
		if !v.LoggedIn {
			a.login()
			return
		}
		a.do("Connect", func(ctx context.Context) error { _, err := a.c.Up(ctx, localapi.UpRequest{}); return err })
	case id == idDisconnect:
		a.do("Disconnect", func(ctx context.Context) error { _, err := a.c.Down(ctx); return err })
	case id == idOpen:
		a.openWindow()
	case id == idLogin:
		a.login()
	case id == idLogout:
		a.logout()
	case id == idCopySelf:
		setClipboard(a.hwnd, v.SelfIP)
	case id == idExit:
		if a.win != nil {
			pDestroyWindow.Call(uintptr(a.win.hwnd))
		}
		pPostQuitMessage.Call(0)
	case id == idExitNone:
		a.setExitNode("")
	case id >= idExitNodeBase && id < idExitNodeBase+len(v.Exits):
		a.setExitNode(v.Exits[id-idExitNodeBase])
	case id >= idPeerBase && id < idPeerBase+len(v.Peers):
		setClipboard(a.hwnd, v.Peers[id-idPeerBase].Addr())
	}
}

// setExitNode sends this PC's internet traffic through the exit node name
// ("" = none). The menu shows the result; a choice that can't be used yet
// (say, the exit node is offline) is reported.
func (a *app) setExitNode(name string) {
	a.do("Exit node", func(ctx context.Context) error {
		st, err := a.c.Up(ctx, localapi.UpRequest{ExitNode: &name})
		if err != nil {
			return err
		}
		if name != "" && st.ExitNode != nil && st.ExitNode.Using == "" && st.ExitNode.Error != "" {
			return fmt.Errorf("%s isn't carrying internet traffic yet: %s", name, st.ExitNode.Error)
		}
		return nil
	})
}

// login opens the login window, elevated: logging in changes the
// machine's network, which needs an Administrator.
func (a *app) login() {
	if isAdmin() { // already elevated: no need for a second process
		newLoginWindow(a.c, a.refresh, false)
		return
	}
	if _, err := runElevated(a.owner(), "-login"); err != nil {
		messageBox(a.owner(), "Cannot start the login window as Administrator: "+err.Error(), appTitle, mbOK|mbIconError)
	}
}

func (a *app) logout() {
	if isAdmin() {
		runLogout(a.c, a.owner())
		a.refresh()
		return
	}
	if _, err := runElevated(a.owner(), "-logout"); err != nil {
		messageBox(a.owner(), "Cannot log out as Administrator: "+err.Error(), appTitle, mbOK|mbIconError)
	}
}

func (a *app) openWindow() {
	if a.win == nil {
		a.win = newStatusWindow(a)
	}
	a.win.update(a.v)
	show(a.win.hwnd, swShow)
	pSetForegroundWindow.Call(uintptr(a.win.hwnd))
}
