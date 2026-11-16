//go:build !android

// Command tc-gui is the TailConnect desktop app: an icon in the panel with
// a menu, and a status window. Installed as /usr/local/bin/tc-gui, started
// at login and from the applications menu.
//
//	tc-gui            the app, with its window open (or open the running app's window)
//	tc-gui -tray      the app with only the panel icon (autostart)
//	tc-gui -login     open the login window
//	tc-gui -icon FILE write the app icon (PNG) to FILE, for installers
//
// Members of the "tailconnect" group connect and disconnect directly.
// Logging in and out (and, for others, connecting) asks for an
// administrator's password with pkexec, which runs `tc-gui -helper` as root.
//
// It uses GTK 3, loaded at run time (no cgo).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"tailconnect/internal/localapi"
	"tailconnect/internal/trayicon"
)

var version = "dev"

const (
	appTitle    = "TailConnect"
	serviceHint = "Start it with: sudo systemctl start tcd"
)

func init() { runtime.LockOSThread() } // GTK lives on the main thread

func main() {
	trayOnly := flag.Bool("tray", false, "start with only the panel icon (for autostart)")
	login := flag.Bool("login", false, "open the login window")
	icon := flag.String("icon", "", "write the app icon as a PNG to `FILE` and exit")
	helper := flag.Bool("helper", false, "internal: run one privileged request from standard input (as root, via pkexec)")
	socket := flag.String("socket", localapi.DefaultSocket, "tcd's socket")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	c := localapi.NewClient(*socket)
	switch {
	case *showVersion:
		fmt.Println("tc-gui", version)
		return
	case *icon != "":
		if err := os.WriteFile(*icon, trayicon.PNG(trayicon.Connected, 256), 0o644); err != nil {
			fatal(err)
		}
		return
	case *helper:
		runHelper(c)
		return
	}

	cmd := "show"
	switch {
	case *login:
		cmd = "login"
	case *trayOnly:
		cmd = ""
	}
	ln, err := singleInstance(cmd)
	if err != nil {
		fatal(err)
	}
	if ln == nil {
		return // the running app does it
	}
	if err := initGTK(); err != nil {
		fatal(err)
	}
	initNotify()
	a, err := newApp(c)
	if err != nil {
		fatal(err)
	}
	go a.listen(ln)
	switch cmd {
	case "show":
		a.openWindow()
	case "login":
		a.login()
	}
	go a.poll()
	gtk_main()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "tc-gui:", err)
	os.Exit(1)
}

// ---- one app per user ----

func instanceSocket() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("tailconnect-%d", os.Getuid()))
		_ = os.MkdirAll(dir, 0o700)
	}
	return filepath.Join(dir, "tailconnect-gui.sock")
}

// singleInstance passes cmd to an app that is already running and returns
// nil, or else returns the listener for later starts.
func singleInstance(cmd string) (net.Listener, error) {
	path := instanceSocket()
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		defer c.Close()
		_, err := fmt.Fprintln(c, cmd)
		return nil, err
	}
	_ = os.Remove(path)
	return net.Listen("unix", path)
}

func (a *app) listen(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		switch strings.TrimSpace(line) {
		case "show":
			post(a.openWindow)
		case "login":
			post(a.login)
		}
	}
}

// ---- the app ----

type app struct {
	c     *localapi.Client
	icons string // directory of the state icons
	tray  *tray
	win   *statusWindow

	mu    sync.Mutex
	st    *localapi.Status
	stErr error

	v        view   // last shown, GTK thread only
	menuKey  string // what the tray menu shows, to rebuild it only on change
	kick     chan struct{}
	loginWin *loginWindow // open login window, or nil
}

func newApp(c *localapi.Client) (*app, error) {
	a := &app{c: c, kick: make(chan struct{}, 1)}
	a.icons = filepath.Join(filepath.Dir(instanceSocket()), "tailconnect-icons")
	if err := os.MkdirAll(a.icons, 0o700); err != nil {
		return nil, err
	}
	for _, s := range []trayicon.State{trayicon.Connected, trayicon.Disconnected, trayicon.Problem} {
		if err := os.WriteFile(iconPath(a.icons, s), trayicon.PNG(s, 128), 0o644); err != nil {
			return nil, err
		}
	}
	gtk_window_set_default_icon_name("tailconnect")
	a.tray = newTray(a.icons, a.openWindow)
	a.update(makeView(nil, errors.New("starting")))
	return a, nil
}

// poll fetches the status every 2s, or at once after an action.
func (a *app) poll() {
	t := time.NewTicker(2 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		st, err := a.c.Status(ctx)
		cancel()
		post(func() { a.update(makeView(&st, err)) })
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

// update shows v in the tray and the window, with a notification when
// something starts needing attention.
func (a *app) update(v view) {
	prev := a.v
	a.v = v
	if v.Detail != "" && v.Icon == trayicon.Problem && v.Detail != prev.Detail && prev.Title != "" {
		notify(v.Title, v.Detail, iconPath(a.icons, trayicon.Problem))
	}
	if k := menuKey(v); k != a.menuKey || prev.Icon != v.Icon {
		a.menuKey = k
		menu, def := a.menu(v)
		a.tray.set(a.icons, v.Icon, v.Tip(), menu, def)
	}
	if a.win != nil {
		a.win.update(v)
	}
}

// menuKey is what the menu depends on (not latencies, which change often).
func menuKey(v view) string {
	var b strings.Builder
	fmt.Fprintln(&b, v.Title, v.Self, v.CanUp, v.CanDown, v.LoggedIn)
	for _, p := range v.Peers {
		fmt.Fprintln(&b, p.Name, p.Addr())
	}
	return b.String()
}

func (a *app) menu(v view) (menu, def uintptr) {
	m := gtk_menu_new()
	menuItem(m, "TailConnect: "+v.Title, false, nil)
	if v.Self != "" {
		ip := v.SelfIP
		menuItem(m, "This computer: "+v.Self+"  (copy)", true, func() { setClipboard(ip) })
	}
	menuSeparator(m)
	switch {
	case v.CanUp:
		menuItem(m, "Connect", true, a.connect)
	case v.CanDown:
		menuItem(m, "Disconnect", true, a.disconnect)
	}
	if len(v.Peers) > 0 {
		sub := gtk_menu_new()
		for _, p := range v.Peers {
			addr := p.Addr()
			menuItem(sub, p.Name+"    "+addr, true, func() { setClipboard(addr) })
		}
		it := menuItem(m, "Copy address of", true, nil)
		gtk_menu_item_set_submenu(it, sub)
	}
	menuSeparator(m)
	def = menuItem(m, "Open TailConnect", true, a.openWindow)
	if v.LoggedIn {
		menuItem(m, "Change server or account…", v.Title != titleNoService, a.login)
		menuItem(m, "Log out…", true, a.logout)
	} else {
		menuItem(m, "Log in…", v.Title != titleNoService, a.login)
	}
	menuSeparator(m)
	menuItem(m, "Quit", true, gtk_main_quit)
	return m, def
}

func (a *app) openWindow() {
	if a.win == nil {
		a.win = newStatusWindow(a)
	}
	a.win.update(a.v)
	gtk_widget_show(a.win.win)
	gtk_window_present(a.win.win)
}

func (a *app) owner() uintptr {
	if a.win != nil && gtk_widget_get_visible(a.win.win) {
		return a.win.win
	}
	return 0
}

// do runs an action off the GTK thread, reporting failure in a message box.
func (a *app) do(what string, f func(context.Context) error) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		err := f(ctx)
		if err != nil && !errors.Is(err, errCancelled) {
			post(func() { messageBox(a.owner(), what+" failed\n\n"+err.Error(), gtkMessageError, gtkButtonsOK) })
		}
		a.refresh()
	}()
}

func (a *app) connect() {
	if !a.v.LoggedIn {
		a.login()
		return
	}
	a.do("Connect", func(ctx context.Context) error {
		_, err := a.c.Up(ctx, localapi.UpRequest{})
		if isDenied(err) { // not in the tailconnect group: ask for a password
			_, err = privileged(ctx, helperRequest{Op: "up"})
		}
		return err
	})
}

func (a *app) disconnect() {
	a.do("Disconnect", func(ctx context.Context) error {
		_, err := a.c.Down(ctx)
		if isDenied(err) {
			_, err = privileged(ctx, helperRequest{Op: "down"})
		}
		return err
	})
}

func isDenied(err error) bool {
	return err != nil && strings.Contains(err.Error(), "permission denied")
}
