package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"tailconnect/internal/localapi"
)

const wmAppLoginDone = wmApp + 10

// loginWindow asks for the server, an auth key, the device name and
// (for self-signed servers) a certificate fingerprint, then logs in. It
// runs elevated: logging in needs an Administrator.
type loginWindow struct {
	c          *localapi.Client
	hwnd       windows.Handle
	standalone bool   // its own process (-login): quit when closed
	onDone     func() // after a successful login
	cur        localapi.Status

	server, key, name, fp windows.Handle
	msg, ok, cancel       windows.Handle
	fonts                 []windows.Handle // deleted when the window closes

	mu     sync.Mutex
	result *localapi.Status
	err    error
}

func runLogin(c *localapi.Client) {
	newLoginWindow(c, nil, true)
	messageLoop()
}

func newLoginWindow(c *localapi.Client, onDone func(), standalone bool) *loginWindow {
	w := &loginWindow{c: c, standalone: standalone, onDone: onDone}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if st, err := c.Status(ctx); err == nil {
		w.cur = st
	}
	cancel()

	dpi := dpiFor(0)
	sc := func(v int32) int32 { return v * dpi / 96 }
	w.hwnd = createWindow(wsExControlParent, classWindow, "Log in to TailConnect", wsCaption|wsSysMenu|wsMinimizeBox,
		cwUseDefault, cwUseDefault, sc(500), sc(380), 0, 0)
	dpi = dpiFor(w.hwnd)
	handlers[w.hwnd] = w.handle
	dialogs[w.hwnd] = true
	icons := makeIcons(systemMetric(smCxSmIcon, dpi))
	sendMessage(w.hwnd, wmSetIcon, 0, uintptr(icons[0]))

	font := messageFont(dpi, 1, false)
	bold := messageFont(dpi, 1.25, true)
	w.fonts = []windows.Handle{font, bold}
	r := clientRect(w.hwnd)
	m := sc(16)
	full := r.Right - r.Left - 2*m
	ctl := func(class, text string, style uint32, ex uint32, x, y, wd, h int32, id uintptr) windows.Handle {
		hh := createWindow(ex, class, text, wsChild|wsVisible|style, x, y, wd, h, w.hwnd, id)
		sendMessage(hh, wmSetFont, uintptr(font), 1)
		return hh
	}
	title := ctl("STATIC", "Join this PC to a TailConnect network", ssNoPrefix, 0, m, sc(14), full, sc(28), 0)
	sendMessage(title, wmSetFont, uintptr(bold), 1)

	lw, ex := sc(130), m+sc(136)
	ew := full - sc(136)
	row := func(y int32, label, value string, style uint32) windows.Handle {
		ctl("STATIC", label, ssNoPrefix, 0, m, sc(y)+sc(4), lw, sc(20), 0)
		return ctl("EDIT", value, wsTabStop|esAutoHScroll|style, wsExClientEdge, ex, sc(y), ew, sc(26), 0)
	}
	host := ""
	if w.cur.Self != nil {
		host = w.cur.Self.HostName
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	w.server = row(58, "Server address", w.cur.ControlURL, 0)
	w.key = row(94, "Auth key", "", esPassword)
	w.name = row(130, "Name of this PC", host, 0)
	w.fp = row(166, "Certificate", "", 0)
	ctl("STATIC", "Only for a server with a self-signed certificate: sha256:… from its log.", ssNoPrefix, 0, ex, sc(196), ew, sc(36), 0)

	keyHint := "From the portal (Auth keys → Generate key) or: tc-control keys create -user NAME"
	if w.cur.State != localapi.StateNeedsLogin && w.cur.State != "" {
		keyHint = "Already logged in: leave Auth key empty to keep this machine's login, or enter a key to re-register."
	}
	w.msg = ctl("STATIC", keyHint, ssNoPrefix, 0, m, sc(238), full, sc(40), 0)
	bw := sc(100)
	w.ok = ctl("BUTTON", "Log in", wsTabStop|bsDefPushButton, 0, r.Right-m-2*bw-sc(10), sc(292), bw, sc(30), idOK)
	w.cancel = ctl("BUTTON", "Cancel", wsTabStop|bsPushButton, 0, r.Right-m-bw, sc(292), bw, sc(30), idCancel)

	show(w.hwnd, swShow)
	pSetForegroundWindow.Call(uintptr(w.hwnd))
	if w.cur.ControlURL == "" {
		pSetFocus.Call(uintptr(w.server))
	} else {
		pSetFocus.Call(uintptr(w.key))
	}
	return w
}

func (w *loginWindow) handle(m uint32, wp, lp uintptr) (uintptr, bool) {
	switch m {
	case wmCommand:
		switch wp & 0xffff {
		case idOK:
			w.submit()
		case idCancel:
			w.close()
		default:
			return 0, false
		}
		return 0, true
	case wmClose:
		w.close()
		return 0, true
	case wmAppLoginDone:
		w.done()
		return 0, true
	}
	return 0, false
}

func (w *loginWindow) close() {
	pDestroyWindow.Call(uintptr(w.hwnd))
	for _, f := range w.fonts { // after the controls using them are gone
		pDeleteObject.Call(uintptr(f))
	}
	w.fonts = nil
	if w.standalone {
		pPostQuitMessage.Call(0)
	}
}

func (w *loginWindow) submit() {
	server := strings.TrimSpace(getText(w.server))
	key := strings.TrimSpace(getText(w.key))
	name := strings.TrimSpace(getText(w.name))
	fp := strings.TrimSpace(getText(w.fp))
	loggedIn := w.cur.State != localapi.StateNeedsLogin && w.cur.State != ""
	switch {
	case server == "":
		setText(w.msg, "Enter the server address, e.g. https://tailconnect.example.com:8443")
		pSetFocus.Call(uintptr(w.server))
		return
	case key == "" && (!loggedIn || server != w.cur.ControlURL):
		setText(w.msg, "Enter an auth key (tc-auth-…) to join.")
		pSetFocus.Call(uintptr(w.key))
		return
	}
	req := localapi.UpRequest{AuthKey: key, TLSFingerprint: fp}
	if server != w.cur.ControlURL || !loggedIn {
		req.ControlURL = server
	}
	cur := ""
	if w.cur.Self != nil {
		cur = w.cur.Self.HostName
	}
	if name != "" && name != cur {
		req.Hostname = name
	}
	for _, h := range []windows.Handle{w.server, w.key, w.name, w.fp, w.ok} {
		enable(h, false)
	}
	setText(w.msg, "Logging in… (this can take up to a minute)")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		st, err := w.c.Up(ctx, req)
		w.mu.Lock()
		w.result, w.err = &st, err
		w.mu.Unlock()
		postMessage(w.hwnd, wmAppLoginDone, 0, 0)
	}()
}

func (w *loginWindow) done() {
	w.mu.Lock()
	st, err := w.result, w.err
	w.mu.Unlock()
	if err != nil {
		setText(w.msg, "Couldn't log in: "+err.Error())
		for _, h := range []windows.Handle{w.server, w.key, w.name, w.fp, w.ok} {
			enable(h, true)
		}
		pSetFocus.Call(uintptr(w.key))
		return
	}
	text := "Logged in."
	if st.Self != nil {
		v := makeView(st, nil)
		text = fmt.Sprintf("Logged in as %s.", v.Self)
	}
	if st.Notice != "" {
		text += "\n\n" + st.Notice
	}
	messageBox(w.hwnd, text, appTitle, mbOK|mbIconInfo)
	if w.onDone != nil {
		w.onDone()
	}
	w.close()
}

// runLogout asks, then logs this machine out of its network.
func runLogout(c *localapi.Client, owner windows.Handle) {
	if messageBox(owner, "Log this PC out of its TailConnect network?\n\nIt disconnects, and joining again needs a new auth key.",
		appTitle, mbYesNo|mbIconWarning) != idYes {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Logout(ctx); err != nil {
		messageBox(owner, "Couldn't log out: "+err.Error(), appTitle, mbOK|mbIconError)
	}
}
