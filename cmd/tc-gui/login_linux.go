//go:build !android

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"tailconnect/internal/localapi"
)

// ---- privileged requests: pkexec tc-gui -helper ----

// helperRequest is what the app sends `tc-gui -helper` on standard input.
type helperRequest struct {
	Op string // "up", "down" or "logout"
	Up localapi.UpRequest
}

type helperResult struct {
	Status localapi.Status
	Error  string
}

var errCancelled = errors.New("cancelled")

// privileged runs req as root: directly if this process is root, else
// through pkexec, which asks for an administrator's password.
func privileged(ctx context.Context, req helperRequest) (localapi.Status, error) {
	if os.Geteuid() == 0 {
		return doRequest(ctx, localapi.NewClient(localapi.DefaultSocket), req)
	}
	exe, err := os.Executable()
	if err != nil {
		return localapi.Status{}, err
	}
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return localapi.Status{}, errors.New("pkexec (polkit) is needed to ask for the administrator password; or use sudo tc in a terminal")
	}
	in, _ := json.Marshal(req)
	var out, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, pkexec, exe, "-helper")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(in), &out, &stderr
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case 126: // the password dialog was closed
			return localapi.Status{}, errCancelled
		case 127:
			return localapi.Status{}, errors.New("not authorized (wrong password, or no administrator rights)")
		}
	}
	var res helperResult
	if jerr := json.Unmarshal(out.Bytes(), &res); jerr != nil {
		if err == nil {
			err = jerr
		}
		if s := strings.TrimSpace(stderr.String()); s != "" {
			err = errors.New(s)
		}
		return localapi.Status{}, err
	}
	if res.Error != "" {
		return res.Status, errors.New(res.Error)
	}
	return res.Status, nil
}

func doRequest(ctx context.Context, c *localapi.Client, req helperRequest) (localapi.Status, error) {
	switch req.Op {
	case "up":
		return c.Up(ctx, req.Up)
	case "down":
		return c.Down(ctx)
	case "logout":
		return c.Logout(ctx)
	}
	return localapi.Status{}, fmt.Errorf("unknown request %q", req.Op)
}

// runHelper is `tc-gui -helper`: one request from standard input, the
// result on standard output.
func runHelper(c *localapi.Client) {
	var req helperRequest
	var res helperResult
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err == nil {
		err = json.Unmarshal(b, &req)
	}
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		res.Status, err = doRequest(ctx, c, req)
		cancel()
	}
	if err != nil {
		res.Error = err.Error()
	}
	json.NewEncoder(os.Stdout).Encode(res)
}

// ---- login ----

// loginWindow asks for the server, an auth key, the device name and (for
// self-signed servers) a certificate fingerprint, then logs in.
type loginWindow struct {
	a                     *app
	win                   uintptr
	cur                   localapi.Status
	server, key, name, fp uintptr
	msg, ok               uintptr
}

func (a *app) login() {
	if a.loginWin != nil {
		gtk_window_present(a.loginWin.win)
		return
	}
	a.loginWin = newLoginWindow(a)
}

func newLoginWindow(a *app) *loginWindow {
	w := &loginWindow{a: a}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if st, err := a.c.Status(ctx); err == nil {
		w.cur = st
	}
	cancel()

	w.win = gtk_window_new(gtkWindowToplevel)
	gtk_window_set_title(w.win, "Log in to TailConnect")
	gtk_window_set_resizable(w.win, false)
	gtk_window_set_position(w.win, gtkWinPosCenter)
	gtk_window_set_icon_from_file(w.win, iconPath(a.icons, a.v.Icon), 0)
	connect(w.win, "destroy", 1, func([]uintptr) uintptr {
		if a.loginWin == w {
			a.loginWin = nil
		}
		return 0
	})
	connect(w.win, "key-press-event", 2, func(args []uintptr) uintptr {
		var k uint32
		if gdk_event_get_keyval(args[1], &k) && k == gdkKeyEscape {
			gtk_widget_destroy(w.win)
			return 1
		}
		return 0
	})

	box := gtk_box_new(gtkOrientationVert, 10)
	gtk_container_set_border_width(box, 18)
	gtk_container_add(w.win, box)
	title := label("")
	gtk_label_set_markup(title, `<span size="large" weight="bold">Join this computer to a TailConnect network</span>`)
	gtk_box_pack_start(box, title, false, false, 0)

	grid := gtk_grid_new()
	gtk_grid_set_row_spacing(grid, 8)
	gtk_grid_set_column_spacing(grid, 12)
	gtk_box_pack_start(box, grid, false, false, 0)
	row := 0
	field := func(name, value, placeholder string) uintptr {
		gtk_grid_attach(grid, label(name), 0, int32(row), 1, 1)
		e := gtk_entry_new()
		gtk_entry_set_text(e, value)
		gtk_entry_set_placeholder_text(e, placeholder)
		gtk_entry_set_width_chars(e, 42)
		gtk_entry_set_activates_default(e, true)
		gtk_widget_set_hexpand(e, true)
		gtk_grid_attach(grid, e, 1, int32(row), 1, 1)
		row++
		return e
	}
	host := ""
	if w.cur.Self != nil {
		host = w.cur.Self.HostName
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	w.server = field("Server address", w.cur.ControlURL, "https://tailconnect.example.com:8443")
	w.key = field("Auth key", "", "tc-auth-…")
	gtk_entry_set_visibility(w.key, false)
	w.name = field("Name of this computer", host, "")
	w.fp = field("Certificate", "", "only for a self-signed server")
	fpHint := label("Only for a server with a self-signed certificate: sha256:… from its log.")
	gtk_label_set_line_wrap(fpHint, true)
	gtk_label_set_max_width_chars(fpHint, 50)
	gtk_style_context_add_class(gtk_widget_get_style_context(fpHint), "dim-label")
	gtk_grid_attach(grid, fpHint, 1, int32(row), 1, 1)

	keyHint := "From the portal (Auth keys → Generate key) or: tc-control keys create -user NAME"
	if w.loggedIn() {
		keyHint = "Already logged in: leave Auth key empty to keep this machine's login, or enter a key to re-register."
	}
	w.msg = label(keyHint)
	gtk_label_set_line_wrap(w.msg, true)
	gtk_label_set_max_width_chars(w.msg, 60)
	gtk_box_pack_start(box, w.msg, false, false, 0)

	buttons := gtk_box_new(gtkOrientationHoriz, 8)
	gtk_widget_set_halign(buttons, gtkAlignEnd)
	cancelBtn := button("Cancel", func() { gtk_widget_destroy(w.win) })
	w.ok = button("Log in", w.submit)
	gtk_style_context_add_class(gtk_widget_get_style_context(w.ok), "suggested-action")
	gtk_widget_set_can_default(w.ok, true)
	gtk_box_pack_start(buttons, cancelBtn, false, false, 0)
	gtk_box_pack_start(buttons, w.ok, false, false, 0)
	gtk_box_pack_start(box, buttons, false, false, 0)
	gtk_window_set_default(w.win, w.ok)

	gtk_widget_show_all(w.win)
	if w.cur.ControlURL == "" {
		gtk_widget_grab_focus(w.server)
	} else {
		gtk_widget_grab_focus(w.key)
	}
	gtk_window_present(w.win)
	return w
}

func (w *loginWindow) loggedIn() bool {
	return w.cur.State != localapi.StateNeedsLogin && w.cur.State != ""
}

func (w *loginWindow) enable(on bool) {
	for _, h := range []uintptr{w.server, w.key, w.name, w.fp, w.ok} {
		gtk_widget_set_sensitive(h, on)
	}
}

func (w *loginWindow) submit() {
	server := strings.TrimSpace(gtk_entry_get_text(w.server))
	key := strings.TrimSpace(gtk_entry_get_text(w.key))
	name := strings.TrimSpace(gtk_entry_get_text(w.name))
	fp := strings.TrimSpace(gtk_entry_get_text(w.fp))
	switch {
	case server == "":
		gtk_label_set_text(w.msg, "Enter the server address, e.g. https://tailconnect.example.com:8443")
		gtk_widget_grab_focus(w.server)
		return
	case key == "" && (!w.loggedIn() || server != w.cur.ControlURL):
		gtk_label_set_text(w.msg, "Enter an auth key (tc-auth-…) to join.")
		gtk_widget_grab_focus(w.key)
		return
	}
	req := localapi.UpRequest{AuthKey: key, TLSFingerprint: fp}
	if server != w.cur.ControlURL || !w.loggedIn() {
		req.ControlURL = server
	}
	cur := ""
	if w.cur.Self != nil {
		cur = w.cur.Self.HostName
	}
	if name != "" && name != cur {
		req.Hostname = name
	}
	w.enable(false)
	gtk_label_set_text(w.msg, "Logging in… (this can take up to a minute)")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		st, err := privileged(ctx, helperRequest{Op: "up", Up: req})
		post(func() { w.done(st, err) })
	}()
}

func (w *loginWindow) done(st localapi.Status, err error) {
	if w.a.loginWin != w {
		return // closed meanwhile
	}
	w.a.refresh()
	if err != nil {
		msg := "Couldn't log in: " + err.Error()
		if errors.Is(err, errCancelled) {
			msg = "Logging in needs an administrator's password."
		}
		gtk_label_set_text(w.msg, msg)
		w.enable(true)
		gtk_widget_grab_focus(w.key)
		return
	}
	text := "Logged in."
	if st.Self != nil {
		text = fmt.Sprintf("Logged in as %s.", makeView(&st, nil).Self)
	}
	if st.Notice != "" {
		text += "\n\n" + st.Notice
	}
	messageBox(w.win, text, gtkMessageInfo, gtkButtonsOK)
	gtk_widget_destroy(w.win)
}

// ---- logout ----

func (a *app) logout() {
	if messageBox(a.owner(), "Log this computer out of its TailConnect network?\n\nIt disconnects, and joining again needs a new auth key.",
		gtkMessageWarning, gtkButtonsYesNo) != gtkResponseYes {
		return
	}
	a.do("Log out", func(ctx context.Context) error {
		_, err := privileged(ctx, helperRequest{Op: "logout"})
		return err
	})
}
