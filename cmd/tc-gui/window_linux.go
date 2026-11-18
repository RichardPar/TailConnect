//go:build !android

package main

import (
	"slices"
	"strconv"

	"tailconnect/internal/trayicon"
)

// statusWindow shows the connection, buttons for the actions, and the
// network's machines. Closing it only hides it.
type statusWindow struct {
	a                           *app
	win                         uintptr
	title, self, server, detail uintptr
	exit                        uintptr // the exit node button (shown when there's a choice)
	toggle, login, logout       uintptr
	store, tree, hint           uintptr
	rows                        []peerRow
}

var titleColors = map[trayicon.State]string{
	trayicon.Connected:    "#0f8f86",
	trayicon.Disconnected: "#7a808a",
	trayicon.Problem:      "#d97706",
}

func newStatusWindow(a *app) *statusWindow {
	w := &statusWindow{a: a}
	w.win = gtk_window_new(gtkWindowToplevel)
	gtk_window_set_title(w.win, appTitle+" "+version)
	gtk_window_set_default_size(w.win, 700, 500)
	gtk_window_set_position(w.win, gtkWinPosCenter)
	connect(w.win, "delete-event", 2, func([]uintptr) uintptr {
		gtk_widget_hide(w.win)
		return 1 // keep the window
	})
	connect(w.win, "key-press-event", 2, func(args []uintptr) uintptr {
		var k uint32
		if gdk_event_get_keyval(args[1], &k) && k == gdkKeyEscape {
			gtk_widget_hide(w.win)
			return 1
		}
		return 0
	})

	box := gtk_box_new(gtkOrientationVert, 6)
	gtk_container_set_border_width(box, 16)
	gtk_container_add(w.win, box)

	w.title = label("")
	w.self = label("")
	w.server = label("")
	for _, l := range []uintptr{w.self, w.server} {
		gtk_label_set_selectable(l, true)
		gtk_label_set_ellipsize(l, pangoEllipsizeEnd)
	}
	w.detail = label("")
	gtk_label_set_line_wrap(w.detail, true)
	gtk_label_set_selectable(w.detail, true)
	gtk_widget_set_no_show_all(w.detail, true)
	gtk_box_pack_start(box, w.title, false, false, 0)
	gtk_box_pack_start(box, w.self, false, false, 0)
	gtk_box_pack_start(box, w.server, false, false, 0)
	gtk_box_pack_start(box, w.detail, false, false, 0)

	buttons := gtk_box_new(gtkOrientationHoriz, 8)
	gtk_widget_set_margin_top(buttons, 6)
	gtk_widget_set_margin_bottom(buttons, 6)
	w.toggle = button("Connect", func() {
		if w.a.v.CanDown {
			w.a.disconnect()
		} else {
			w.a.connect()
		}
	})
	w.login = button("Log in…", w.a.login)
	w.logout = button("Log out…", w.a.logout)
	gtk_box_pack_start(buttons, w.toggle, false, false, 0)
	gtk_box_pack_start(buttons, w.login, false, false, 0)
	gtk_box_pack_start(buttons, w.logout, false, false, 0)
	w.exit = button("Exit node: None", func() {
		gtk_menu_popup_at_pointer(w.a.exitMenu(w.a.v), 0)
	})
	gtk_widget_set_no_show_all(w.exit, true)
	gtk_box_pack_start(buttons, w.exit, false, false, 0)
	gtk_box_pack_start(box, buttons, false, false, 0)

	w.store = newListStore(5)
	w.tree = gtk_tree_view_new_with_model(w.store)
	for i, c := range []struct {
		name  string
		width int32
	}{{"Machine", 140}, {"Address", 110}, {"OS", 70}, {"Account", 80}, {"Connection", 160}} {
		col := gtk_tree_view_column_new()
		gtk_tree_view_column_set_title(col, c.name)
		cell := gtk_cell_renderer_text_new()
		gtk_tree_view_column_pack_start(col, cell, true)
		gtk_tree_view_column_add_attribute(col, cell, "text", int32(i))
		gtk_tree_view_column_set_resizable(col, true)
		gtk_tree_view_column_set_min_width(col, c.width)
		gtk_tree_view_column_set_expand(col, i == 4)
		gtk_tree_view_append_column(w.tree, col)
	}
	connect(w.tree, "row-activated", 3, func(args []uintptr) uintptr {
		if i := pathIndex(args[1]); i >= 0 && i < len(w.rows) {
			w.copy(w.rows[i].Addr())
		}
		return 0
	})
	connect(w.tree, "button-press-event", 2, func(args []uintptr) uintptr {
		var btn uint32
		var x, y float64
		if !gdk_event_get_button(args[1], &btn) || btn != 3 || !gdk_event_get_coords(args[1], &x, &y) {
			return 0
		}
		var path, col uintptr
		if !gtk_tree_view_get_path_at_pos(w.tree, int32(x), int32(y), &path, &col, nil, nil) {
			return 1
		}
		i := pathIndex(path)
		gtk_tree_view_set_cursor(w.tree, path, 0, false)
		gtk_tree_path_free(path)
		if i >= 0 && i < len(w.rows) {
			w.peerMenu(w.rows[i], args[1])
		}
		return 1
	})
	sw := gtk_scrolled_window_new(0, 0)
	gtk_scrolled_window_set_policy(sw, gtkPolicyAutomatic, gtkPolicyAutomatic)
	gtk_scrolled_window_set_shadow(sw, gtkShadowIn)
	gtk_container_add(sw, w.tree)
	gtk_box_pack_start(box, sw, true, true, 0)

	w.hint = label("Double-click a machine to copy its address; right-click for more.")
	gtk_label_set_ellipsize(w.hint, pangoEllipsizeEnd)
	gtk_box_pack_start(box, w.hint, false, false, 0)
	gtk_widget_show_all(box)
	gtk_widget_grab_focus(w.tree) // not the selectable labels
	return w
}

func (w *statusWindow) copy(s string) {
	if s != "" {
		setClipboard(s)
		gtk_label_set_text(w.hint, "Copied "+s)
	}
}

func (w *statusWindow) peerMenu(p peerRow, event uintptr) {
	m := gtk_menu_new()
	if p.IPv4 != "" {
		menuItem(m, "Copy "+p.IPv4, true, func() { w.copy(p.IPv4) })
	}
	if p.IPv6 != "" {
		menuItem(m, "Copy "+p.IPv6, true, func() { w.copy(p.IPv6) })
	}
	menuItem(m, "Copy name "+p.Name, true, func() { w.copy(p.Name) })
	gtk_widget_show_all(m)
	gtk_menu_popup_at_pointer(m, event)
}

func (w *statusWindow) update(v view) {
	gtk_label_set_markup(w.title, `<span size="x-large" weight="bold" foreground="`+titleColors[v.Icon]+`">`+markup(v.Title)+`</span>`)
	self := ""
	if v.Self != "" {
		self = "This computer: " + v.Self
	}
	gtk_label_set_text(w.self, self)
	server := ""
	if v.Server != "" {
		server = "Server: " + v.Server
		if v.DNS != "" {
			server += "      MagicDNS: " + v.DNS
		}
	}
	gtk_label_set_text(w.server, server)
	if v.Detail != "" {
		gtk_label_set_markup(w.detail, `<span foreground="`+titleColors[trayicon.Problem]+`">`+markup(v.Detail)+`</span>`)
		gtk_widget_show(w.detail)
	} else {
		gtk_widget_hide(w.detail)
	}

	if v.CanDown {
		gtk_button_set_label(w.toggle, "Disconnect")
	} else {
		gtk_button_set_label(w.toggle, "Connect")
	}
	gtk_widget_set_sensitive(w.toggle, v.CanUp || v.CanDown || (!v.LoggedIn && v.Title != titleNoService))
	if v.LoggedIn {
		gtk_button_set_label(w.login, "Change server or account…")
	} else {
		gtk_button_set_label(w.login, "Log in…")
	}
	gtk_widget_set_sensitive(w.login, v.Title != titleNoService)
	gtk_widget_set_sensitive(w.logout, v.LoggedIn)
	if v.ShowExit() {
		gtk_button_set_label(w.exit, v.ExitLabel())
		gtk_widget_show(w.exit)
	} else {
		gtk_widget_hide(w.exit)
	}
	gtk_window_set_icon_from_file(w.win, iconPath(w.a.icons, v.Icon), 0)

	if !slices.Equal(v.Peers, w.rows) {
		w.fill(v.Peers)
	}
}

// fill replaces the list's rows, keeping the selected machine selected.
func (w *statusWindow) fill(rows []peerRow) {
	sel := ""
	var path, col uintptr
	gtk_tree_view_get_cursor(w.tree, &path, &col)
	if i := pathIndex(path); i >= 0 && i < len(w.rows) {
		sel = w.rows[i].Name
	}
	if path != 0 {
		gtk_tree_path_free(path)
	}
	gtk_list_store_clear(w.store)
	for _, p := range rows {
		appendRow(w.store, []string{p.Name, p.Addr(), p.OS, p.User, p.Connection})
	}
	w.rows = slices.Clone(rows)
	for i, p := range rows {
		if sel != "" && p.Name == sel {
			path := gtk_tree_path_new_from_string(strconv.Itoa(i))
			gtk_tree_view_set_cursor(w.tree, path, 0, false)
			gtk_tree_path_free(path)
		}
	}
}
