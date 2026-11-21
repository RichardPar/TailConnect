//go:build !android

package main

// GTK 3, loaded at run time with purego: no cgo, so the binary still cross
// compiles, and it only needs libgtk-3 when it shows a window. Only the
// calls the app uses are bound. GTK runs on the main thread (see main);
// other goroutines hand it work with post.

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/ebitengine/purego"
)

// GTK, GLib and GDK enums.
const (
	gtkWindowToplevel     = 0
	gtkOrientationHoriz   = 0
	gtkOrientationVert    = 1
	gtkPolicyAutomatic    = 1
	gtkShadowIn           = 1
	gtkWinPosCenter       = 1
	gtkAlignStart         = 1
	gtkAlignEnd           = 2
	pangoEllipsizeEnd     = 3
	gtkDialogModal        = 1
	gtkDialogDestroy      = 2
	gtkMessageInfo        = 0
	gtkMessageWarning     = 1
	gtkMessageQuestion    = 2
	gtkMessageError       = 3
	gtkButtonsOK          = 1
	gtkButtonsYesNo       = 4
	gtkResponseYes        = -8
	gTypeString           = 16 << 2
	gdkKeyEscape          = 0xff1b
	gtkSelectionClipboard = 69 // GDK_SELECTION_CLIPBOARD, a predefined atom
)

// gValue is a GValue (a GType and two words of data).
type gValue struct {
	typ  uintptr
	data [2]uint64
}

// gtkIter is a GtkTreeIter.
type gtkIter struct {
	stamp int32
	_     int32
	data  [3]uintptr
}

var (
	gtk_init_check                     func(argc, argv uintptr) bool
	gtk_main                           func()
	gtk_main_quit                      func()
	g_idle_add                         func(fn, data uintptr) uint32
	g_set_prgname                      func(string)
	g_set_application_name             func(string)
	g_signal_connect_data              func(obj uintptr, signal string, fn, data, destroy uintptr, flags int32) uint64
	g_object_unref                     func(uintptr)
	g_value_init                       func(v *gValue, typ uintptr) *gValue
	g_value_set_string                 func(v *gValue, s string)
	g_value_unset                      func(v *gValue)
	gtk_widget_show_all                func(uintptr)
	gtk_widget_show                    func(uintptr)
	gtk_widget_hide                    func(uintptr)
	gtk_widget_destroy                 func(uintptr)
	gtk_widget_get_visible             func(uintptr) bool
	gtk_widget_set_sensitive           func(uintptr, bool)
	gtk_widget_set_hexpand             func(uintptr, bool)
	gtk_widget_set_vexpand             func(uintptr, bool)
	gtk_widget_set_halign              func(uintptr, int32)
	gtk_widget_set_margin_top          func(uintptr, int32)
	gtk_widget_set_margin_bottom       func(uintptr, int32)
	gtk_widget_set_no_show_all         func(uintptr, bool)
	gtk_widget_grab_focus              func(uintptr)
	gtk_widget_set_can_default         func(uintptr, bool)
	gtk_widget_get_style_context       func(uintptr) uintptr
	gtk_style_context_add_class        func(uintptr, string)
	gtk_container_add                  func(container, child uintptr)
	gtk_container_set_border_width     func(uintptr, uint32)
	gtk_window_new                     func(int32) uintptr
	gtk_window_set_title               func(uintptr, string)
	gtk_window_set_default_size        func(uintptr, int32, int32)
	gtk_window_set_position            func(uintptr, int32)
	gtk_window_set_resizable           func(uintptr, bool)
	gtk_window_set_default             func(win, widget uintptr)
	gtk_window_set_icon_from_file      func(win uintptr, path string, err uintptr) bool
	gtk_window_set_default_icon_name   func(string)
	gtk_window_set_keep_above          func(uintptr, bool)
	gtk_window_present                 func(uintptr)
	gtk_box_new                        func(orientation, spacing int32) uintptr
	gtk_box_pack_start                 func(box, child uintptr, expand, fill bool, padding uint32)
	gtk_box_pack_end                   func(box, child uintptr, expand, fill bool, padding uint32)
	gtk_grid_new                       func() uintptr
	gtk_grid_attach                    func(grid, child uintptr, left, top, width, height int32)
	gtk_grid_set_row_spacing           func(uintptr, uint32)
	gtk_grid_set_column_spacing        func(uintptr, uint32)
	gtk_label_new                      func(string) uintptr
	gtk_label_set_text                 func(uintptr, string)
	gtk_label_set_markup               func(uintptr, string)
	gtk_label_set_xalign               func(uintptr, float32)
	gtk_label_set_line_wrap            func(uintptr, bool)
	gtk_label_set_ellipsize            func(uintptr, int32)
	gtk_label_set_selectable           func(uintptr, bool)
	gtk_label_set_max_width_chars      func(uintptr, int32)
	gtk_button_new_with_label          func(string) uintptr
	gtk_button_set_label               func(uintptr, string)
	gtk_entry_new                      func() uintptr
	gtk_entry_set_text                 func(uintptr, string)
	gtk_entry_get_text                 func(uintptr) string
	gtk_entry_set_visibility           func(uintptr, bool)
	gtk_entry_set_activates_default    func(uintptr, bool)
	gtk_entry_set_placeholder_text     func(uintptr, string)
	gtk_entry_set_width_chars          func(uintptr, int32)
	gtk_scrolled_window_new            func(h, v uintptr) uintptr
	gtk_scrolled_window_set_policy     func(uintptr, int32, int32)
	gtk_scrolled_window_set_shadow     func(uintptr, int32)
	gtk_list_store_newv                func(n int32, types *uintptr) uintptr
	gtk_list_store_clear               func(uintptr)
	gtk_list_store_insert_with_valuesv func(store uintptr, iter *gtkIter, pos int32, cols *int32, vals *gValue, n int32)
	gtk_tree_view_new_with_model       func(uintptr) uintptr
	gtk_tree_view_append_column        func(tree, col uintptr) int32
	gtk_tree_view_get_cursor           func(tree uintptr, path, col *uintptr)
	gtk_tree_view_set_cursor           func(tree, path, col uintptr, edit bool)
	gtk_tree_view_get_path_at_pos      func(tree uintptr, x, y int32, path, col *uintptr, cx, cy *int32) bool
	gtk_tree_view_column_new           func() uintptr
	gtk_tree_view_column_set_title     func(uintptr, string)
	gtk_tree_view_column_pack_start    func(col, cell uintptr, expand bool)
	gtk_tree_view_column_add_attribute func(col, cell uintptr, attr string, column int32)
	gtk_tree_view_column_set_resizable func(uintptr, bool)
	gtk_tree_view_column_set_expand    func(uintptr, bool)
	gtk_tree_view_column_set_min_width func(uintptr, int32)
	gtk_cell_renderer_text_new         func() uintptr
	gtk_tree_path_get_indices          func(uintptr) *int32
	gtk_tree_path_free                 func(uintptr)
	gtk_tree_path_new_from_string      func(string) uintptr
	gtk_menu_new                       func() uintptr
	gtk_menu_item_new_with_label       func(string) uintptr
	gtk_check_menu_item_new_with_label func(string) uintptr
	gtk_check_menu_item_set_active     func(uintptr, bool)
	gtk_separator_menu_item_new        func() uintptr
	gtk_menu_item_set_submenu          func(item, menu uintptr)
	gtk_menu_shell_append              func(menu, item uintptr)
	gtk_menu_popup_at_pointer          func(menu, event uintptr)
	gtk_menu_popup                     func(menu, parentShell, parentItem, fn, data uintptr, button, time uint32)
	gtk_message_dialog_new             func(parent uintptr, flags, typ, buttons int32, format uintptr) uintptr
	gtk_message_dialog_set_markup      func(uintptr, string)
	gtk_dialog_run                     func(uintptr) int32
	gtk_clipboard_get                  func(atom uintptr) uintptr
	gtk_clipboard_set_text             func(cb uintptr, text string, n int32)
	gtk_clipboard_store                func(uintptr)
	gdk_event_get_button               func(ev uintptr, b *uint32) bool
	gdk_event_get_coords               func(ev uintptr, x, y *float64) bool
	gdk_event_get_keyval               func(ev uintptr, k *uint32) bool
	gtk_status_icon_new_from_file      func(string) uintptr
	gtk_status_icon_set_from_file      func(uintptr, string)
	gtk_status_icon_set_tooltip_text   func(uintptr, string)
	gtk_status_icon_set_title          func(uintptr, string)
	gtk_status_icon_is_embedded        func(uintptr) bool
	statusIconPositionMenu             uintptr // gtk_status_icon_position_menu, for gtk_menu_popup
)

var gtkLib uintptr

// loadGTK opens libgtk-3 and binds the functions above.
func loadGTK() (err error) {
	gtkLib, err = purego.Dlopen("libgtk-3.so.0", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("GTK 3 is needed (install libgtk-3-0): %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("GTK 3 is too old or incomplete: %v", r)
		}
	}()
	b := func(fn any, name string) { purego.RegisterLibFunc(fn, gtkLib, name) }
	b(&gtk_init_check, "gtk_init_check")
	b(&gtk_main, "gtk_main")
	b(&gtk_main_quit, "gtk_main_quit")
	b(&g_idle_add, "g_idle_add")
	b(&g_set_prgname, "g_set_prgname")
	b(&g_set_application_name, "g_set_application_name")
	b(&g_signal_connect_data, "g_signal_connect_data")
	b(&g_object_unref, "g_object_unref")
	b(&g_value_init, "g_value_init")
	b(&g_value_set_string, "g_value_set_string")
	b(&g_value_unset, "g_value_unset")
	b(&gtk_widget_show_all, "gtk_widget_show_all")
	b(&gtk_widget_show, "gtk_widget_show")
	b(&gtk_widget_hide, "gtk_widget_hide")
	b(&gtk_widget_destroy, "gtk_widget_destroy")
	b(&gtk_widget_get_visible, "gtk_widget_get_visible")
	b(&gtk_widget_set_sensitive, "gtk_widget_set_sensitive")
	b(&gtk_widget_set_hexpand, "gtk_widget_set_hexpand")
	b(&gtk_widget_set_vexpand, "gtk_widget_set_vexpand")
	b(&gtk_widget_set_halign, "gtk_widget_set_halign")
	b(&gtk_widget_set_margin_top, "gtk_widget_set_margin_top")
	b(&gtk_widget_set_margin_bottom, "gtk_widget_set_margin_bottom")
	b(&gtk_widget_set_no_show_all, "gtk_widget_set_no_show_all")
	b(&gtk_widget_grab_focus, "gtk_widget_grab_focus")
	b(&gtk_widget_set_can_default, "gtk_widget_set_can_default")
	b(&gtk_widget_get_style_context, "gtk_widget_get_style_context")
	b(&gtk_style_context_add_class, "gtk_style_context_add_class")
	b(&gtk_container_add, "gtk_container_add")
	b(&gtk_container_set_border_width, "gtk_container_set_border_width")
	b(&gtk_window_new, "gtk_window_new")
	b(&gtk_window_set_title, "gtk_window_set_title")
	b(&gtk_window_set_default_size, "gtk_window_set_default_size")
	b(&gtk_window_set_position, "gtk_window_set_position")
	b(&gtk_window_set_resizable, "gtk_window_set_resizable")
	b(&gtk_window_set_default, "gtk_window_set_default")
	b(&gtk_window_set_icon_from_file, "gtk_window_set_icon_from_file")
	b(&gtk_window_set_default_icon_name, "gtk_window_set_default_icon_name")
	b(&gtk_window_set_keep_above, "gtk_window_set_keep_above")
	b(&gtk_window_present, "gtk_window_present")
	b(&gtk_box_new, "gtk_box_new")
	b(&gtk_box_pack_start, "gtk_box_pack_start")
	b(&gtk_box_pack_end, "gtk_box_pack_end")
	b(&gtk_grid_new, "gtk_grid_new")
	b(&gtk_grid_attach, "gtk_grid_attach")
	b(&gtk_grid_set_row_spacing, "gtk_grid_set_row_spacing")
	b(&gtk_grid_set_column_spacing, "gtk_grid_set_column_spacing")
	b(&gtk_label_new, "gtk_label_new")
	b(&gtk_label_set_text, "gtk_label_set_text")
	b(&gtk_label_set_markup, "gtk_label_set_markup")
	b(&gtk_label_set_xalign, "gtk_label_set_xalign")
	b(&gtk_label_set_line_wrap, "gtk_label_set_line_wrap")
	b(&gtk_label_set_ellipsize, "gtk_label_set_ellipsize")
	b(&gtk_label_set_selectable, "gtk_label_set_selectable")
	b(&gtk_label_set_max_width_chars, "gtk_label_set_max_width_chars")
	b(&gtk_button_new_with_label, "gtk_button_new_with_label")
	b(&gtk_button_set_label, "gtk_button_set_label")
	b(&gtk_entry_new, "gtk_entry_new")
	b(&gtk_entry_set_text, "gtk_entry_set_text")
	b(&gtk_entry_get_text, "gtk_entry_get_text")
	b(&gtk_entry_set_visibility, "gtk_entry_set_visibility")
	b(&gtk_entry_set_activates_default, "gtk_entry_set_activates_default")
	b(&gtk_entry_set_placeholder_text, "gtk_entry_set_placeholder_text")
	b(&gtk_entry_set_width_chars, "gtk_entry_set_width_chars")
	b(&gtk_scrolled_window_new, "gtk_scrolled_window_new")
	b(&gtk_scrolled_window_set_policy, "gtk_scrolled_window_set_policy")
	b(&gtk_scrolled_window_set_shadow, "gtk_scrolled_window_set_shadow_type")
	b(&gtk_list_store_newv, "gtk_list_store_newv")
	b(&gtk_list_store_clear, "gtk_list_store_clear")
	b(&gtk_list_store_insert_with_valuesv, "gtk_list_store_insert_with_valuesv")
	b(&gtk_tree_view_new_with_model, "gtk_tree_view_new_with_model")
	b(&gtk_tree_view_append_column, "gtk_tree_view_append_column")
	b(&gtk_tree_view_get_cursor, "gtk_tree_view_get_cursor")
	b(&gtk_tree_view_set_cursor, "gtk_tree_view_set_cursor")
	b(&gtk_tree_view_get_path_at_pos, "gtk_tree_view_get_path_at_pos")
	b(&gtk_tree_view_column_new, "gtk_tree_view_column_new")
	b(&gtk_tree_view_column_set_title, "gtk_tree_view_column_set_title")
	b(&gtk_tree_view_column_pack_start, "gtk_tree_view_column_pack_start")
	b(&gtk_tree_view_column_add_attribute, "gtk_tree_view_column_add_attribute")
	b(&gtk_tree_view_column_set_resizable, "gtk_tree_view_column_set_resizable")
	b(&gtk_tree_view_column_set_expand, "gtk_tree_view_column_set_expand")
	b(&gtk_tree_view_column_set_min_width, "gtk_tree_view_column_set_min_width")
	b(&gtk_cell_renderer_text_new, "gtk_cell_renderer_text_new")
	b(&gtk_tree_path_get_indices, "gtk_tree_path_get_indices")
	b(&gtk_tree_path_free, "gtk_tree_path_free")
	b(&gtk_tree_path_new_from_string, "gtk_tree_path_new_from_string")
	b(&gtk_menu_new, "gtk_menu_new")
	b(&gtk_menu_item_new_with_label, "gtk_menu_item_new_with_label")
	b(&gtk_check_menu_item_new_with_label, "gtk_check_menu_item_new_with_label")
	b(&gtk_check_menu_item_set_active, "gtk_check_menu_item_set_active")
	b(&gtk_separator_menu_item_new, "gtk_separator_menu_item_new")
	b(&gtk_menu_item_set_submenu, "gtk_menu_item_set_submenu")
	b(&gtk_menu_shell_append, "gtk_menu_shell_append")
	b(&gtk_menu_popup_at_pointer, "gtk_menu_popup_at_pointer")
	b(&gtk_menu_popup, "gtk_menu_popup")
	b(&gtk_message_dialog_new, "gtk_message_dialog_new")
	b(&gtk_message_dialog_set_markup, "gtk_message_dialog_set_markup")
	b(&gtk_dialog_run, "gtk_dialog_run")
	b(&gtk_clipboard_get, "gtk_clipboard_get")
	b(&gtk_clipboard_set_text, "gtk_clipboard_set_text")
	b(&gtk_clipboard_store, "gtk_clipboard_store")
	b(&gdk_event_get_button, "gdk_event_get_button")
	b(&gdk_event_get_coords, "gdk_event_get_coords")
	b(&gdk_event_get_keyval, "gdk_event_get_keyval")
	b(&gtk_status_icon_new_from_file, "gtk_status_icon_new_from_file")
	b(&gtk_status_icon_set_from_file, "gtk_status_icon_set_from_file")
	b(&gtk_status_icon_set_tooltip_text, "gtk_status_icon_set_tooltip_text")
	b(&gtk_status_icon_set_title, "gtk_status_icon_set_title")
	b(&gtk_status_icon_is_embedded, "gtk_status_icon_is_embedded")
	statusIconPositionMenu, err = purego.Dlsym(gtkLib, "gtk_status_icon_position_menu")
	return err
}

// initGTK loads GTK and connects to the display.
func initGTK() error {
	if err := loadGTK(); err != nil {
		return err
	}
	g_set_prgname("tailconnect") // WM_CLASS, matching the .desktop file
	g_set_application_name(appTitle)
	if !gtk_init_check(0, 0) {
		return errors.New("cannot open the display (no desktop session?)")
	}
	initCallbacks()
	return nil
}

// ---- signals and callbacks ----
//
// purego callbacks are limited and never freed, so there are a few shared
// ones, by argument count; each signal's user data is the key of its Go
// handler.

var (
	cbMu     sync.Mutex
	cbFuncs  = map[uintptr]func(args []uintptr) uintptr{}
	cbNext   uintptr
	cbByArgs [5]uintptr // cbByArgs[n]: handler with n arguments before user data
	cbIdle   uintptr
	cbFree   uintptr // GClosureNotify: forgets a handler when its signal goes

	postMu    sync.Mutex
	postQueue []func()
)

func initCallbacks() {
	call := func(d uintptr, args ...uintptr) uintptr {
		cbMu.Lock()
		f := cbFuncs[d]
		cbMu.Unlock()
		if f == nil {
			return 0
		}
		return f(args)
	}
	cbByArgs[1] = purego.NewCallback(func(a, d uintptr) uintptr { return call(d, a) })
	cbByArgs[2] = purego.NewCallback(func(a, b, d uintptr) uintptr { return call(d, a, b) })
	cbByArgs[3] = purego.NewCallback(func(a, b, c, d uintptr) uintptr { return call(d, a, b, c) })
	cbByArgs[4] = purego.NewCallback(func(a, b, c, e, d uintptr) uintptr { return call(d, a, b, c, e) })
	// GTK calls this when a connection is destroyed (its widget was), so
	// handlers of menus rebuilt on every change don't pile up.
	cbFree = purego.NewCallback(func(d, _ uintptr) uintptr {
		cbMu.Lock()
		delete(cbFuncs, d)
		cbMu.Unlock()
		return 0
	})
	cbIdle = purego.NewCallback(func(uintptr) uintptr {
		postMu.Lock()
		q := postQueue
		postQueue = nil
		postMu.Unlock()
		for _, f := range q {
			f()
		}
		return 0 // G_SOURCE_REMOVE
	})
}

// connect calls f when obj emits signal; nargs is the number of the
// signal's arguments before user data (the emitter counts as one). f's
// result is the signal's return value (gboolean for events).
func connect(obj uintptr, signal string, nargs int, f func(args []uintptr) uintptr) {
	cbMu.Lock()
	cbNext++
	id := cbNext
	cbFuncs[id] = f
	cbMu.Unlock()
	g_signal_connect_data(obj, signal, cbByArgs[nargs], id, cbFree, 0)
}

// onClick runs f when a button is clicked.
func onClick(w uintptr, f func()) {
	connect(w, "clicked", 1, func([]uintptr) uintptr { f(); return 0 })
}

// onActivate runs f when a menu item is chosen.
func onActivate(it uintptr, f func()) {
	connect(it, "activate", 1, func([]uintptr) uintptr { f(); return 0 })
}

// post runs f on the GTK thread. Safe from any goroutine.
func post(f func()) {
	postMu.Lock()
	postQueue = append(postQueue, f)
	first := len(postQueue) == 1
	postMu.Unlock()
	if first {
		g_idle_add(cbIdle, 0)
	}
}

// ---- small widget helpers ----

func label(text string) uintptr {
	l := gtk_label_new(text)
	gtk_label_set_xalign(l, 0)
	return l
}

func button(text string, f func()) uintptr {
	b := gtk_button_new_with_label(text)
	onClick(b, f)
	return b
}

func menuItem(menu uintptr, text string, enabled bool, f func()) uintptr {
	it := gtk_menu_item_new_with_label(text)
	gtk_widget_set_sensitive(it, enabled)
	if f != nil {
		onActivate(it, f)
	}
	gtk_menu_shell_append(menu, it)
	return it
}

// checkMenuItem is a menu item with a check mark, ticked if active.
func checkMenuItem(menu uintptr, text string, active bool, f func()) uintptr {
	it := gtk_check_menu_item_new_with_label(text)
	gtk_check_menu_item_set_active(it, active) // before onActivate: setting it activates the item
	if f != nil {
		onActivate(it, f)
	}
	gtk_menu_shell_append(menu, it)
	return it
}

func menuSeparator(menu uintptr) {
	gtk_menu_shell_append(menu, gtk_separator_menu_item_new())
}

// markup escapes s for Pango markup.
func markup(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// messageBox shows a modal message and returns the response
// (gtkResponseYes, ...).
func messageBox(parent uintptr, text string, typ, buttons int32) int32 {
	d := gtk_message_dialog_new(parent, gtkDialogModal|gtkDialogDestroy, typ, buttons, 0)
	gtk_window_set_title(d, appTitle)
	title, body, _ := strings.Cut(text, "\n\n")
	m := "<b>" + markup(title) + "</b>"
	if body != "" {
		m += "\n\n" + markup(body)
	}
	gtk_message_dialog_set_markup(d, m)
	if parent == 0 {
		gtk_window_set_position(d, gtkWinPosCenter)
		gtk_window_set_keep_above(d, true)
	}
	r := gtk_dialog_run(d)
	gtk_widget_destroy(d)
	return r
}

func setClipboard(text string) {
	cb := gtk_clipboard_get(gtkSelectionClipboard)
	gtk_clipboard_set_text(cb, text, -1)
	gtk_clipboard_store(cb)
}

// pathIndex returns a GtkTreePath's row, for a flat list.
func pathIndex(path uintptr) int {
	if path == 0 {
		return -1
	}
	if p := gtk_tree_path_get_indices(path); p != nil {
		return int(*p)
	}
	return -1
}

// newListStore makes a GtkListStore of n string columns.
func newListStore(n int) uintptr {
	types := make([]uintptr, n)
	for i := range types {
		types[i] = gTypeString
	}
	return gtk_list_store_newv(int32(n), &types[0])
}

// appendRow adds a row of strings to a list store.
func appendRow(store uintptr, cells []string) {
	cols := make([]int32, len(cells))
	vals := make([]gValue, len(cells))
	for i, s := range cells {
		cols[i] = int32(i)
		g_value_init(&vals[i], gTypeString)
		g_value_set_string(&vals[i], s)
	}
	var it gtkIter
	gtk_list_store_insert_with_valuesv(store, &it, -1, &cols[0], &vals[0], int32(len(cells)))
	for i := range vals {
		g_value_unset(&vals[i])
	}
}
