//go:build !android

package main

import (
	"github.com/ebitengine/purego"

	"tailconnect/internal/trayicon"
)

// tray is the icon in the panel. It prefers AppIndicator
// (StatusNotifierItem: Cinnamon, KDE, MATE, XFCE, GNOME with the
// AppIndicator extension), and falls back to the older XEmbed tray
// (GtkStatusIcon) where that library isn't installed.
type tray struct {
	ind  uintptr // AppIndicator, or 0
	icon uintptr // GtkStatusIcon, or 0
	menu uintptr
	open func() // left click (GtkStatusIcon only; AppIndicator always shows the menu)
}

var (
	app_indicator_new                           func(id, icon string, category int32) uintptr
	app_indicator_set_status                    func(uintptr, int32)
	app_indicator_set_icon_full                 func(ind uintptr, name, desc string)
	app_indicator_set_icon_theme_path           func(uintptr, string)
	app_indicator_set_menu                      func(ind, menu uintptr)
	app_indicator_set_title                     func(uintptr, string)
	app_indicator_set_secondary_activate_target func(ind, item uintptr)
)

func loadAppIndicator() bool {
	for _, name := range []string{"libayatana-appindicator3.so.1", "libappindicator3.so.1"} {
		lib, err := purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			continue
		}
		ok := func() (ok bool) {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			purego.RegisterLibFunc(&app_indicator_new, lib, "app_indicator_new")
			purego.RegisterLibFunc(&app_indicator_set_status, lib, "app_indicator_set_status")
			purego.RegisterLibFunc(&app_indicator_set_icon_full, lib, "app_indicator_set_icon_full")
			purego.RegisterLibFunc(&app_indicator_set_icon_theme_path, lib, "app_indicator_set_icon_theme_path")
			purego.RegisterLibFunc(&app_indicator_set_menu, lib, "app_indicator_set_menu")
			purego.RegisterLibFunc(&app_indicator_set_title, lib, "app_indicator_set_title")
			purego.RegisterLibFunc(&app_indicator_set_secondary_activate_target, lib, "app_indicator_set_secondary_activate_target")
			return true
		}()
		if ok {
			return true
		}
	}
	return false
}

func iconName(s trayicon.State) string {
	switch s {
	case trayicon.Connected:
		return "tailconnect-connected"
	case trayicon.Problem:
		return "tailconnect-problem"
	}
	return "tailconnect-disconnected"
}

// newTray shows the icon; icons is the directory holding iconName(s)+".png".
func newTray(icons string, open func()) *tray {
	t := &tray{open: open}
	if loadAppIndicator() {
		t.ind = app_indicator_new("tailconnect", iconName(trayicon.Disconnected), 0) // APPLICATION_STATUS
		app_indicator_set_icon_theme_path(t.ind, icons)
		app_indicator_set_icon_full(t.ind, iconName(trayicon.Disconnected), appTitle)
		app_indicator_set_title(t.ind, appTitle)
		app_indicator_set_status(t.ind, 1) // ACTIVE
		return t
	}
	t.icon = gtk_status_icon_new_from_file(iconPath(icons, trayicon.Disconnected))
	gtk_status_icon_set_title(t.icon, appTitle)
	connect(t.icon, "activate", 1, func([]uintptr) uintptr { t.open(); return 0 })
	connect(t.icon, "popup-menu", 3, func(a []uintptr) uintptr {
		if t.menu != 0 {
			gtk_menu_popup(t.menu, 0, 0, statusIconPositionMenu, t.icon, uint32(a[1]), uint32(a[2]))
		}
		return 0
	})
	return t
}

func iconPath(dir string, s trayicon.State) string { return dir + "/" + iconName(s) + ".png" }

// set shows the state, tooltip and menu. The menu is a new GtkMenu each
// time; the old one is freed.
func (t *tray) set(icons string, s trayicon.State, tip string, menu uintptr, defaultItem uintptr) {
	gtk_widget_show_all(menu)
	if t.ind != 0 {
		app_indicator_set_icon_full(t.ind, iconName(s), tip)
		app_indicator_set_title(t.ind, tip)
		app_indicator_set_menu(t.ind, menu)
		if defaultItem != 0 {
			app_indicator_set_secondary_activate_target(t.ind, defaultItem) // middle click
		}
	} else {
		gtk_status_icon_set_from_file(t.icon, iconPath(icons, s))
		gtk_status_icon_set_tooltip_text(t.icon, tip)
	}
	if t.icon != 0 && t.menu != 0 && t.menu != menu { // AppIndicator drops its old menu itself
		gtk_widget_destroy(t.menu)
	}
	t.menu = menu
}

// ---- notifications (libnotify, if installed) ----

var (
	notifyOK                 bool
	notify_init              func(string) bool
	notify_notification_new  func(summary, body, icon string) uintptr
	notify_notification_show func(n, err uintptr) bool
)

func initNotify() {
	lib, err := purego.Dlopen("libnotify.so.4", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return
	}
	defer func() { _ = recover() }()
	purego.RegisterLibFunc(&notify_init, lib, "notify_init")
	purego.RegisterLibFunc(&notify_notification_new, lib, "notify_notification_new")
	purego.RegisterLibFunc(&notify_notification_show, lib, "notify_notification_show")
	notifyOK = notify_init(appTitle)
}

// notify shows a desktop notification, if it can.
func notify(title, body, icon string) {
	if !notifyOK {
		return
	}
	n := notify_notification_new(title, body, icon)
	notify_notification_show(n, 0)
	g_object_unref(n)
}
