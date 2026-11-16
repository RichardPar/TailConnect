package main

import (
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"

	"tailconnect/internal/trayicon"
)

// Status window control IDs.
const (
	idBtnToggle = 200 + iota
	idBtnLogin
	idBtnLogout
	idList
	idCopyV4
	idCopyV6
	idCopyName
)

// statusWindow shows the connection, buttons for the actions, and the
// network's machines. Closing it only hides it.
type statusWindow struct {
	a                           *app
	hwnd                        windows.Handle
	dpi                         int32
	font, titleFont             windows.Handle
	title, self, server, detail windows.Handle
	toggle, login, logout       windows.Handle
	list, hint                  windows.Handle
	titleColor                  uint32
	hasDetail                   bool
	rows                        []peerRow
}

func rgb(r, g, b uint8) uint32 { return uint32(r) | uint32(g)<<8 | uint32(b)<<16 }

var titleColors = map[trayicon.State]uint32{
	trayicon.Connected:    rgb(0x0b, 0x76, 0x6e),
	trayicon.Disconnected: rgb(0x55, 0x5b, 0x65),
	trayicon.Problem:      rgb(0xb4, 0x53, 0x09),
}

func newStatusWindow(a *app) *statusWindow {
	w := &statusWindow{a: a}
	dpi := dpiFor(0)
	sc := func(v int32) int32 { return v * dpi / 96 }
	w.hwnd = createWindow(wsExControlParent, classWindow, appTitle, wsOverlappedWindow,
		cwUseDefault, cwUseDefault, sc(660), sc(500), 0, 0)
	w.dpi = dpiFor(w.hwnd)
	handlers[w.hwnd] = w.handle
	dialogs[w.hwnd] = true
	sendMessage(w.hwnd, wmSetIcon, 0, uintptr(a.icons[trayicon.Connected]))
	sendMessage(w.hwnd, wmSetIcon, 1, uintptr(a.bigIcons[trayicon.Connected]))

	w.font = messageFont(w.dpi, 1, false)
	w.titleFont = messageFont(w.dpi, 1.45, true)
	label := func() windows.Handle {
		return createWindow(0, "STATIC", "", wsChild|wsVisible|ssLeft|ssNoPrefix|ssEndEllipsis, 0, 0, 0, 0, w.hwnd, 0)
	}
	button := func(id uintptr, text string) windows.Handle {
		return createWindow(0, "BUTTON", text, wsChild|wsVisible|wsTabStop|bsPushButton, 0, 0, 0, 0, w.hwnd, id)
	}
	w.title, w.self, w.server = label(), label(), label()
	w.detail = createWindow(0, "STATIC", "", wsChild|wsVisible|ssLeft|ssNoPrefix, 0, 0, 0, 0, w.hwnd, 0)
	w.toggle = button(idBtnToggle, "Connect")
	w.login = button(idBtnLogin, "Log in…")
	w.logout = button(idBtnLogout, "Log out…")
	w.list = createWindow(wsExClientEdge, "SysListView32", "",
		wsChild|wsVisible|wsTabStop|lvsReport|lvsSingleSel|lvsShowSelAlways|lvsNoSortHeader, 0, 0, 0, 0, w.hwnd, idList)
	sendMessage(w.list, lvmSetExtendedListViewStyle, 0, lvsExFullRowSelect|lvsExDoubleBuffer)
	w.hint = label()
	setText(w.hint, "Double-click a machine to copy its address; right-click for more.")
	for _, h := range []windows.Handle{w.self, w.server, w.detail, w.toggle, w.login, w.logout, w.list, w.hint} {
		sendMessage(h, wmSetFont, uintptr(w.font), 1)
	}
	sendMessage(w.title, wmSetFont, uintptr(w.titleFont), 1)

	for i, c := range []struct {
		name  string
		width int32
	}{{"Machine", 150}, {"Address", 115}, {"OS", 70}, {"Account", 85}, {"Connection", 190}} {
		col := lvColumn{Mask: lvcfText | lvcfWidth, Cx: sc(c.width), Text: str(c.name)}
		sendMessage(w.list, lvmInsertColumnW, uintptr(i), uintptr(unsafe.Pointer(&col)))
	}
	w.layout()
	return w
}

func (w *statusWindow) layout() {
	sc := func(v int32) int32 { return v * w.dpi / 96 }
	r := clientRect(w.hwnd)
	width, height := r.Right-r.Left, r.Bottom-r.Top
	m := sc(16)
	full := width - 2*m
	move(w.title, m, sc(14), full, sc(32))
	move(w.self, m, sc(50), full, sc(20))
	move(w.server, m, sc(72), full, sc(20))
	// The warning line takes room only when there is one.
	y := sc(100)
	if w.hasDetail {
		move(w.detail, m, y, full, sc(36))
		y += sc(42)
	} else {
		move(w.detail, m, y, full, 0)
	}
	bh := sc(30)
	move(w.toggle, m, y, sc(120), bh)
	move(w.login, m+sc(130), y, sc(200), bh)
	move(w.logout, m+sc(340), y, sc(110), bh)
	top := y + bh + sc(14)
	move(w.list, m, top, full, height-top-sc(44))
	move(w.hint, m, height-sc(32), full, sc(20))
}

func (w *statusWindow) handle(m uint32, wp, lp uintptr) (uintptr, bool) {
	switch m {
	case wmClose:
		show(w.hwnd, swHide)
		return 0, true
	case wmSize:
		w.layout()
		return 0, true
	case wmGetMinMax:
		mm := *(**[10]int32)(unsafe.Pointer(&lp)) // MINMAXINFO; ptMinTrackSize is at index 6, 7
		mm[6], mm[7] = 520*w.dpi/96, 360*w.dpi/96
		return 0, true
	case wmCtlColorStat:
		hdc, ctl := wp, windows.Handle(lp)
		face, _, _ := pGetSysColor.Call(colorBtnFace)
		pSetBkColor.Call(hdc, face)
		switch ctl {
		case w.title:
			pSetTextColor.Call(hdc, uintptr(w.titleColor))
		case w.detail:
			pSetTextColor.Call(hdc, uintptr(titleColors[trayicon.Problem]))
		default:
			return 0, false
		}
		br, _, _ := pGetSysColorBrush.Call(colorBtnFace)
		return br, true
	case wmCommand:
		switch wp & 0xffff {
		case idBtnToggle:
			if w.a.v.CanDown {
				w.a.command(idDisconnect)
			} else {
				w.a.command(idConnect)
			}
		case idBtnLogin:
			w.a.command(idLogin)
		case idBtnLogout:
			w.a.command(idLogout)
		case idCancel: // Esc
			show(w.hwnd, swHide)
		default:
			return 0, false
		}
		return 0, true
	case wmNotify:
		h := *(**nmhdr)(unsafe.Pointer(&lp))
		if h.From != w.list {
			return 0, false
		}
		switch h.Code {
		case nmDblClk:
			if p, ok := w.selected(); ok {
				w.copy(p.Addr())
			}
		case nmRClick:
			w.peerMenu()
		}
		return 0, true
	}
	return 0, false
}

func (w *statusWindow) selected() (peerRow, bool) {
	i := int(int32(sendMessage(w.list, lvmGetNextItem, ^uintptr(0), lvniSelected)))
	if i < 0 || i >= len(w.rows) {
		return peerRow{}, false
	}
	return w.rows[i], true
}

func (w *statusWindow) copy(s string) {
	if s != "" && setClipboard(w.hwnd, s) {
		setText(w.hint, "Copied "+s)
	}
}

func (w *statusWindow) peerMenu() {
	p, ok := w.selected()
	if !ok {
		return
	}
	m, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(m)
	add := func(id uintptr, text string) {
		pAppendMenuW.Call(m, mfString, id, uintptr(unsafe.Pointer(str(text))))
	}
	if p.IPv4 != "" {
		add(idCopyV4, "Copy "+p.IPv4)
	}
	if p.IPv6 != "" {
		add(idCopyV6, "Copy "+p.IPv6)
	}
	add(idCopyName, "Copy name "+p.Name)
	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmRightButton|tpmReturnCmd, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(w.hwnd), 0)
	switch cmd {
	case idCopyV4:
		w.copy(p.IPv4)
	case idCopyV6:
		w.copy(p.IPv6)
	case idCopyName:
		w.copy(p.Name)
	}
}

func (w *statusWindow) update(v view) {
	w.titleColor = titleColors[v.Icon]
	setText(w.title, v.Title)
	self := ""
	if v.Self != "" {
		self = "This PC: " + v.Self
	}
	setText(w.self, self)
	server := ""
	if v.Server != "" {
		server = "Server: " + v.Server
		if v.DNS != "" {
			server += "      MagicDNS: " + v.DNS
		}
	}
	setText(w.server, server)
	setText(w.detail, v.Detail)
	if has := v.Detail != ""; has != w.hasDetail {
		w.hasDetail = has
		w.layout()
	}

	switch {
	case v.CanDown:
		setText(w.toggle, "Disconnect")
	default:
		setText(w.toggle, "Connect")
	}
	enable(w.toggle, v.CanUp || v.CanDown || (!v.LoggedIn && v.Title != "TailConnect service not running"))
	if v.LoggedIn {
		setText(w.login, "Change server or account…")
	} else {
		setText(w.login, "Log in…")
	}
	enable(w.logout, v.LoggedIn)
	sendMessage(w.hwnd, wmSetIcon, 0, uintptr(w.a.icons[v.Icon]))
	sendMessage(w.hwnd, wmSetIcon, 1, uintptr(w.a.bigIcons[v.Icon]))
	pInvalidateRect.Call(uintptr(w.title), 0, 1)

	if !slices.Equal(v.Peers, w.rows) {
		w.fill(v.Peers)
	}
}

// fill replaces the list's rows, keeping the selected machine selected.
func (w *statusWindow) fill(rows []peerRow) {
	sel, hadSel := w.selected()
	sendMessage(w.list, lvmDeleteAllItems, 0, 0)
	for i, p := range rows {
		it := lvItem{Mask: lvifText, Item: int32(i), Text: str(p.Name)}
		sendMessage(w.list, lvmInsertItemW, 0, uintptr(unsafe.Pointer(&it)))
		for j, s := range []string{p.Addr(), p.OS, p.User, p.Connection} {
			sub := lvItem{SubItem: int32(j + 1), Text: str(s)}
			sendMessage(w.list, lvmSetItemTextW, uintptr(i), uintptr(unsafe.Pointer(&sub)))
		}
		if hadSel && p.Name == sel.Name {
			st := lvItem{StateMask: 0x3, State: 0x3} // LVIS_SELECTED | LVIS_FOCUSED
			sendMessage(w.list, lvmSetItemState, uintptr(i), uintptr(unsafe.Pointer(&st)))
		}
	}
	w.rows = slices.Clone(rows)
}
