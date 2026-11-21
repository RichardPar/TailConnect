package main

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Win32 calls the app uses, bound by hand (x/sys/windows has few GUI
// calls) to keep the app free of dependencies and cgo.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	// comctl32 must be loaded after the activation context (see
	// enableVisualStyles) so the version 6 controls are used.
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")

	pRegisterClassExW              = user32.NewProc("RegisterClassExW")
	pCreateWindowExW               = user32.NewProc("CreateWindowExW")
	pDefWindowProcW                = user32.NewProc("DefWindowProcW")
	pGetMessageW                   = user32.NewProc("GetMessageW")
	pTranslateMessage              = user32.NewProc("TranslateMessage")
	pDispatchMessageW              = user32.NewProc("DispatchMessageW")
	pIsDialogMessageW              = user32.NewProc("IsDialogMessageW")
	pPostMessageW                  = user32.NewProc("PostMessageW")
	pSendMessageW                  = user32.NewProc("SendMessageW")
	pPostQuitMessage               = user32.NewProc("PostQuitMessage")
	pShowWindow                    = user32.NewProc("ShowWindow")
	pIsWindowVisible               = user32.NewProc("IsWindowVisible")
	pSetForegroundWindow           = user32.NewProc("SetForegroundWindow")
	pDestroyWindow                 = user32.NewProc("DestroyWindow")
	pSetWindowTextW                = user32.NewProc("SetWindowTextW")
	pGetWindowTextW                = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW          = user32.NewProc("GetWindowTextLengthW")
	pEnableWindow                  = user32.NewProc("EnableWindow")
	pSetWindowPos                  = user32.NewProc("SetWindowPos")
	pGetClientRect                 = user32.NewProc("GetClientRect")
	pSetFocus                      = user32.NewProc("SetFocus")
	pCreatePopupMenu               = user32.NewProc("CreatePopupMenu")
	pAppendMenuW                   = user32.NewProc("AppendMenuW")
	pTrackPopupMenu                = user32.NewProc("TrackPopupMenu")
	pDestroyMenu                   = user32.NewProc("DestroyMenu")
	pSetMenuDefaultItem            = user32.NewProc("SetMenuDefaultItem")
	pGetCursorPos                  = user32.NewProc("GetCursorPos")
	pLoadCursorW                   = user32.NewProc("LoadCursorW")
	pRegisterWindowMessageW        = user32.NewProc("RegisterWindowMessageW")
	pFindWindowW                   = user32.NewProc("FindWindowW")
	pGetDpiForWindow               = user32.NewProc("GetDpiForWindow")
	pGetDpiForSystem               = user32.NewProc("GetDpiForSystem")
	pSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	pSystemParametersInfoForDpi    = user32.NewProc("SystemParametersInfoForDpi")
	pGetSystemMetricsForDpi        = user32.NewProc("GetSystemMetricsForDpi")
	pCreateIconFromResourceEx      = user32.NewProc("CreateIconFromResourceEx")
	pDestroyIcon                   = user32.NewProc("DestroyIcon")
	pOpenClipboard                 = user32.NewProc("OpenClipboard")
	pEmptyClipboard                = user32.NewProc("EmptyClipboard")
	pSetClipboardData              = user32.NewProc("SetClipboardData")
	pCloseClipboard                = user32.NewProc("CloseClipboard")
	pGetSysColorBrush              = user32.NewProc("GetSysColorBrush")
	pGetSysColor                   = user32.NewProc("GetSysColor")
	pInvalidateRect                = user32.NewProc("InvalidateRect")
	pSetTextColor                  = gdi32.NewProc("SetTextColor")
	pSetBkColor                    = gdi32.NewProc("SetBkColor")
	pShellNotifyIconW              = shell32.NewProc("Shell_NotifyIconW")
	pShellExecuteExW               = shell32.NewProc("ShellExecuteExW")
	pCreateFontIndirectW           = gdi32.NewProc("CreateFontIndirectW")
	pCreateActCtxW                 = kernel32.NewProc("CreateActCtxW")
	pActivateActCtx                = kernel32.NewProc("ActivateActCtx")
	pGlobalAlloc                   = kernel32.NewProc("GlobalAlloc")
	pGlobalLock                    = kernel32.NewProc("GlobalLock")
	pGlobalUnlock                  = kernel32.NewProc("GlobalUnlock")
	pGlobalFree                    = kernel32.NewProc("GlobalFree")
	pDeleteObject                  = gdi32.NewProc("DeleteObject")
	pInitCommonControlsEx          = comctl32.NewProc("InitCommonControlsEx")
)

const (
	wmDestroy       = 0x0002
	wmSize          = 0x0005
	wmClose         = 0x0010
	wmSetFont       = 0x0030
	wmGetMinMax     = 0x0024
	wmNotify        = 0x004E
	wmSetIcon       = 0x0080
	wmCommand       = 0x0111
	wmCtlColorStat  = 0x0138
	wmLButtonUp     = 0x0202
	wmRButtonUp     = 0x0205
	wmLButtonDblClk = 0x0203
	wmNull          = 0x0000
	wmApp           = 0x8000

	wsOverlappedWindow = 0x00CF0000
	wsCaption          = 0x00C00000
	wsSysMenu          = 0x00080000
	wsMinimizeBox      = 0x00020000
	wsChild            = 0x40000000
	wsVisible          = 0x10000000
	wsTabStop          = 0x00010000
	wsBorder           = 0x00800000
	wsExControlParent  = 0x00010000
	wsExClientEdge     = 0x00000200

	bsPushButton    = 0x0
	bsDefPushButton = 0x1
	esAutoHScroll   = 0x0080
	esPassword      = 0x0020
	ssLeft          = 0x0
	ssNoPrefix      = 0x0080
	ssEndEllipsis   = 0x4000

	swHide       = 0
	swShow       = 5
	swShowNormal = 1

	cwUseDefault = -0x80000000 // CW_USEDEFAULT

	idOK     = 1
	idCancel = 2

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfChecked   = 0x0008
	mfPopup     = 0x0010
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmBottomAlign = 0x0020

	nimAdd      = 0
	nimModify   = 1
	nimDelete   = 2
	nifMessage  = 0x01
	nifIcon     = 0x02
	nifTip      = 0x04
	nifInfo     = 0x10
	niifInfo    = 0x1
	niifWarning = 0x2

	mbOK          = 0x0
	mbYesNo       = 0x4
	mbIconError   = 0x10
	mbIconWarning = 0x30
	mbIconInfo    = 0x40
	idYes         = 6

	swpNoZOrder = 0x0004

	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	colorWindow  = 5
	colorBtnFace = 15

	smCxSmIcon = 49
	smCxIcon   = 11

	spiGetNonClientMetrics = 0x0029
)

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

type msg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	private uint32
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type notifyIconData struct {
	Size            uint32
	Wnd             windows.Handle
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            windows.Handle
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        windows.GUID
	BalloonIcon     windows.Handle
}

type logFont struct {
	Height, Width, Escapement, Orientation, Weight    int32
	Italic, Underline, StrikeOut, CharSet             uint8
	OutPrecision, ClipPrecision, Quality, PitchFamily uint8
	FaceName                                          [32]uint16
}

type nonClientMetrics struct {
	Size                                   uint32
	BorderWidth, ScrollWidth, ScrollHeight int32
	CaptionWidth, CaptionHeight            int32
	CaptionFont                            logFont
	SmCaptionWidth, SmCaptionHeight        int32
	SmCaptionFont                          logFont
	MenuWidth, MenuHeight                  int32
	MenuFont, StatusFont, MessageFont      logFont
	PaddedBorderWidth                      int32
}

type actCtx struct {
	Size                  uint32
	Flags                 uint32
	Source                *uint16
	ProcessorArchitecture uint16
	LangID                uint16
	AssemblyDirectory     *uint16
	ResourceName          uintptr // a string pointer, or a resource ID (MAKEINTRESOURCE)
	ApplicationName       *uint16
	Module                windows.Handle
}

type shellExecuteInfo struct {
	Size          uint32
	Mask          uint32
	Wnd           windows.Handle
	Verb          *uint16
	File          *uint16
	Parameters    *uint16
	Directory     *uint16
	Show          int32
	InstApp       windows.Handle
	IDList        uintptr
	Class         *uint16
	KeyClass      windows.Handle
	HotKey        uint32
	IconOrMonitor windows.Handle
	Process       windows.Handle
}

type initCommonControlsEx struct {
	Size, ICC uint32
}

// ListView.
const (
	lvmFirst                    = 0x1000
	lvmDeleteAllItems           = lvmFirst + 9
	lvmGetNextItem              = lvmFirst + 12
	lvmSetColumnWidth           = lvmFirst + 30
	lvmSetExtendedListViewStyle = lvmFirst + 54
	lvmInsertItemW              = lvmFirst + 77
	lvmSetItemTextW             = lvmFirst + 116
	lvmInsertColumnW            = lvmFirst + 97
	lvmGetItemCount             = lvmFirst + 4
	lvmSetItemState             = lvmFirst + 43

	lvsReport          = 0x0001
	lvsSingleSel       = 0x0004
	lvsShowSelAlways   = 0x0008
	lvsNoSortHeader    = 0x8000
	lvsExFullRowSelect = 0x00000020
	lvsExDoubleBuffer  = 0x00010000

	lvcfFmt      = 0x1
	lvcfWidth    = 0x2
	lvcfText     = 0x4
	lvifText     = 0x1
	lvniSelected = 0x2

	nmDblClk = ^uint32(2) // NM_DBLCLK  (-3)
	nmRClick = ^uint32(4) // NM_RCLICK  (-5)

	iccListViewClasses = 0x1
	iccStandardClasses = 0x4000
)

type lvColumn struct {
	Mask      uint32
	Fmt       int32
	Cx        int32
	Text      *uint16
	TextMax   int32
	SubItem   int32
	Image     int32
	Order     int32
	CxMin     int32
	CxDefault int32
	CxIdeal   int32
}

type lvItem struct {
	Mask      uint32
	Item      int32
	SubItem   int32
	State     uint32
	StateMask uint32
	Text      *uint16
	TextMax   int32
	Image     int32
	LParam    uintptr
	Indent    int32
	GroupID   int32
	Columns   uint32
	PuColumns uintptr
	PiColFmt  uintptr
	Group     int32
}

type nmhdr struct {
	From windows.Handle
	ID   uintptr
	Code uint32
}

func str(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

func sendMessage(h windows.Handle, m uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(uintptr(h), uintptr(m), w, l)
	return r
}

func postMessage(h windows.Handle, m uint32, w, l uintptr) {
	pPostMessageW.Call(uintptr(h), uintptr(m), w, l)
}

func createWindow(exStyle uint32, class, title string, style uint32, x, y, w, h int32, parent windows.Handle, id uintptr) windows.Handle {
	r, _, _ := pCreateWindowExW.Call(uintptr(exStyle), uintptr(unsafe.Pointer(str(class))), uintptr(unsafe.Pointer(str(title))),
		uintptr(style), uintptr(x), uintptr(y), uintptr(w), uintptr(h), uintptr(parent), id, 0, 0)
	return windows.Handle(r)
}

func setText(h windows.Handle, s string) {
	pSetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(str(s))))
}

func getText(h windows.Handle) string {
	n, _, _ := pGetWindowTextLengthW.Call(uintptr(h))
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}

func enable(h windows.Handle, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pEnableWindow.Call(uintptr(h), v)
}

func show(h windows.Handle, cmd int) { pShowWindow.Call(uintptr(h), uintptr(cmd)) }

func visible(h windows.Handle) bool {
	r, _, _ := pIsWindowVisible.Call(uintptr(h))
	return r != 0
}

func move(h windows.Handle, x, y, w, ht int32) {
	pSetWindowPos.Call(uintptr(h), 0, uintptr(x), uintptr(y), uintptr(w), uintptr(ht), swpNoZOrder)
}

func clientRect(h windows.Handle) rect {
	var r rect
	pGetClientRect.Call(uintptr(h), uintptr(unsafe.Pointer(&r)))
	return r
}

func messageBox(owner windows.Handle, text, title string, flags uint32) int32 {
	r, _ := windows.MessageBox(windows.HWND(owner), str(text), str(title), flags)
	return r
}

func dpiFor(h windows.Handle) int32 {
	if h != 0 && pGetDpiForWindow.Find() == nil {
		if r, _, _ := pGetDpiForWindow.Call(uintptr(h)); r != 0 {
			return int32(r)
		}
	}
	if pGetDpiForSystem.Find() == nil {
		if r, _, _ := pGetDpiForSystem.Call(); r != 0 {
			return int32(r)
		}
	}
	return 96
}

func systemMetric(index, dpi int32) int32 {
	if pGetSystemMetricsForDpi.Find() == nil {
		r, _, _ := pGetSystemMetricsForDpi.Call(uintptr(index), uintptr(dpi))
		return int32(r)
	}
	return 16 * dpi / 96
}

// iconFromPNG makes an icon from PNG data (Windows Vista and later accept
// PNG in icon resources).
func iconFromPNG(b []byte, size int32) windows.Handle {
	r, _, _ := pCreateIconFromResourceEx.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 1, 0x00030000,
		uintptr(size), uintptr(size), 0)
	return windows.Handle(r)
}

// messageFont returns the system's message font for dpi, optionally scaled
// and bold.
func messageFont(dpi int32, scale float64, bold bool) windows.Handle {
	var ncm nonClientMetrics
	ncm.Size = uint32(unsafe.Sizeof(ncm))
	if pSystemParametersInfoForDpi.Find() == nil {
		pSystemParametersInfoForDpi.Call(spiGetNonClientMetrics, uintptr(ncm.Size), uintptr(unsafe.Pointer(&ncm)), 0, uintptr(dpi))
	}
	lf := ncm.MessageFont
	if lf.Height == 0 {
		lf.Height = -12 * dpi / 72
		copy(lf.FaceName[:], windows.StringToUTF16("Segoe UI"))
	}
	lf.Height = int32(float64(lf.Height) * scale)
	if bold {
		lf.Weight = 600
	}
	r, _, _ := pCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	return windows.Handle(r)
}

func setClipboard(owner windows.Handle, s string) bool {
	if r, _, _ := pOpenClipboard.Call(uintptr(owner)); r == 0 {
		return false
	}
	defer pCloseClipboard.Call()
	pEmptyClipboard.Call()
	u := windows.StringToUTF16(s)
	h, _, _ := pGlobalAlloc.Call(gmemMoveable, uintptr(len(u)*2))
	if h == 0 {
		return false
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		pGlobalFree.Call(h)
		return false
	}
	copy(unsafe.Slice(*(**uint16)(unsafe.Pointer(&p)), len(u)), u)
	pGlobalUnlock.Call(h)
	if r, _, _ := pSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		pGlobalFree.Call(h) // the clipboard owns it only once it accepts it
		return false
	}
	return true
}

// commonControlsManifest asks for version 6 of the common controls, which
// draw in the current Windows style.
const commonControlsManifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency><dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
      processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly></dependency>
</assembly>
`

// enableVisualStyles activates the manifest above for this thread and
// initialises the common controls under it. (A manifest compiled into the
// .exe would do the same; this keeps the build plain `go build`.)
// enableVisualStyles turns on Common Controls 6 (themed controls). It needs
// an activation context from a manifest. The one embedded in Windows'
// shell32.dll (resource 124) asks for exactly that and only administrators
// can change it, so it's used first. A manifest file is only a fallback for
// an unelevated app: an elevated one (login, uninstall, the installer) must
// not load a manifest from a folder the user's other programs can write to,
// as it decides which DLLs are loaded.
func enableVisualStyles() {
	const (
		actCtxFlagResourceNameValid = 0x008
		shell32Manifest             = 124
	)
	sys, _ := windows.GetSystemDirectory()
	ctx := actCtx{Source: str(filepath.Join(sys, "shell32.dll")), Flags: actCtxFlagResourceNameValid,
		ResourceName: shell32Manifest}
	ctx.Size = uint32(unsafe.Sizeof(ctx))
	h, _, _ := pCreateActCtxW.Call(uintptr(unsafe.Pointer(&ctx)))
	if h == uintptr(windows.InvalidHandle) && !windows.GetCurrentProcessToken().IsElevated() {
		manifest := filepath.Join(os.TempDir(), "tailconnect-gui.manifest")
		if b, err := os.ReadFile(manifest); err != nil || string(b) != commonControlsManifest {
			_ = os.WriteFile(manifest, []byte(commonControlsManifest), 0o644)
		}
		ctx = actCtx{Source: str(manifest)}
		ctx.Size = uint32(unsafe.Sizeof(ctx))
		h, _, _ = pCreateActCtxW.Call(uintptr(unsafe.Pointer(&ctx)))
	}
	if h != uintptr(windows.InvalidHandle) {
		var cookie uintptr
		pActivateActCtx.Call(h, uintptr(unsafe.Pointer(&cookie)))
	}
	icc := initCommonControlsEx{ICC: iccListViewClasses | iccStandardClasses}
	icc.Size = uint32(unsafe.Sizeof(icc))
	pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
}

// runElevated starts this program again as Administrator (the UAC prompt)
// with args. It reports false if the user declined.
func runElevated(owner windows.Handle, args string) (bool, error) {
	exe, err := osExecutable()
	if err != nil {
		return false, err
	}
	sei := shellExecuteInfo{Wnd: owner, Verb: str("runas"), File: str(exe), Parameters: str(args), Show: swShowNormal}
	sei.Size = uint32(unsafe.Sizeof(sei))
	r, _, err := pShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == windows.ERROR_CANCELLED {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isAdmin reports whether this process has the Administrators group enabled
// (it is elevated).
func isAdmin() bool {
	tok := windows.GetCurrentProcessToken()
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return g.Attributes&windows.SE_GROUP_ENABLED != 0 && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0
		}
	}
	return false
}
