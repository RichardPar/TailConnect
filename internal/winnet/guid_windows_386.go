package winnet

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// callGUID calls p(g, arg) with the GUID passed by value as the x86
// calling convention does: its 16 bytes on the stack, four 32-bit words.
func callGUID(p *windows.LazyProc, g *windows.GUID, arg unsafe.Pointer) uintptr {
	b := (*[4]uint32)(unsafe.Pointer(g))
	r, _, _ := p.Call(uintptr(b[0]), uintptr(b[1]), uintptr(b[2]), uintptr(b[3]), uintptr(arg))
	return r
}
