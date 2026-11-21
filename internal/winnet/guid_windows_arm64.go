package winnet

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// callGUID calls p(g, arg) with the GUID passed by value as the ARM64
// calling convention does: a struct of up to 16 bytes goes in two
// registers, its bytes in order.
func callGUID(p *windows.LazyProc, g *windows.GUID, arg unsafe.Pointer) uintptr {
	b := (*[2]uint64)(unsafe.Pointer(g))
	r, _, _ := p.Call(uintptr(b[0]), uintptr(b[1]), uintptr(arg))
	return r
}
