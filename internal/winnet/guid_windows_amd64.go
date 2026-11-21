package winnet

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// callGUID calls p(g, arg) with the GUID passed by value as the x64
// calling convention does: a struct larger than 8 bytes goes as a pointer
// to a copy.
func callGUID(p *windows.LazyProc, g *windows.GUID, arg unsafe.Pointer) uintptr {
	c := *g
	r, _, _ := p.Call(uintptr(unsafe.Pointer(&c)), uintptr(arg))
	return r
}
