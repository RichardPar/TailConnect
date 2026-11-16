package engine

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IP Helper calls missing from x/sys/windows.
var (
	iphlpapi                            = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeUnicastIpAddressEntry = iphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = iphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry     = iphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procInitializeIpForwardEntry        = iphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2           = iphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2           = iphlpapi.NewProc("DeleteIpForwardEntry2")
	procSetIpInterfaceEntry             = iphlpapi.NewProc("SetIpInterfaceEntry")
	procConvertInterfaceAliasToLuid     = iphlpapi.NewProc("ConvertInterfaceAliasToLuid")
)

// errno turns a NETIO_STATUS return value into an error.
func errno(r uintptr) error {
	if r == 0 {
		return nil
	}
	return windows.Errno(r)
}

func initializeUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) {
	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
}

func createUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func deleteUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func initializeIpForwardEntry(row *windows.MibIpForwardRow2) {
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
}

func createIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func deleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func setIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	r, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func interfaceAliasToLUID(alias string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0, err
	}
	var luid uint64
	r, _, _ := procConvertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&luid)))
	return luid, errno(r)
}

// SOCKADDR_INET conversions. RawSockaddrInet, RawSockaddrInet4 and
// RawSockaddrInet6 share the union's 28-byte layout.

func putSockaddr(sa *windows.RawSockaddrInet, a netip.Addr) {
	*sa = windows.RawSockaddrInet{}
	if a.Is4() {
		s := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
		s.Family = windows.AF_INET
		s.Addr = a.As4()
	} else {
		s := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
		s.Family = windows.AF_INET6
		s.Addr = a.As16()
	}
}

func sockaddrAddr(sa *windows.RawSockaddrInet) (netip.Addr, bool) {
	switch sa.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(sa)).Addr), true
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(sa)).Addr), true
	}
	return netip.Addr{}, false
}
