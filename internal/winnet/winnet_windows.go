// Package winnet has the Windows IP Helper and DNS calls missing from
// golang.org/x/sys/windows, for the router and the DNS configurator.
package winnet

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

func InitializeUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) {
	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
}

func CreateUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func DeleteUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func InitializeIpForwardEntry(row *windows.MibIpForwardRow2) {
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
}

func CreateIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func DeleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func SetIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	r, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	return errno(r)
}

func InterfaceAliasToLUID(alias string) (uint64, error) {
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

func PutSockaddr(sa *windows.RawSockaddrInet, a netip.Addr) {
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

func SockaddrAddr(sa *windows.RawSockaddrInet) (netip.Addr, bool) {
	switch sa.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(sa)).Addr), true
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(sa)).Addr), true
	}
	return netip.Addr{}, false
}

var (
	procConvertInterfaceLuidToGuid = iphlpapi.NewProc("ConvertInterfaceLuidToGuid")
	procSetInterfaceDnsSettings    = iphlpapi.NewProc("SetInterfaceDnsSettings")
	dnsapi                         = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache      = dnsapi.NewProc("DnsFlushResolverCache")
)

// LUIDToGUID returns the interface GUID of an interface LUID.
func LUIDToGUID(luid uint64) (windows.GUID, error) {
	var g windows.GUID
	r, _, _ := procConvertInterfaceLuidToGuid.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&g)))
	return g, errno(r)
}

// DNS_INTERFACE_SETTINGS flags.
const (
	DNSSettingIPv6                = 0x0001
	DNSSettingNameServer          = 0x0002
	DNSSettingSearchList          = 0x0004
	DNSSettingRegistrationEnabled = 0x0008
	DNSSettingDomain              = 0x0020
)

// DNSInterfaceSettings is DNS_INTERFACE_SETTINGS (version 1).
type DNSInterfaceSettings struct {
	Version             uint32
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

// SetInterfaceDNSSettings sets the fields of s named by s.Flags on the
// interface (Windows 10 2004 and later).
func SetInterfaceDNSSettings(guid windows.GUID, s *DNSInterfaceSettings) error {
	if err := procSetInterfaceDnsSettings.Find(); err != nil {
		return err
	}
	s.Version = 1
	r, _, _ := procSetInterfaceDnsSettings.Call(
		uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(s)))
	return errno(r)
}

// FlushResolverCache empties the DNS client's cache (ipconfig /flushdns).
func FlushResolverCache() error {
	if err := procDnsFlushResolverCache.Find(); err != nil {
		return err
	}
	r, _, err := procDnsFlushResolverCache.Call()
	if r == 0 { // BOOL: FALSE on failure
		return err
	}
	return nil
}
