// Code generated by 'go generate'; DO NOT EDIT.

package winsys

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procFwpmEngineOpen0                = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmFilterAdd0                 = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFreeMemory0                = modfwpuclnt.NewProc("FwpmFreeMemory0")
	procFwpmGetAppIdFromFileName0      = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmNetEventCreateEnumHandle0  = modfwpuclnt.NewProc("FwpmNetEventCreateEnumHandle0")
	procFwpmNetEventDestroyEnumHandle0 = modfwpuclnt.NewProc("FwpmNetEventDestroyEnumHandle0")
	procFwpmNetEventEnum3              = modfwpuclnt.NewProc("FwpmNetEventEnum3")
	procFwpmSubLayerAdd0               = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procModule32FirstW                 = modkernel32.NewProc("Module32FirstW")
)

func FwpmEngineOpen0(serverName *uint16, authnService uint32, authIdentity *uintptr, session *FWPM_SESSION0, engineHandle unsafe.Pointer) (err error) {
	r1, _, e1 := syscall.Syscall6(procFwpmEngineOpen0.Addr(), 5, uintptr(unsafe.Pointer(serverName)), uintptr(authnService), uintptr(unsafe.Pointer(authIdentity)), uintptr(unsafe.Pointer(session)), uintptr(engineHandle), 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func FwpmFilterAdd0(engineHandle uintptr, filter *FWPM_FILTER0, sd uintptr, id *uint64) (err error) {
	r1, _, e1 := syscall.Syscall6(procFwpmFilterAdd0.Addr(), 4, uintptr(engineHandle), uintptr(unsafe.Pointer(filter)), uintptr(sd), uintptr(unsafe.Pointer(id)), 0, 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func FwpmFreeMemory0(p unsafe.Pointer) {
	syscall.Syscall(procFwpmFreeMemory0.Addr(), 1, uintptr(p), 0, 0)
	return
}

func FwpmGetAppIdFromFileName0(fileName *uint16, appID unsafe.Pointer) (err error) {
	r1, _, e1 := syscall.Syscall(procFwpmGetAppIdFromFileName0.Addr(), 2, uintptr(unsafe.Pointer(fileName)), uintptr(appID), 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func FwpmNetEventCreateEnumHandle0(engineHandle uintptr, enumTemplate *FWPM_NET_EVENT_ENUM_TEMPLATE0, enumHandle unsafe.Pointer) (err error) {
	r1, _, e1 := syscall.Syscall(procFwpmNetEventCreateEnumHandle0.Addr(), 3, uintptr(engineHandle), uintptr(unsafe.Pointer(enumTemplate)), uintptr(enumHandle))
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func FwpmNetEventDestroyEnumHandle0(engineHandle uintptr, enumHandle uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procFwpmNetEventDestroyEnumHandle0.Addr(), 2, uintptr(engineHandle), uintptr(enumHandle), 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func FwpmNetEventEnum3(engineHandle uintptr, enumHandle uintptr, numEntriesRequested uint32, entries *uintptr, numEntriesReturned *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procFwpmNetEventEnum3.Addr(), 5, uintptr(engineHandle), uintptr(enumHandle), uintptr(numEntriesRequested), uintptr(unsafe.Pointer(entries)), uintptr(unsafe.Pointer(numEntriesReturned)), 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func FwpmSubLayerAdd0(engineHandle uintptr, subLayer *FWPM_SUBLAYER0, sd uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procFwpmSubLayerAdd0.Addr(), 3, uintptr(engineHandle), uintptr(unsafe.Pointer(subLayer)), uintptr(sd))
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func Module32First(snapshot Handle, moduleEntry *ModuleEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procModule32FirstW.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(moduleEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}
