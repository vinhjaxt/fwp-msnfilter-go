// +build windows

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	// https://github.com/mellow-io/go-tun2socks
	win "./winsys"
)

func ip2Long(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}

func loop() {
	// Open the engine with a session.
	var engine uintptr
	session := &win.FWPM_SESSION0{Flags: win.FWPM_SESSION_FLAG_DYNAMIC}
	err := win.FwpmEngineOpen0(nil, win.RPC_C_AUTHN_WINNT, nil, session, unsafe.Pointer(&engine))
	if err != nil {
		log.Panicln("0", err)
	}

	enumTmpl := win.FWPM_NET_EVENT_ENUM_TEMPLATE0{}
	windows.GetSystemTimeAsFileTime(&enumTmpl.EndTime)
	log.Println(time.Unix(enumTmpl.EndTime.Nanoseconds()/1000000000, 0))
	enumTmpl.StartTime = windows.NsecToFiletime(enumTmpl.EndTime.Nanoseconds() - 6000000000000)

	conditions := make([]win.FWPM_FILTER_CONDITION0, 1)
	conditions[0].FieldKey = win.FWPM_CONDITION_IP_REMOTE_ADDRESS
	conditions[0].MatchType = win.FWP_MATCH_EQUAL
	conditions[0].ConditionValue.Type = win.FWP_UINT32
	ip := ip2Long("69.171.250.12")
	conditions[0].ConditionValue.Value = uintptr(ip)
	enumTmpl.FilterCondition = (*win.FWPM_FILTER_CONDITION0)(unsafe.Pointer(&conditions[0]))
	enumTmpl.NumFilterConditions = 1

	var enumHandle uintptr
	err = win.FwpmNetEventCreateEnumHandle0(engine, &enumTmpl, unsafe.Pointer(&enumHandle))
	if err != nil {
		log.Panicln("Error: May be admin can", err)
	}
	var numEvents uint32
	var netEventPtr uintptr
	err = win.FwpmNetEventEnum3(engine, enumHandle, windows.INFINITE, &netEventPtr, &numEvents)
	if err != nil {
		log.Panicln("2", err)
	}
	log.Println("Num events:", numEvents)
	defer win.FwpmNetEventDestroyEnumHandle0(engine, enumHandle)
	netEvents := *(*[]*win.FWPM_NET_EVENT3)(unsafe.Pointer(&reflect.SliceHeader{
		Data: netEventPtr,
		Len:  int(numEvents),
		Cap:  int(numEvents),
	}))

	for _, netEvent := range netEvents {
		log.Println("Time:", time.Unix(netEvent.Header.TimeStamp.Nanoseconds()/1000000000, 0))
		if netEvent.Header.IPVersion == win.FWP_IP_VERSION_V4 {
			log.Println(net.IPv4(netEvent.Header.LocalAddr[6], netEvent.Header.LocalAddr[5], netEvent.Header.LocalAddr[4], netEvent.Header.LocalAddr[3]),
				"=>",
				net.IPv4(netEvent.Header.RemoteAddr[6], netEvent.Header.RemoteAddr[5], netEvent.Header.RemoteAddr[4], netEvent.Header.RemoteAddr[3]))
		} else {
			log.Println(netEvent.Header.LocalAddr, "=>", netEvent.Header.RemoteAddr)
		}
		log.Println(netEvent.Header.LocalPort, "=>", netEvent.Header.RemotePort)
	}
}

func main() {
	for {
		loop()
		time.Sleep(time.Second)
	}
}
