// +build windows

package main

import (
	"fmt"
	"math"
	"unsafe"
	"log"
	"time"

	"golang.org/x/sys/windows"

	// https://github.com/mellow-io/go-tun2socks
	win "./winsys"
)

func startEngine() error {
	// Open the engine with a session.
	var engine uintptr
	session := &win.FWPM_SESSION0{Flags: win.FWPM_SESSION_FLAG_DYNAMIC}
	err := win.FwpmEngineOpen0(nil, win.RPC_C_AUTHN_DEFAULT, nil, session, unsafe.Pointer(&engine))
	if err != nil {
		return fmt.Errorf("failed to open engine: %v", err)
	}

	// Add a sublayer.
	key, err := windows.GenerateGUID()
	if err != nil {
		return fmt.Errorf("failed to generate GUID: %v", err)
	}
	displayData, err := win.CreateDisplayData("Mellow", "Sublayer")
	if err != nil {
		return fmt.Errorf("failed to create display data: %v", err)
	}
	sublayer := win.FWPM_SUBLAYER0{}
	sublayer.SubLayerKey = key
	sublayer.DisplayData = *displayData
	sublayer.Weight = math.MaxUint16
	err = win.FwpmSubLayerAdd0(engine, &sublayer, 0)
	if err != nil {
		return fmt.Errorf("failed to add sublayer: %v", err)
	}

	files := []string{`C:\Windows\System32\curl.exe`, `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`}
	for _, file := range files {
		_, err := addFilter(file, engine, key)
		if err != nil {
			log.Println(err)
		}
	}

	return nil
}

func addFilter(file string, engine uintptr, key windows.GUID) (filterId uint64, err error) {

	// Allow all IPv4 traffic from the current process i.e. Mellow.
	appID, err := win.GetAppIdFromFileName(file)
	if err != nil {
		return
	}
	defer win.FwpmFreeMemory0(unsafe.Pointer(&appID))
	// Block all TCP traffic targeting port 80.
	conditions := make([]win.FWPM_FILTER_CONDITION0, 2)
	conditions[0].FieldKey = win.FWPM_CONDITION_ALE_APP_ID
	conditions[0].MatchType = win.FWP_MATCH_EQUAL
	conditions[0].ConditionValue.Type = win.FWP_BYTE_BLOB_TYPE
	conditions[0].ConditionValue.Value = uintptr(unsafe.Pointer(appID))

	conditions[1].FieldKey = win.FWPM_CONDITION_IP_REMOTE_PORT
	conditions[1].MatchType = win.FWP_MATCH_EQUAL
	conditions[1].ConditionValue.Type = win.FWP_UINT16
	conditions[1].ConditionValue.Value = uintptr(uint16(80))
	myFilterDisplayData, err := win.CreateDisplayData("Mellow", "Block all TCP traffic targeting port 80")
	if err != nil {
		return
	}
	myFilter := win.FWPM_FILTER0{}
	myFilter.FilterCondition = (*win.FWPM_FILTER_CONDITION0)(unsafe.Pointer(&conditions[0]))
	myFilter.NumFilterConditions = uint32(len(conditions))
	myFilter.DisplayData = *myFilterDisplayData
	myFilter.SubLayerKey = key
	myFilter.LayerKey = win.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	myFilter.Action.Type = win.FWP_ACTION_BLOCK
	myFilter.Weight.Type = win.FWP_UINT8
	myFilter.Weight.Value = uintptr(10)
	err = win.FwpmFilterAdd0(engine, &myFilter, 0, &filterId)
	if err != nil {
		return
	}
	return 
}

func main()  {
	log.Println(startEngine())
	time.Sleep(time.Hour)
}