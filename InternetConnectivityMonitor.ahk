#Requires AutoHotkey v1.1.0+
;==============================================================
; InternetConnectivityMonitor — Internet connect/disconnect event monitor (NLM events + connectivity query)
;
; GitHub: https://github.com/SevenKeyboard/internet-connectivity-monitor
; Author: SevenKeyboard Ltd. (2025)
; License: MIT License
;
; Documentation / References:
;   Alert on internet connect or disconnect
;     https://www.autohotkey.com/boards/viewtopic.php?t=113844
;==============================================================

/*
Example Usage:
    #SingleInstance Force
    #Persistent
    fn := func("callback")
    InternetConnectivityMonitor.onEvent(fn)
    callback(connectivity)    {
        msgbox % connectivity
    }
    F2::msgbox % InternetConnectivityMonitor.isConnected()
    F3::msgbox % InternetConnectivityMonitor.isConnected(true)
*/

class VersionManager_InternetConnectivityMonitor
{
    static _ := VersionManager_InternetConnectivityMonitor._init()
    _init()    {
        global
        INTERNETCONNECTIVITYMONITOR_VERSION := "1.0.1"
    }
}
class InternetConnectivityMonitor
{
    static _isConnected := false
        ,_callbacks := []
        ,_activeCallbackInvoker     := objBindMethod(InternetConnectivityMonitor, "_invokeCallbacks", true)
        ,_inactiveCallbackInvoker   := objBindMethod(InternetConnectivityMonitor, "_invokeCallbacks", false)
    isConnected(useCache := false)    {
        local
        static NLM_CONNECTIVITY_IPV4_INTERNET   := 0x40
            ,NLM_CONNECTIVITY_IPV6_INTERNET     := 0x400
        switch (!!useCache)
        {
            case true:
                if (!this._initNetworkMonitoring())
                    return false
                return this._isConnected
            default:
                if (!this._initNetworkListManager())
                    return false
                try  {
                    connectivity := this._networkListManager.getConnectivity()
                }  catch  {
                    return false
                }
                return (connectivity & NLM_CONNECTIVITY_IPV4_INTERNET || connectivity & NLM_CONNECTIVITY_IPV6_INTERNET)
        }
    }
    onEvent(callback, addRemove := 1)    {
        local
        this._initNetworkMonitoring()
        for i, v in this._callbacks    {
            if (v == callback)    {
                this._callbacks.removeAt(i)
                break
            }
        }
        switch (addRemove)
        {
            case 1:     this._callbacks.push(callback)
            case -1:    this._callbacks.insertAt(1, callback)
        }
    }
    isEventRegistered(callback)    {
        local
        for i, v in this._callbacks    {
            if (v == callback)
                return true
        }
        return false
    }
    ;------------------------------------
    delayedInvokeTimer(connectivity, delayTick := 1)    { ;  Do not call directly.
        local
        this._isConnected := connectivity
        switch (connectivity)
        {
            case true:  fn := this._activeCallbackInvoker
            default:    fn := this._inactiveCallbackInvoker
        }
        setTimer % fn, % -abs(delayTick)
    }
    _invokeCallbacks(connectivity)    {
        local
        for _, v in this._callbacks
            v.call(connectivity)
    }
    _initNetworkListManager()    {
        local
        static CLSID_NetworkListManager := "{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"
        if (!this.hasKey("_networkListManager"))    {
            try  {
                this._networkListManager := comObjCreate(CLSID_NetworkListManager)
            }  finally  {
                if (this.hasKey("_networkListManager") && this._networkListManager == "")
                    this.delete("_networkListManager")
            }
        }
        return (this.hasKey("_networkListManager"))
    }
    _initNetworkMonitoring()    {
        ;  global callbackTable
        local
        static isInitialized := false
            ,IID_IConnectionPointContainer  := "{B196B284-BAB4-101A-B69C-00AA00341D07}"
            ,IID_INetworkListManagerEvents  := "{DCB00001-570F-4A9B-8D69-199FDBA5723B}"
            ,NLM_CONNECTIVITY_IPV4_INTERNET := 0x40
            ,NLM_CONNECTIVITY_IPV6_INTERNET := 0x400
            ,GMEM_FIXED := 0x0000
            ,S_OK := 0x00000000
        if (isInitialized)
            return true
        if (!this._initNetworkListManager())
            return false
        try  {
            connectivity := this._networkListManager.getConnectivity()
        }  catch  {
            return false
        }
        internetExist:= this._isConnected:= (connectivity & NLM_CONNECTIVITY_IPV4_INTERNET || connectivity & NLM_CONNECTIVITY_IPV6_INTERNET)
        events := [3    ;  QueryInterface
            ,1          ;  AddRef
            ,1          ;  Release
            ,2]         ;  ConnectivityChanged
        this.setCapacity("_callbackTable", byteSize := A_PtrSize * events.length()) ;  varSetCapacity(callbackTable, A_PtrSize * events.length(), 0)
        dllCall("Ntdll.dll\RtlFillMemory", "Ptr",this.getAddress("_callbackTable"), "UPtr",byteSize, "Int",0)
        for i, paramCount in events    {
            numPut(registerCallback("networkListManagerEventsSink_BC5A0D9D", "Fast", paramCount, i - 1)
                ,this.getAddress("_callbackTable") ;  callbackTable
                ,A_PtrSize * (i - 1))
        }
        pSink := dllCall("Kernel32.dll\GlobalAlloc", "UInt",GMEM_FIXED, "UPtr",A_PtrSize + 4, "Ptr")
        if (!pSink)
            return false
        numPut(this.getAddress("_callbackTable"), pSink + 0, 0) ;  numPut(&callbackTable, pSink + 0, 0)
        numPut(internetExist, pSink + 0, A_PtrSize, "UInt")
        connectionPointContainer := comObjQuery(this._networkListManager, IID_IConnectionPointContainer)
        if (!connectionPointContainer)    {
            dllCall("Kernel32.dll\GlobalFree", "Ptr",pSink, "Ptr")
            return false
        }
        varSetCapacity(CLSID, 16, 0)
        dllCall("Ole32.dll\CLSIDFromString", "WStr",IID_INetworkListManagerEvents, "Ptr",&CLSID, "Int")
        ;  IConnectionPointContainer::FindConnectionPoint
        hr := dllCall(numGet(numGet(connectionPointContainer + 0) + A_PtrSize * 4), "Ptr",connectionPointContainer, "Ptr",&CLSID, "Ptr*",connectionPoint, "Int")
        objRelease(connectionPointContainer)
        if (hr !== S_OK || !connectionPoint) {
            dllCall("Kernel32.dll\GlobalFree", "Ptr",pSink, "Ptr")
            return false
        }
        ;  IConnectionPoint::Advise
        hr := dllCall(numGet(numGet(connectionPoint + 0) + A_PtrSize * 5), "Ptr",connectionPoint, "Ptr",pSink, "UInt*",nCookie, "Int")
        if (hr !== S_OK || !nCookie) {
            objRelease(connectionPoint)
            dllCall("Kernel32.dll\GlobalFree", "Ptr",pSink, "Ptr")
            return false
        }
        this._connectionPoint := connectionPoint
        this._nCookie := nCookie        
        onExit(objBindMethod(this, "_onApplicationExit"))
        isInitialized := true
        return true
    }
    _onApplicationExit(exitReason, exitCode)    {
        local
        connectionPoint := this._connectionPoint
        nCookie := this._nCookie
        if (connectionPoint)    {
            ;  IConnectionPoint::Unadvise
            dllCall(numGet(numGet(connectionPoint + 0) + A_PtrSize * 6), "Ptr",connectionPoint, "UInt",nCookie, "Int")
            objRelease(connectionPoint)
        }
    }
}
networkListManagerEventsSink_BC5A0D9D(pSink, guid = "", ppvObject = "")    {
    local
    global InternetConnectivityMonitor
    static IID_IUnknown                 := "{00000000-0000-0000-C000-000000000046}"
        ,IID_INetworkListManagerEvents  := "{DCB00001-570F-4A9B-8D69-199FDBA5723B}"
        ,NLM_CONNECTIVITY_IPV4_INTERNET := 0x40
        ,NLM_CONNECTIVITY_IPV6_INTERNET := 0x400
        ,E_NOINTERFACE := 0x80004002
        ,refCount := 0
        ,p1
        ,p2
        ,internetExist
    if (!isSet(p1))    {
        varSetCapacity(p1, 16, 0)
        dllCall("Ole32.dll\CLSIDFromString", "WStr",IID_IUnknown, "Ptr",&p1, "Int")
        varSetCapacity(p2, 16, 0)
        dllCall("Ole32.dll\CLSIDFromString", "WStr",IID_INetworkListManagerEvents, "Ptr",&p2, "Int")
        internetExist := numGet(pSink + 0, A_PtrSize, "UInt")
    }
    switch (A_EventInfo)
    {
        case 0: ;  QueryInterface
            if (dllCall("Ole32.dll\IsEqualGUID", "Ptr",guid, "Ptr",&p1, "Int") || dllCall("Ole32.dll\IsEqualGUID", "Ptr",guid, "Ptr",&p2, "Int"))    {
                numPut(pSink, ppvObject + 0)
                ++refCount
                return 0
            }  else  {
                numPut(0, ppvObject + 0)
                return E_NOINTERFACE
            }
        case 1: ;  AddRef
            ++refCount
            return refCount
        case 2: ;  Release
            if (0 < refCount)    {
                --refCount
                if (refCount == 0)
                    dllCall("Kernel32.dll\GlobalFree", "Ptr",pSink, "Ptr")
            }
            return refCount
        case 3: ;  ConnectivityChanged
            if (guid & NLM_CONNECTIVITY_IPV4_INTERNET || guid & NLM_CONNECTIVITY_IPV6_INTERNET)    {
            if (!internetExist)
                InternetConnectivityMonitor.delayedInvokeTimer(internetExist := true)
            }  else  {
                if (internetExist)
                    InternetConnectivityMonitor.delayedInvokeTimer(internetExist := false)
            }
            return 0
    }
}