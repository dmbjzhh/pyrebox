from __future__ import print_function
import subprocess
import os
import time

expect_result = ["ADVAPI32.dll:AddAccessAllowedAce", "ADVAPI32.dll:InitializeAcl", "ADVAPI32.dll:InitializeSecurityDescriptor", "ADVAPI32.dll:OpenThreadToken", "ADVAPI32.dll:RegCloseKey", "ADVAPI32.dll:RegNotifyChangeKeyValue", "ADVAPI32.dll:RegOpenKeyExW", "ADVAPI32.dll:RegQueryValueExA", "ADVAPI32.dll:RegQueryValueExW", "ADVAPI32.dll:SetSecurityDescriptorDacl", "GDI32.dll:CreateBitmap", "GDI32.dll:CreateCompatibleDC", "GDI32.dll:CreateSolidBrush", "GDI32.dll:GdiDllInitialize", "GDI32.dll:GdiProcessSetup", "GDI32.dll:GetStockObject", "GDI32.dll:SelectObject", "GDI32.dll:SetBkColor", "GDI32.dll:SetBkMode", "GDI32.dll:SetTextColor", "IMM32.DLL:ImmRegisterClient", "LPK.DLL:LpkDllInitialize", "LPK.DLL:LpkInitialize", "RPCRT4.dll:RpcBindingFree", "RPCRT4.dll:RpcBindingFromStringBindingW", "RPCRT4.dll:RpcBindingSetAuthInfoExW", "RPCRT4.dll:RpcStringBindingComposeW", "USER32.dll:GetAppCompatFlags2", "USER32.dll:InitializeLpkHooks", "USER32.dll:User32InitializeImmEntryTable", "USER32.dll:UserClientDllInitialize", "USP10.dll:LpkPresent", "USP10.dll:ScriptGetProperties", "WS2HELP.dll:WahCloseApcHelper", "WS2HELP.dll:WahCreateHandleContextTable", "WS2HELP.dll:WahEnumerateHandleContexts", "WS2HELP.dll:WahInsertHandleContext", "WS2HELP.dll:WahOpenApcHelper", "WS2HELP.dll:WahOpenCurrentThread", "WS2HELP.dll:WahReferenceContextByHandle", "WS2HELP.dll:WahRemoveHandleContext", "WS2_32.dll:WSACleanup", "WS2_32.dll:WSAStartup", "WS2_32.dll:closesocket", "WS2_32.dll:connect", "WS2_32.dll:inet_addr", "WS2_32.dll:ntohs", "WS2_32.dll:socket", "hnetcfg.dll:IcfConnect", "hnetcfg.dll:IcfDisconnect", "kernel32.dll:BaseProcessInitPostImport", "kernel32.dll:CloseHandle", "kernel32.dll:CreateEventA", "kernel32.dll:CreateEventW", "kernel32.dll:DisableThreadLibraryCalls", "kernel32.dll:DuplicateHandle", "kernel32.dll:ExitProcess", "kernel32.dll:ExpandEnvironmentStringsA", "kernel32.dll:ExpandEnvironmentStringsW", "kernel32.dll:FreeEnvironmentStringsW", "kernel32.dll:FreeLibrary", "kernel32.dll:GetACP", "kernel32.dll:GetCPInfo", "kernel32.dll:GetCommandLineA", "kernel32.dll:GetCommandLineW", "kernel32.dll:GetCurrentProcess", "kernel32.dll:GetCurrentProcessId", "kernel32.dll:GetCurrentThread", "kernel32.dll:GetCurrentThreadId", "kernel32.dll:GetEnvironmentStringsW", "kernel32.dll:GetEnvironmentVariableA", "kernel32.dll:GetFileType", "kernel32.dll:GetModuleFileNameA", "kernel32.dll:GetModuleHandleA", "kernel32.dll:GetModuleHandleW", "kernel32.dll:GetProcAddress", "kernel32.dll:GetProcessHeap", "kernel32.dll:GetStartupInfoA", "kernel32.dll:GetStdHandle", "kernel32.dll:GetStringTypeW", "kernel32.dll:GetSystemDirectoryW", "kernel32.dll:GetSystemInfo", "kernel32.dll:GetSystemTimeAsFileTime", "kernel32.dll:GetTickCount", "kernel32.dll:GetUserDefaultLCID", "kernel32.dll:GetVersionExA", "kernel32.dll:GlobalAlloc", "kernel32.dll:GlobalMemoryStatusEx", "kernel32.dll:HeapCreate", "kernel32.dll:InitializeCriticalSection", "kernel32.dll:InitializeCriticalSectionAndSpinCount", "kernel32.dll:InterlockedCompareExchange", "kernel32.dll:InterlockedDecrement", "kernel32.dll:InterlockedExchange", "kernel32.dll:InterlockedExchangeAdd", "kernel32.dll:InterlockedIncrement", "kernel32.dll:IsBadWritePtr", "kernel32.dll:LCMapStringW", "kernel32.dll:LoadLibraryA", "kernel32.dll:LoadLibraryW", "kernel32.dll:LocalAlloc", "kernel32.dll:LocalFree", "kernel32.dll:MultiByteToWideChar", "kernel32.dll:QueryPerformanceCounter", "kernel32.dll:RegisterWaitForInputIdle", "kernel32.dll:SetHandleCount", "kernel32.dll:SetUnhandledExceptionFilter", "kernel32.dll:SwitchToThread", "kernel32.dll:TlsAlloc", "kernel32.dll:TlsFree", "kernel32.dll:TlsGetValue", "kernel32.dll:TlsSetValue", "kernel32.dll:WaitForSingleObject", "kernel32.dll:WideCharToMultiByte", "kernel32.dll:WriteFile", "kernel32.dll:lstrcmp", "kernel32.dll:lstrcpy", "msvcrt.dll:__getmainargs", "msvcrt.dll:__p__environ", "msvcrt.dll:__p__fmode", "msvcrt.dll:__set_app_type", "msvcrt.dll:_cexit", "msvcrt.dll:_initterm", "msvcrt.dll:atexit", "msvcrt.dll:free", "msvcrt.dll:malloc", "msvcrt.dll:puts", "msvcrt.dll:sprintf", "msvcrt.dll:wcscat", "msvcrt.dll:wcscpy", "msvcrt.dll:wcslen", "mswsock.dll:WSPStartup", "ntdll.dll:CsrAllocateCaptureBuffer", "ntdll.dll:CsrCaptureMessageBuffer", "ntdll.dll:CsrClientCallServer", "ntdll.dll:CsrClientConnectToServer", "ntdll.dll:CsrFreeCaptureBuffer", "ntdll.dll:CsrNewThread", "ntdll.dll:KiFastSystemCall", "ntdll.dll:LdrDisableThreadCalloutsForDll", "ntdll.dll:LdrEnumerateLoadedModules", "ntdll.dll:LdrFindResourceDirectory_U", "ntdll.dll:LdrFindResourceEx_U", "ntdll.dll:LdrGetDllHandle", "ntdll.dll:LdrGetProcedureAddress", "ntdll.dll:LdrLoadDll", "ntdll.dll:LdrLockLoaderLock", "ntdll.dll:LdrSetDllManifestProber", "ntdll.dll:LdrShutdownProcess", "ntdll.dll:LdrUnloadDll", "ntdll.dll:LdrUnlockLoaderLock", "ntdll.dll:NtSetInformationThread", "ntdll.dll:NtWaitForMultipleObjects", "ntdll.dll:RtlAcquirePebLock", "ntdll.dll:RtlAcquireResourceExclusive", "ntdll.dll:RtlActivateActivationContextUnsafeFast", "ntdll.dll:RtlAddAccessAllowedAce", "ntdll.dll:RtlAllocateHeap", "ntdll.dll:RtlAnsiStringToUnicodeString", "ntdll.dll:RtlAreBitsSet", "ntdll.dll:RtlClearBits", "ntdll.dll:RtlCopyLuid", "ntdll.dll:RtlCreateAcl", "ntdll.dll:RtlCreateHeap", "ntdll.dll:RtlCreateSecurityDescriptor", "ntdll.dll:RtlCreateTagHeap", "ntdll.dll:RtlCreateUnicodeStringFromAsciiz", "ntdll.dll:RtlDeactivateActivationContextUnsafeFast", "ntdll.dll:RtlDecodePointer", "ntdll.dll:RtlDeleteCriticalSection", "ntdll.dll:RtlDeleteResource", "ntdll.dll:RtlDestroyHandleTable", "ntdll.dll:RtlDllShutdownInProgress", "ntdll.dll:RtlEncodePointer", "ntdll.dll:RtlEnterCriticalSection", "ntdll.dll:RtlEnumerateGenericTableWithoutSplaying", "ntdll.dll:RtlEqualUnicodeString", "ntdll.dll:RtlExpandEnvironmentStrings_U", "ntdll.dll:RtlFindClearBitsAndSet", "ntdll.dll:RtlFreeAnsiString", "ntdll.dll:RtlFreeHeap", "ntdll.dll:RtlGetLastWin32Error", "ntdll.dll:RtlGetNtProductType", "ntdll.dll:RtlGetNtVersionNumbers", "ntdll.dll:RtlGetVersion", "ntdll.dll:RtlImageNtHeader", "ntdll.dll:RtlInitAnsiString", "ntdll.dll:RtlInitString", "ntdll.dll:RtlInitUnicodeString", "ntdll.dll:RtlInitUnicodeStringEx", "ntdll.dll:RtlInitializeCriticalSection", "ntdll.dll:RtlInitializeCriticalSectionAndSpinCount", "ntdll.dll:RtlInitializeGenericTable", "ntdll.dll:RtlInitializeHandleTable", "ntdll.dll:RtlInitializeResource", "ntdll.dll:RtlInitializeSid", "ntdll.dll:RtlIntegerToUnicodeString", "ntdll.dll:RtlIpv4StringToAddressA", "ntdll.dll:RtlLeaveCriticalSection", "ntdll.dll:RtlLengthRequiredSid", "ntdll.dll:RtlMultiByteToUnicodeN", "ntdll.dll:RtlNtStatusToDosError", "ntdll.dll:RtlNumberGenericTableElements", "ntdll.dll:RtlQueryEnvironmentVariable_U", "ntdll.dll:RtlReleasePebLock", "ntdll.dll:RtlReleaseResource", "ntdll.dll:RtlRestoreLastWin32Error", "ntdll.dll:RtlSetCriticalSectionSpinCount", "ntdll.dll:RtlSetDaclSecurityDescriptor", "ntdll.dll:RtlSetThreadPoolStartFunc", "ntdll.dll:RtlSizeHeap", "ntdll.dll:RtlSubAuthoritySid", "ntdll.dll:RtlTimeToSecondsSince1980", "ntdll.dll:RtlUnicodeStringToAnsiString", "ntdll.dll:RtlUnicodeToMultiByteN", "ntdll.dll:RtlUnicodeToMultiByteSize", "ntdll.dll:ZwCallbackReturn", "ntdll.dll:ZwClose", "ntdll.dll:ZwCreateEvent", "ntdll.dll:ZwCreateFile", "ntdll.dll:ZwDeviceIoControlFile", "ntdll.dll:ZwDuplicateObject", "ntdll.dll:ZwMapViewOfSection", "ntdll.dll:ZwNotifyChangeKey", "ntdll.dll:ZwOpenKey", "ntdll.dll:ZwOpenProcessToken", "ntdll.dll:ZwOpenSection", "ntdll.dll:ZwOpenThreadToken", "ntdll.dll:ZwQueryDefaultLocale", "ntdll.dll:ZwQueryInformationProcess", "ntdll.dll:ZwQueryInformationToken", "ntdll.dll:ZwQueryPerformanceCounter", "ntdll.dll:ZwQuerySection", "ntdll.dll:ZwQuerySystemInformation", "ntdll.dll:ZwQuerySystemTime", "ntdll.dll:ZwQueryValueKey", "ntdll.dll:ZwQueryVirtualMemory", "ntdll.dll:ZwSetInformationObject", "ntdll.dll:ZwTerminateProcess", "ntdll.dll:ZwWaitForSingleObject", "ntdll.dll:ZwYieldExecution", "ntdll.dll:_allmul", "ntdll.dll:_alloca_probe", "ntdll.dll:_stricmp", "ntdll.dll:_wcsicmp", "ntdll.dll:memmove", "ntdll.dll:wcschr", "ntdll.dll:wcscpy", "ntdll.dll:wcslen", "ntdll.dll:wcsncmp", "ntdll.dll:wcsrchr", "rasadhlp.dll:WSAttemptAutodialAddr", "wshtcpip.dll:WSHGetSockaddrType", "wshtcpip.dll:WSHGetSocketInformation", "wshtcpip.dll:WSHGetWildcardSockaddr", "wshtcpip.dll:WSHNotify", "wshtcpip.dll:WSHOpenSocket2", "wshtcpip.dll:WSHSetSocketInformation"]
ls = len(expect_result)

target_procname = "zk.exe"

# set pyrebox.conf
try:
    f1 = open("pyrebox.conf.mdump", "r")
    f2 = open("pyrebox.conf", "w")

    for line in f1:
        if "plugins.guest_agent: True" in line:
            line = line.replace("True", "False")

        if "scripts.mdump_syscall: False" in line:
            line = line.replace("False", "True")

        if "target:" in line:
            line = line.replace(line, "target: {}\n".format(target_procname))
        f2.write(line)
finally:
    if f1:
        f1.close()
    if f2:
        f2.close()

print("start pyrebox")
p = subprocess.Popen("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../pyrebox_venv/images/WinXP.qcow2,index=0,media=disk,format=qcow2,cache=unsafe -loadvm clean", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
res = p.poll()
start_time = time.time()
while res is None:
    line = p.stdout.readline()
    if "-->" in line:
        li = line.split("mod:")[1][:-11].replace(",func","")
        if li in expect_result:
            expect_result.remove(li)
            if len(expect_result) <= 0:
                p.stdin.write('q\n')
        if time.time() - start_time > 30:
            p.stdin.write('q\n')
    res = p.poll()

if len(expect_result) > 0:
    print("Expect result coverage is {:.2%}".format(float(len(expect_result)) / float(ls)))
else:
    print("No bug in the code.")

