#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
#include <wincrypt.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000

BOOL EnablePrivilege(LPCWSTR privilege) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return result && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

DWORD FindTrustedInstallerPID() {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"TrustedInstaller.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

BOOL StartTrustedInstallerService() {
    if (!EnablePrivilege(SE_LOAD_DRIVER_NAME)) {
        wprintf(L"[-] Failed to enable SeLoadDriverPrivilege\n");
        return FALSE;
    }

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        wprintf(L"[-] OpenSCManager failed (%d)\n", GetLastError());
        return FALSE;
    }
    SC_HANDLE service = OpenService(scm, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        wprintf(L"[-] OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(scm);
        return FALSE;
    }

    SERVICE_STATUS status;
    if (!QueryServiceStatus(service, &status)) {
        wprintf(L"[-] QueryServiceStatus failed (%d)\n", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return FALSE;
    }
    BOOL success = FALSE;
    if (status.dwCurrentState != SERVICE_RUNNING) {
        wprintf(L"[*] 正在启动TrustedInstaller服务...\n");
        if (!StartService(service, 0, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                wprintf(L"[-] StartService failed (%d)\n", err);
                goto cleanup;
            }
        }
        for (int i = 0; i < 15; i++) {
            Sleep(1000);
            if (!QueryServiceStatus(service, &status)) break;
            if (status.dwCurrentState == SERVICE_RUNNING) {
                success = TRUE;
                break;
            }
        }
    }
    else {
        success = TRUE;
    }

cleanup:
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return success;
}

BOOL CreateChildProcessAsTrustedInstaller(LPCWSTR commandLine) {
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        wprintf(L"[-] Failed to enable SeDebugPrivilege\n");
        return FALSE;
    }
    if (!StartTrustedInstallerService()) {
        wprintf(L"[-] Failed to start TrustedInstaller service (%d)\n", GetLastError());
        return FALSE;
    }
    DWORD pid = 0;
    for (int i = 0; i < 5; i++) {
        pid = FindTrustedInstallerPID();
        if (pid != 0) break;
        Sleep(1000);
    }
    if (pid == 0) {
        wprintf(L"[-]Installer process not found\n");
        return FALSE;
    }
    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hParent) {
        wprintf(L"[-] OpenProcess failed (%d)\n", GetLastError());
        return FALSE;
    }
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attrSize);
    if (!attrList) {
        CloseHandle(hParent);
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(HANDLE), NULL, NULL)) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return FALSE;
    }
    STARTUPINFOEX siex = { sizeof(STARTUPINFOEX) };
    PROCESS_INFORMATION pi;
    siex.lpAttributeList = attrList;

    BOOL success = CreateProcess(
        NULL,
        (LPWSTR)commandLine,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &siex.StartupInfo,
        &pi
    );
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);

    if (success) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        wprintf(L"[+] Process created with PID: %d\n", pi.dwProcessId);
        return TRUE;
    }
    else {
        wprintf(L"[-] CreateProcess failed (%d)\n", GetLastError());
        return FALSE;
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s \"command\"\n", argv[0]);
        return 1;
    }

    if (!CreateChildProcessAsTrustedInstaller(argv[1])) {
        return 1;
    }

    return 0;
}