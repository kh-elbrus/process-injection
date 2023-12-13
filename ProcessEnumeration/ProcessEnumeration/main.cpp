#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <winternl.h>
#include "main.h"

using namespace std;

// list of possible NTSTATUS values -> https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005)

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

void SecondMethod() {
    cout << "*** start with CreateToolhelp32Snapshot ***" << endl;
    cout << " " << endl;

    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 lppe32 = { sizeof(PROCESSENTRY32) };

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(hSnapshot, &lppe32)) {
        do {
            wprintf(L"* Process: %s \n", lppe32.szExeFile);
            wprintf(L"* Process id: %d \n", lppe32.th32ProcessID);
            
            cout << " --- " << endl;
        } while (Process32Next(hSnapshot, &lppe32));
    }

    free(hSnapshot);
}

int main()
{
    cout << "*** start with NtQuerySystemInformation ***" << endl;
    cout << " " << endl;

    // loading the ntdll
    HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
    if (hNtdll == NULL) {
        cerr << "Failed to load ntdll" << endl;
        return 1;
    }

    // getting func pointer to NtQuerySystemInformation
    PNtQuerySystemInformation pNtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        cerr << "Failed to get address of NtQuerySystemInformation" << endl;
        return 1;
    }

    // calling the func NtQuerySystemInformation with parameter SystemProcessInformation
    // first get the mem size
    ULONG bufferSize = 0x20480;
    DWORD resLen = 0;
    PSYSTEM_PROCESS_INFORMATION buffer = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferSize);
    if (buffer == NULL) {
        cerr << "Failed to allocate buffer" << endl;
        return 1;
    }

    while (pNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &resLen) == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize *= 2;
        buffer = (PSYSTEM_PROCESS_INFORMATION)realloc(buffer, bufferSize);
    }

    // getting process info
    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (processInfo->NextEntryOffset != NULL) {
        processInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)processInfo + processInfo->NextEntryOffset);
        wprintf(L"* Process ID: %d \n", processInfo->UniqueProcessId);
        wprintf(L"* Number Of Threads: %d \n", processInfo->NumberOfThreads);
        wprintf(L"* Session ID: %x \n", processInfo->SessionId);
        wprintf(L"* Exe Name: %s \n", processInfo->ImageName.Buffer);
        
        cout << " --- " << endl;
    }

    // cleaning buffer 
    free(buffer);
    FreeLibrary(hNtdll);

    SecondMethod();

    return 0;
}
