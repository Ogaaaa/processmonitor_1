#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>

using namespace std;

typedef struct LogFile
{
    char ProcessName[100];
    unsigned int pid;
    unsigned int ppid;
    unsigned int thread_cnt;
} LOGFILE;

class ThreadInfo
{
private:
    DWORD PID;
    HANDLE hThreadSnap;
    THREADENTRY32 te32;
public:
    ThreadInfo(DWORD);
    BOOL ThreadsDisplay();
};

ThreadInfo::ThreadInfo(DWORD no)
{
    PID = no;
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        cout << "Unable to create snapshot of threads" << endl;
        return;
    }
    te32.dwSize = sizeof(THREADENTRY32);
}

BOOL ThreadInfo::ThreadsDisplay()
{
    if (!Thread32First(hThreadSnap, &te32))
    {
        cout << "Error in getting the first thread" << endl;
        CloseHandle(hThreadSnap);
        return false;
    }
    do
    {
        if (te32.th32OwnerProcessID == PID)
            cout << "\tTHREAD ID : " << te32.th32ThreadID << endl;
    } while (Thread32Next(hThreadSnap, &te32));
    CloseHandle(hThreadSnap);
    return true;
}

class DLLInfo
{
private:
    DWORD PID;
    MODULEENTRY32 me32;
    HANDLE hProcessSnap;
public:
    DLLInfo(DWORD);
    BOOL DependentDLLDisplay();
};

DLLInfo::DLLInfo(DWORD no)
{
    PID = no;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        cout << "Unable to create snapshot of modules" << endl;
        return;
    }
    me32.dwSize = sizeof(MODULEENTRY32);
}

BOOL DLLInfo::DependentDLLDisplay()
{
    char arr[200];
    if (!Module32First(hProcessSnap, &me32))
    {
        cout << "FAILED to get DLL Information" << endl;
        CloseHandle(hProcessSnap);
        return false;
    }
    cout << "DEPENDENT DLLS:" << endl;
    do
    {
        wcstombs_s(NULL, arr, 200, me32.szModule, 200);
        cout << arr << endl;
    } while (Module32Next(hProcessSnap, &me32));
    CloseHandle(hProcessSnap);
    return true;
}

class ProcessInfo
{
private:
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
public:
    ProcessInfo();
    BOOL ProcessDisplay();
    BOOL ProcessLog();
};

ProcessInfo::ProcessInfo()
{
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
}

BOOL ProcessInfo::ProcessDisplay()
{
    char arr[200];
    if (!Process32First(hProcessSnap, &pe32))
    {
        cout << "Error in finding the first process" << endl;
        CloseHandle(hProcessSnap);
        return false;
    }
    do
    {
        wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
        cout << "Process: " << arr
            << " | PID: " << pe32.th32ProcessID
            << " | Threads: " << pe32.cntThreads << endl;
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return true;
}

BOOL ProcessInfo::ProcessLog()
{
    cout << "Log function placeholder" << endl;
    return true;
}

int main()
{
    ProcessInfo p;
    p.ProcessDisplay();
    return 0;
}
