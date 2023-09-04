
#include <Windows.h>
#include <handleapi.h>
#include <processthreadsapi.h>
#include <stdint.h>
#include <string>
#include <filesystem>
#include <TlHelp32.h>

#include "steam_utils.h"

#define XSTR(s) #s
#define STR(s) XSTR(s)

#define GAME_APP_ID 1888160
#define DLL_NAME "param_field_mapper.dll"
#define GAME_REL_PATH "Game/armoredcore6.exe"
#define GAME_NAME "armoredcore6.exe"

HANDLE find_process(const char* name)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            if (_stricmp(entry.szExeFile, name) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                printf(GAME_NAME " found - PID = %lu HND = %p\n", entry.th32ProcessID, hProcess);
                CloseHandle(snapshot);
                return hProcess;
            }
        }
    }

    CloseHandle(snapshot);
    return nullptr;
}

bool inject_dll(HANDLE proc, const char* dll_path)
{
    char full_path[MAX_PATH + 1];
    SIZE_T full_path_sz = (SIZE_T)GetFullPathNameA(dll_path, MAX_PATH + 1, full_path, NULL) + 1;
    if (full_path_sz == 1 || full_path_sz > sizeof(full_path)) {
        printf("[DLL INJECT] GetFullPathNameA failed! Size = %I64d, Error = %lu\n", full_path_sz, GetLastError());
        return false;
    }
    LPVOID lib = VirtualAllocEx(proc, NULL, full_path_sz, MEM_COMMIT, PAGE_READWRITE);
    if (lib == NULL) {
        printf("[DLL INJECT] VirtualAllocEx failed! Error = %lu\n", GetLastError());
        return false;
    }
    SIZE_T n_written = 0;
    if (!WriteProcessMemory(proc, lib, full_path, full_path_sz, &n_written) || n_written != full_path_sz) {
        printf("[DLL INJECT] WriteProcessMemory failed! Error = %lu, nWritten = %I64d (expected %I64d)\n", GetLastError(), n_written, full_path_sz);
        VirtualFreeEx(proc, lib, 0, MEM_RELEASE);
        return false;
    }
    LPVOID load_lib_call = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE thread = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)load_lib_call, lib, 0, NULL);
    if (thread == NULL) {
        printf("[DLL INJECT] CreateRemoteThread failed! Error = %lu\n", GetLastError());
        VirtualFreeEx(proc, lib, 0, MEM_RELEASE);
        return false;
    }
    DWORD wait_result = WaitForSingleObject(thread, 10000);
    if (wait_result != WAIT_OBJECT_0)
        printf("[DLL INJECT] WaitForSingleObject failed! Return value = %lu, Error = %lu\n", wait_result, GetLastError());

    CloseHandle(thread);
    VirtualFreeEx(proc, lib, 0, MEM_RELEASE);
    return wait_result == WAIT_OBJECT_0;
}

int main()
{
    if (!SetEnvironmentVariableA("SteamAppId", STR(GAME_APP_ID))) {
        printf("SetEnvironmentVariable failed! Error = %lu\n", GetLastError());
        system("pause");
        return 1;
    }

    HANDLE game_proc = find_process(GAME_NAME);
    HANDLE game_thread = nullptr;
    if (!game_proc) {
        path game_path;
        if (!get_steam_game_install_dir(GAME_APP_ID, game_path)) {
                printf("get_steam_game_install_dir failed! Could not find game install directory\n");
                system("pause");
                return 1;
        }
        game_path = game_path.append(GAME_REL_PATH);
        auto game_dir = game_path.parent_path().string();
        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        PROCESS_INFORMATION pi;
        if (!CreateProcessA(game_path.string().c_str(), NULL, NULL, NULL, FALSE, DETACHED_PROCESS | CREATE_SUSPENDED, NULL, game_dir.c_str(), &si, &pi)) {
            printf(GAME_NAME " process creation failed game_dir = %s, Error = %lu\n", game_dir.c_str(), GetLastError());
            system("pause");
            return 1;
        }

        game_thread = pi.hThread;
        game_proc = pi.hProcess;
    }

    if (inject_dll(game_proc, DLL_NAME)) {
        printf("DLL injection success\n");
    }
    else {
        system("pause");
        return 1;
    }

    if (game_thread) {
        ResumeThread(game_thread);
        CloseHandle(game_thread);
    }
    CloseHandle(game_proc);
    return 0;
}