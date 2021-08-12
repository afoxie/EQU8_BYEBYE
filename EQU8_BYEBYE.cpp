#include <Windows.h>
#include <cstdio>
#include <string>
#include <tlhelp32.h>

//
// Fuck unicode.
//
#undef PROCESSENTRY32
#undef Process32First
#undef Process32Next

/// <summary>
/// Find process ID by process name.
/// </summary>
/// <param name="ProcessName">The name of the process to find.</param>
/// <returns>The PID of the target process or 0 if not found.</returns>
DWORD
GetProcessPidByName(
    _In_ CONST CHAR* ProcessName
)
{
    PROCESSENTRY32 entry;
    HANDLE snapshot;
    DWORD targetProcessId;

    entry.dwSize = sizeof(PROCESSENTRY32);
    targetProcessId = 0;

    //
    // Create a snapshot of current processes.
    //
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    //
    // Enumerate every process until we find
    // the one that matches the desired name.
    //
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_stricmp(entry.szExeFile, ProcessName) == 0)
            {
                targetProcessId = entry.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(snapshot);

    return targetProcessId;
}

int main()
{
    int lastError;
    int lastErrorHistory;
    HANDLE ioctlHandle;

    LSTATUS status;
    HKEY equ8DriverKey;
    CHAR deviceSessionId[MAX_PATH];
    DWORD deviceSessionIdLength;
    std::string driverDeviceName;

    DWORD anticheatProcessPid;
    HANDLE anticheatProcessHandle;
    HANDLE anticheatProcessToken;
    SID_IDENTIFIER_AUTHORITY newTokenSidAuthority;
    TOKEN_MANDATORY_LABEL newTokenIntegrity;
    PSID newTokenSid;

    lastErrorHistory = 0;
    deviceSessionIdLength = sizeof(deviceSessionId);

    //
    // First, we need to open the EQU8 driver key for the
    // "session ID" string which is used for the device name.
    //
    status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\EQU8_HELPER_36", 0, KEY_READ, &equ8DriverKey);
    if (status != ERROR_SUCCESS)
    {
        printf("[-] Failed to open EQU8 driver key. Have you lanuched the game at least once before? RegOpenKeyExA status = %i\n", status);
        _fgetchar();
        return 0;
    }

    //
    // Read the session ID from the registry.
    //
    status = RegQueryValueExA(equ8DriverKey, "SessionId", 0, NULL, reinterpret_cast<LPBYTE>(deviceSessionId), &deviceSessionIdLength);
    if (status != ERROR_SUCCESS)
    {
        printf("[-] Failed to query EQU8 session ID value. Have you launched the game at least once before? RegQueryValueExA status = %i\n", status);
        _fgetchar();
        return 0;
    }

    //
    // Create the full device name.
    //
    driverDeviceName = "\\??\\" + std::string(deviceSessionId);

    printf("[+] EQU8 Driver Device Path = %s.\n", driverDeviceName.c_str());
    printf("[+] Entering device open loop. Start the game.\n");

    //
    // Loop until we get a handle to the driver.
    //
    do
    {
        ioctlHandle = CreateFileA(driverDeviceName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        lastError = GetLastError();

        if (lastErrorHistory != lastError)
        {
            //
            // If the first attempt at opening the handle results in no such device,
            // this likely means that you ran this tool while the game is running.
            //
            if (lastErrorHistory == 0 && lastError == ERROR_NO_SUCH_DEVICE)
            {
                printf("[~] First attempt to open device failed. Are you sure you stopped the game before running this tool?\n");
            }
            //
            // If we go from no such device to file not found, this likely means that
            // the anti-cheat client opened a handle before we could.
            //
            if (lastErrorHistory == ERROR_NO_SUCH_DEVICE && lastError != ERROR_SUCCESS)
            {
                printf("[~] Lost race condition. Please restart the game.\n");
            }
            lastErrorHistory = lastError;
        }

    } while (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_ACCESS_DENIED || lastError == ERROR_NO_SUCH_DEVICE);

    //
    // Sanity check, we should have a handle now or
    // we received an unrecognized error.
    //
    if (ioctlHandle == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open device handle with unrecognized last error %i.\n", lastError);
        _fgetchar();
        return 0;
    }

    //
    // Wait until game launches (otherwise AC will use driver).
    //
    printf("[+] EQU8 device successfully opened with handle 0x%llx. Waiting for game launch before disabling anti-cheat process...\n", reinterpret_cast<ULONG64>(ioctlHandle));
    while (GetProcessPidByName("PortalWars-Win64-Shipping.exe") == 0)
    {
        Sleep(20);
    }

    //
    // By closing the last handle to the driver, it will unload itself.
    // 
    printf("[+] Game launch detected. Unloading EQU8 driver...\n");
    CloseHandle(ioctlHandle);

    printf("[+] EQU8 driver unloaded. You should be able to open the game process. If you get kicked, just join back (it may occasionally happen).\n");
    printf("\n[!] Press any key to exit.");
    _fgetchar();
    return 1;
}