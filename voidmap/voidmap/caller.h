#pragma once

typedef void(*DrvDisablePDEV_t)(DHPDEV dhpdev);
typedef BOOL(*DrvEnableDriver_t)(ULONG version, ULONG cj, DRVENABLEDATA* pded);
typedef DHPDEV(*DrvEnablePDEV_t)(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
typedef void(*VoidFunc_t)();

void CallerSprayPalettes(DWORD size);
DHPDEV CallerHookedFunction(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
BOOL CallerInit();
BOOL CallerCallKernelFunction(PVOID function, DWORD64 rdx);