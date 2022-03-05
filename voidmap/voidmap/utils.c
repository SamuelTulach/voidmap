#include "general.h"

PVOID UtilsReadFile(const char* path, SIZE_T* fileSize)
{
    HANDLE fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
        return NULL;

    LARGE_INTEGER size;
    BOOL status = GetFileSizeEx(fileHandle, &size);
    if (!status)
    {
        CloseHandle(fileHandle);
        return NULL;
    }

    PVOID buffer = malloc(size.QuadPart);
    if (!buffer)
    {
        CloseHandle(fileHandle);
        return NULL;
    }

    DWORD bytesRead;
    status = ReadFile(fileHandle, buffer, size.LowPart, &bytesRead, NULL);
    if (!status)
    {
        CloseHandle(fileHandle);
        free(buffer);
        return NULL;
    }

    CloseHandle(fileHandle);
    *fileSize = size.QuadPart;
    return buffer;
}

PIMAGE_NT_HEADERS64 UtilsGetImageHeaders(PVOID imageStart, SIZE_T maximumSize)
{
    if (maximumSize < sizeof(IMAGE_DOS_HEADER))
        return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageStart;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD64)imageStart + dosHeader->e_lfanew);

    if ((DWORD64)ntHeaders > (DWORD64)imageStart + maximumSize + sizeof(IMAGE_NT_HEADERS64))
        return NULL;

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    return ntHeaders;
}

char* UtilsCompare(const char* haystack, const char* needle)
{
    do
    {
        const char* h = haystack;
        const char* n = needle;
        while (tolower(*h) == tolower(*n) && *n)
        {
            h++;
            n++;
        }

        if (*n == 0)
            return (char*)haystack;
    } while (*haystack++);
    return NULL;
}

extern NTSTATUS WINAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

PVOID UtilsGetModuleBase(const char* moduleName)
{
    PVOID address = NULL;
    ULONG size = 0;

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return NULL;

    PSYSTEM_MODULE_INFORMATION moduleList = (PSYSTEM_MODULE_INFORMATION)malloc(size);
    if (!moduleList)
        return NULL;

    status = NtQuerySystemInformation(SystemModuleInformation, moduleList, size, NULL);
    if (!NT_SUCCESS(status))
        goto end;

    for (ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++)
    {
        DWORD64 pointer = (DWORD64)&moduleList->Modules[i];
        pointer += sizeof(SYSTEM_MODULE);
        if (pointer > ((DWORD64)moduleList + size))
            break;

        SYSTEM_MODULE module = moduleList->Modules[i];
        module.ImageName[255] = '\0';
        if (UtilsCompare(module.ImageName, moduleName))
        {
            address = module.Base;
            break;
        }
    }

end:
    free(moduleList);
    return address;
}