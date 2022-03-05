#include "general.h"

BOOL kernelCallbackCalled = FALSE;

PVOID driverBuffer; 



void KernelCallback(void* first, void* second)
{
    // WARNING
    // this function is being executed with CPL 0

    UNREFERENCED_PARAMETER(first);
    UNREFERENCED_PARAMETER(second);

    kernelCallbackCalled = TRUE;


}