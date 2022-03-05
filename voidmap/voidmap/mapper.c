#include "general.h"

BOOL kernelCallbackCalled = FALSE;

void KernelCallback(void* first, void* second)
{
    UNREFERENCED_PARAMETER(first);
    UNREFERENCED_PARAMETER(second);

    kernelCallbackCalled = TRUE;
}