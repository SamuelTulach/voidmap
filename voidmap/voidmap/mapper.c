#include "general.h"

typedef void(*VoidFunc_t)();

void KernelCallback(void* first, void* second)
{
    UNREFERENCED_PARAMETER(first);
    UNREFERENCED_PARAMETER(second);

    VoidFunc_t test = (VoidFunc_t)0xFEEDFEADFEED;
    test();
}