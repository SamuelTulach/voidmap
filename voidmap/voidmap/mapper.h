#pragma once

extern BOOL kernelCallbackCalled;
extern PVOID driverBuffer;

void KernelCallback(void* first, void* second);