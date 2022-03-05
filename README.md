# voidmap
A very simple driver manual mapper that exploits CVE-2021-40449 to get arbitrary function executed at a given address with a single given argument. It's based on an [expoit PoC CallbackHell](https://github.com/ly4k/CallbackHell). Tested on Windows 10 Pro For Workstations 1809 17763.379 (64-bit), but realistically anything around that time should be supported.

It does the following:
- Disables SMEP (and possibly SMAP) by rewriting cr4 register value
- Jumps into usermode code that manual maps the desired driver
- Enables SMEP (and possibly SMAP) again

There are two main problems with this approach:
- Manual mapped driver will be in a pool allocated by ExAllocatePool. If you want to use this for anything more serious you should consider finding a better way of memory allocation so it can't be dumped so easily.
- There is no easy way to read the original cr4 value which means that I had to hardcode the value that was there on my system. While it *should* be the same for most modern CPUs, you should still double-check that the value is correct.

Video:
[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/9zHR2Lz1GrM/0.jpg)](https://www.youtube.com/watch?v=9zHR2Lz1GrM)

