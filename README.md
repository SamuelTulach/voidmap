# voidmap
A very simple driver manual mapper that exploits CVE-2021-40449 to get arbitrary code executed at a given pointer with a single given argument. It's based on an [expoit PoC CallbackHell](https://github.com/ly4k/CallbackHell). Tested on Windows 10 Pro For Workstations 1809 17763.379 (64-bit), but realistically anything around that time should be supported.

It does the following:
- Disables SMEP (and possibly SMAP) by rewriting cr4 register value
- Jumps into usermode code that manual maps the desired driver
- Enables SMEP (and possibly SMAP) again

There are two main problems with this approach:
- Manual mapped driver will be in a pool allocated by ExAllocatePool. If you want to use this for anything more serious you should consider finding a better way of memory allocation so it can't be dumped so easilly.
- There is no easy way to read the original cr4 value which means that I had to hardcode the value that was there on my system. While is *should* be the same for most modern CPUs, you should still double check that the value is correct.

Video:
[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/YOUTUBE_VIDEO_ID_HERE/0.jpg)](https://www.youtube.com/watch?v=YOUTUBE_VIDEO_ID_HERE)

