// When hiding the jailbreak in Dopamine settings, a lot of processes will crash due to the /usr/lib mount disappearing
// Anything that has libraries inside /usr/lib that are not in the shared cache (e.g. libobjc_trampolines.dylib) mapped in will crash
// We solve this here by redirecting dlopen calls for files in /usr/lib to /var/jb/basebin/.fakelib (if the latter is accessible)
// This way the vnode will not be on /usr/lib mount and the /usr/lib mount therefore can be unmounted without making stuff crash
// There are a few rare edge cases of processes that cannot access /var/jb/basebin/.fakelib for some reason, so we need to make sure those still go over /usr/lib
