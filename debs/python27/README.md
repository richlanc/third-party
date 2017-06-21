https://github.com/jonathonf helped us tweak our python build to be more performant
https://osirium.atlassian.net/browse/OS-2037

Here's what he said:

It looks like a key performance difference is due to the flags passed during compilation; this patch (lto-link-flags.diff) is applied by Debian and so the Ubuntu packages also benefit.

Applying just this patch gets the test execution time down to the expected ~5s. There may be smaller optimisations in the other Debian patches but they didn't make a noticeable difference for this specific test case - this patch is the key change.

However, switching to a newer Ubuntu version (with newer GCC) might provide much more improvement. During my testing I compiled Python 2.7 without the --enable-optimizations configure flag (or any other configure flags, for that matter) and found 64-bit 16.04 (GCC 5.4.1) runs the same test code in 1.5s, though this may simply be the later GCC version optimising out the loop.