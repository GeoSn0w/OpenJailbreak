This is the first ever plug-and-play Jailbreak Framework. It was developed by Jonathan Levin, the author of the *OS Internals books.

By his description:

"All you have to do in order to build on QiLin is to call: int initQiLin (mach_port_t TFP0, uint64_t KernelBase); with the kernel send right (TFP0) and the kernelbase (i.e address of kernel Mach-O + slide). And now you don't even have to do that anymore since QiLin can figure out the slide with just your own task address (which exploits use anyway). The rest is provided by numerous functions."

