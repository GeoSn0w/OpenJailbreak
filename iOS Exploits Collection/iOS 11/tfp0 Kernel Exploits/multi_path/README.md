### multi_path - exploit for p0 issue 1558 (CVE-2018-4241)
@i41nbeer

mptcp_usr_connectx is the handler for the connectx syscall for the AP_MULTIPATH socket family.

The logic of this function fails to correctly handle source and destination sockaddrs which aren't
AF_INET or AF_INET6:

```
  // verify sa_len for AF_INET:

  if (dst->sa_family == AF_INET &&
      dst->sa_len != sizeof(mpte->__mpte_dst_v4)) {
    mptcplog((LOG_ERR, "%s IPv4 dst len %u\n", __func__, dst->sa_len), MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
    error = EINVAL;
    goto out;
  }

  // verify sa_len for AF_INET6:

  if (dst->sa_family == AF_INET6 &&
      dst->sa_len != sizeof(mpte->__mpte_dst_v6)) {
    mptcplog((LOG_ERR, "%s IPv6 dst len %u\n", __func__, dst->sa_len), MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
    error = EINVAL;
    goto out;
  }

  // code doesn't bail if sa_family was neither AF_INET nor AF_INET6

  if (!(mpte->mpte_flags & MPTE_SVCTYPE_CHECKED)) {
    if (mptcp_entitlement_check(mp_so) < 0) {
      error = EPERM;
      goto out;
    }

    mpte->mpte_flags |= MPTE_SVCTYPE_CHECKED;
  }

  // memcpy with sa_len up to 255:

  if ((mp_so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0) {
    memcpy(&mpte->mpte_dst, dst, dst->sa_len);
  }

```

Looking around in the structure which you overflow inside you notice you can hit both fields here:

  if (mpte->mpte_itfinfo_size > MPTE_ITFINFO_SIZE)
    _FREE(mpte->mpte_itfinfo, M_TEMP);

mpte_itfinfo_size is just before mpte_itfinfo.

When the structure is initialized the mpte_itfinfo pointer points to a small inline array. If more subflows are added
than will fit in there they are instead put in a heap buffer, and mpte_itfinfo will point to that.

If you had another bug (eg the kernel heap disclosure bug from async_wake) you could overwrite the mpte_itfinfo field
with any valid zone object and it would get free'd (in fact, you could also overwrite it with an offset into that object
for even more fun!)

However, we don't have that.

Instead another approach is to partially overwrite the pointer. If we partially overwrite it with NULL bytes we can point
it to a 256 byte, 65k, 16MB or 4GB aligned value.

In this exploit I choose a 3 byte NULL overwrite, which will cause a kfree of the mpte_itfinfo address rounded down to the
next 16MB boundary.

The exploitation flow is as follows:

Allocate alternatingly 16MB of ipc_kmsgs followed by a bunch of mptcp sockets. The goal here is to get a kalloc.2048 allocation
at that 16MB boundary.

Use the bug to free one of the ipc_kmsgs, moving that page to the intermediate list and putting the 16MB-aligned allocation on a
kalloc.2048 intermediate page freelist.

Allocate a bunch of filled 2047 byte pipes; the backing buffers for these pipes will come from kalloc.2048, hopefully including our
16MB-aligned address.

Trigger the bug a second time, freeing the same address and this time then allocate a bunch of preallocated ipc_kmsg buffers from
kalloc.2048.

Now we hopefully have an ipc_kmsg (which we can get messages sent to and then receive) and a pipe buffer (which we can read and write)
overlapping each other.

I use the thread exception port trick from extra_recipe to get messages sent to the prealloced ipc_kmsg buffer. Each time we check each
of the pipes to see if any of them contain the message. When we find the right (ipc_kmsg,pipe) pair we can rewrite the message to send ourselves
a fake port which lives inside the pipe buffer. I structure that fake port like the one from async_wake (which I based on yalu 10.2 by
@qwertyoruiopz and @marcograss) to give me an early kernel read primitive.

Using the kernel read primitive I find the kernel task and make a fake port which allows easier kernel memory read/write via
mach_vm_read/mach_vm_write.

Caveat: To connect mptcp sockets you do need the com.apple.developer.networking.multipath entitlement which requires an apple developer cert, which
anyone can buy from Apple.

Reliability:
This is a security reseach tool and is faaaar from perfect. However, it should work most of the time, and when it does work it should
do a good job of cleaning up so it won't panic later.

To improve the probability of it working:
  * turn off wifi and go in to airplane mode
  * reboot
  * wait 30 seconds after restarting
  * run the app from xcode

Supported devices:
It should work on iOS 11.0 - 11.3.1 inclusive. I have tested on: iPod Touch 6g, iPhone 6s, iPhone SE, iPhone 7, iPhone 8

API:
#include "sploit.h" and call go() to run the exploit.
If it worked you can use the functions in kmem.h to read and write kernel memory

***Notes***:
Multiple people have publically bindiff'ed this bug from the patch (or their 0day got patched ;) read their stuff for more details:
  @elvanderb gave a lightning talk about the bug at rump.beer in Paris on May 31st: https://www.rump.beer/2018/slides/ios_48h.pdf
  @jaakerblom published a working exploit on github on June 1st: https://github.com/potmdehex/multipath_kfree
     John's technique is similar to mine but he does a two-byte overflow rather than a three byte one, and replaces with different objects. good stuff!
