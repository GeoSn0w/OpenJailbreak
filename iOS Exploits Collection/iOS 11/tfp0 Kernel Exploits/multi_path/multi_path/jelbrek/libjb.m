/*
 *  fast directory traversal
 *
 *  Copyright (c) 2017 xerub
 */


/* Notes:
 * directories:
 *   symlinks are skipped, except when passed directly
 *   "/private/var" is entirely skipped (pass in "/var" if you want to parse it)
 *   ".app" directories are first checked against libmis (if they pass, entire dir is skipped)
 * files:
 *   ".plist", ".nib", ".strings", ".png" are skipped
 *   symlinks are skipped
 *   files smaller than 0x4000 are skipped
 */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif
#include "libjb.h"

hash_t *allhash = NULL;
unsigned numhash = 0;
static unsigned maxhash = 0;
struct hash_entry_t *amfitab = NULL;
hash_t *allkern = NULL;
static unsigned numkern = 0;

#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

#define SWAP32(p) __builtin_bswap32(p)

struct dyld_cache_header {
    char magic[16];            /* e.g. "dyld_v0     ppc" */
    uint32_t mappingOffset;        /* file offset to first dyld_cache_mapping_info */
    uint32_t mappingCount;        /* number of dyld_cache_mapping_info entries */
    uint32_t imagesOffset;        /* file offset to first dyld_cache_image_info */
    uint32_t imagesCount;        /* number of dyld_cache_image_info entries */
    uint64_t dyldBaseAddress;        /* base address of dyld when cache was built */
    uint64_t codeSignatureOffset;    /* file offset in of code signature blob */
    uint64_t codeSignatureSize;        /* size of code signature blob (zero means to end of file) */
};

#define LC_CODE_SIGNATURE 0x1d    /* local of code signature */

typedef int    cpu_type_t;
typedef int    cpu_subtype_t;

struct mach_header {
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct linkedit_data_command {
    uint32_t    cmd;        /* LC_CODE_SIGNATURE or LC_SEGMENT_SPLIT_INFO */
    uint32_t    cmdsize;    /* sizeof(struct linkedit_data_command) */
    uint32_t    dataoff;    /* file offset of data in __LINKEDIT segment */
    uint32_t    datasize;    /* file size of data in __LINKEDIT segment  */
};

struct fat_header {
    uint32_t    magic;        /* FAT_MAGIC */
    uint32_t    nfat_arch;    /* number of structs that follow */
};

struct fat_arch {
    cpu_type_t    cputype;    /* cpu specifier (int) */
    cpu_subtype_t    cpusubtype;    /* machine specifier (int) */
    uint32_t    offset;        /* file offset to this object file */
    uint32_t    size;        /* size of this object file */
    uint32_t    align;        /* alignment as a power of 2 */
};

/*
 * Magic numbers used by Code Signing
 */
enum {
    CSMAGIC_REQUIREMENT    = 0xfade0c00,        /* single Requirement blob */
    CSMAGIC_REQUIREMENTS = 0xfade0c01,        /* Requirements vector (internal requirements) */
    CSMAGIC_CODEDIRECTORY = 0xfade0c02,        /* CodeDirectory blob */
    CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
    CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
    
    CSSLOT_CODEDIRECTORY = 0,                /* slot index for CodeDirectory */
    CSSLOT_ENTITLEMENTS = 5,
};

/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
    uint32_t type;                    /* type of entry */
    uint32_t offset;                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
    uint32_t magic;                    /* magic number */
    uint32_t length;                /* total length of SuperBlob */
    uint32_t count;                    /* number of index entries following */
    CS_BlobIndex index[];            /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
    uint32_t magic;                    /* magic number (CSMAGIC_CODEDIRECTORY) */
    uint32_t length;                /* total length of CodeDirectory blob */
    uint32_t version;                /* compatibility version */
    uint32_t flags;                    /* setup and mode flags */
    uint32_t hashOffset;            /* offset of hash slot element at index zero */
    uint32_t identOffset;            /* offset of identifier string */
    uint32_t nSpecialSlots;            /* number of special hash slots */
    uint32_t nCodeSlots;            /* number of ordinary (code) hash slots */
    uint32_t codeLimit;                /* limit to main image signature range */
    uint8_t hashSize;                /* size of each hash in bytes */
    uint8_t hashType;                /* type of hash (cdHashType* constants) */
    uint8_t spare1;                    /* unused (must be zero) */
    uint8_t    pageSize;                /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;                /* unused (must be zero) */
    /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

static int
compar(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(hash_t));
}

static int
check_cdhash(hash_t cdhash)
{
    unsigned i;
    
    if (amfitab) {
        uint8_t head = cdhash[0];
        uint8_t *data = (uint8_t *)(amfitab + 256) + 19 * amfitab[head].start;
        // XXX bsearch(&cdhash[1], data, amfitab[head].num, sizeof(hash_t) - 1, compar19)
        for (i = amfitab[head].num; i; i--, data += 19) {
            if (!memcmp(&cdhash[1], data, 19)) {
                return -1;
            }
        }
    }
#if 000
    for (i = 0; i < numkern; i++) {
        if (!memcmp(allkern[i], cdhash, sizeof(hash_t))) {
            return 1;
        }
    }
#else
    if (bsearch(cdhash, allkern, numkern, sizeof(hash_t), compar)) {
        return 1;
    }
#endif
    for (i = 0; i < numhash; i++) {
        if (!memcmp(allhash[i], cdhash, sizeof(hash_t))) {
            return 1;
        }
    }
    
    return 0;
}

static int
print_cdhash(const uint8_t *p, uint64_t codeSignatureOffset, uint64_t codeSignatureSize)
{
    uint32_t i;
    const CS_SuperBlob *super = (CS_SuperBlob *)(p + codeSignatureOffset);
    uint32_t count = SWAP32(super->count);
    const CS_BlobIndex *index;
    
    assert(SWAP32(super->magic) == CSMAGIC_EMBEDDED_SIGNATURE);
    for (index = super->index, i = 0; i < count; i++, index++) {
        if (SWAP32(index->type) == CSSLOT_CODEDIRECTORY) {
            const CS_CodeDirectory *directory = (CS_CodeDirectory *)((uint8_t *)super + SWAP32(index->offset));
            uint8_t cdhash[32];
            if (directory->hashType == 1) {
                assert(directory->hashSize == 20);
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
                CC_SHA1((const uint8_t *)directory, SWAP32(directory->length), cdhash);
#else
                SHA1((const uint8_t *)directory, SWAP32(directory->length), cdhash);
#endif
            } else {
                assert(directory->hashSize == 32);
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
                CC_SHA256((const uint8_t *)directory, SWAP32(directory->length), cdhash);
#else
                SHA256((const uint8_t *)directory, SWAP32(directory->length), cdhash);
#endif
            }
            if (check_cdhash(cdhash) == 0) {
                if (numhash >= maxhash) {
                    hash_t *tmp;
                    maxhash = numhash;
                    if (!maxhash) {
                        maxhash = 8;
                    }
                    maxhash *= 2;
                    tmp = realloc(allhash, maxhash * sizeof(hash_t));
                    if (!tmp) {
                        return -1;
                    }
                    allhash = tmp;
                }
                memcpy(allhash + numhash, cdhash, sizeof(hash_t));
                numhash++;
            }
            break;
        }
    }
    
    return 0;
}

static int
print_cdhash_macho(off_t sz, const uint8_t *p)
{
    uint32_t i;
    const struct mach_header *hdr = (struct mach_header *)p;
    const uint8_t *q = p + sizeof(struct mach_header);
    
    if (!MACHO(p)) {
        return 0;
    }
    if (IS64(p)) {
        q += 4;
    }
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            const struct linkedit_data_command *ldc = (struct linkedit_data_command *)q;
            return print_cdhash(p, ldc->dataoff, ldc->datasize);
        }
        q = q + cmd->cmdsize;
    }
    
    return 0;
}

static int
print_cdhash_fat(off_t sz, const uint8_t *p)
{
    if (*(uint32_t *)p == 0xBEBAFECA) {
        const struct fat_header *fat = (struct fat_header *)p;
        const struct fat_arch *arch = (struct fat_arch *)(fat + 1);
        int n = SWAP32(fat->nfat_arch);
        while (n-- > 0) {
            const uint32_t offset = SWAP32(arch->offset);
            const uint32_t size = SWAP32(arch->size);
            const uint32_t cputype = SWAP32(arch->cputype);
            if ((cputype & 0xFF) == 12 && offset < sz && offset + size <= sz) {
                int rv = print_cdhash_macho(size, p + offset);
                if (rv) {
                    return rv;
                }
            }
            arch++;
        }
        return 0;
    }
    return print_cdhash_macho(sz, p);
}

static int
strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
#include <CoreFoundation/CoreFoundation.h>
static int (*MISValidateSignature)(CFStringRef path, CFDictionaryRef opt) = NULL;

static int
misvalid(const char *fpath)
{
    int rv;
    CFStringRef path;
    if (!MISValidateSignature) {
        return -1;
    }
    path = CFStringCreateWithCString(NULL, fpath, kCFStringEncodingUTF8);
    if (!path) {
        return -1;
    }
    rv = MISValidateSignature(path, NULL);
    CFRelease(path);
    return rv;
}
#else
static int
misvalid(const char *fpath)
{
    return -1;
}
#endif

static int
callback(const char *fpath, int *isdir, int level)
{
    int rv;
    int fd;
    uint8_t *p;
    off_t sz;
    struct stat st;
    uint8_t buf[16];
    
#if DEBUG
    printf("%s%s\n", fpath, (*isdir) ? "/" : "");
#endif
    
    if (*isdir) {
        *isdir = (strcmp(fpath, "/private/var") && (strtail(fpath, ".app") || misvalid(fpath)));
        return 0;
    }
    if (strtail(fpath, ".plist") == 0 || strtail(fpath, ".nib") == 0 || strtail(fpath, ".strings") == 0 || strtail(fpath, ".png") == 0) {
        return 0;
    }
    
    rv = lstat(fpath, &st);
    if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
        return 0;
    }
    
    fd = open(fpath, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    
    sz = read(fd, buf, sizeof(buf));
    if (sz != sizeof(buf)) {
        close(fd);
        return 0;
    }
    if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
        close(fd);
        return 0;
    }
    
    p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        close(fd);
        return 0;
    }
    
    rv = print_cdhash_fat(st.st_size, p);
    
    munmap(p, st.st_size);
    close(fd);
    
    return rv;
}

#if 666
static void *
MALLOC(size_t size)
{
    static void *buf = NULL;
    static size_t sz = 0;
    if (size == 0) {
        free(buf);
        buf = NULL;
        sz = 0;
        return NULL;
    }
    if (size > sz) {
        size = (size + 1024) & ~1023;
        free(buf);
        buf = malloc(size);
        if (!buf) {
            sz = 0;
            return NULL;
        }
        sz = size;
    }
    return buf;
}
#define FREE(x)
#else
#define MALLOC malloc
#define FREE free
#endif

static int
dtw(const char *root, int (*callback)(const char *, int *, int), int depth)
{
    int rv = 0;
    DIR *dir;
    struct dirent *ent;
    size_t ldir, lfile;
    
    dir = opendir(root);
    if (!dir) {
        return (errno == EACCES) - 1;
    }
    
    ldir = strlen(root);
    while ((ent = readdir(dir))) {
        int isdir;
        char *path;
        const char *name = ent->d_name;
        
        if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) {
            continue;
        }
        
        lfile = strlen(name);
        path = MALLOC(ldir + 1 + lfile + 1);
        if (!path) {
            rv = -1;
            break;
        }
        memcpy(path, root, ldir);
        path[ldir] = '/';
        memcpy(path + ldir + 1, name, lfile + 1);
        
        isdir = (ent->d_type == DT_DIR);
        
        rv = callback(path, &isdir, depth);
        if (rv == 0 && isdir) {
            rv = dtw(path, callback, depth + 1);
        }
        
        FREE(path);
        if (rv) {
            break;
        }
    }
    
    closedir(dir);
    return rv;
}

static void
prep_amfi(size_t (*kread)(uint64_t, void *, size_t), uint64_t addr)
{
    size_t sz;
    unsigned i;
    uint8_t buf[1024];
    size_t size = 1024;
    const struct hash_entry_t *tab = (struct hash_entry_t *)buf;
    
    if (!kread || !addr || amfitab) {
        return;
    }
    
    sz = kread(addr, buf, size);
    if (sz != size) {
        return;
    }
    
    if (tab->start) {
        return;
    }
    for (i = 0; i < 256; i++) {
        if (i != 0 && tab->start != (tab - 1)->start + (tab - 1)->num) {
            return;
        }
        size += 19 * tab->num;
        tab++;
    }
    
    amfitab = malloc(size);
    if (!amfitab) {
        return;
    }
    
    sz = kread(addr, amfitab, size);
    if (sz != size) {
        free(amfitab);
        amfitab = NULL;
    }
}

static void
prep_kern(size_t (*kread)(uint64_t, void *, size_t), uint64_t addr)
{
    size_t n;
    struct trust_mem mem;
    
    if (!kread || !addr || allkern) {
        return;
    }
    
    while (addr) {
        n = kread(addr, &mem, sizeof(struct trust_mem));
        if (n != sizeof(struct trust_mem)) {
            break;
        }
        if (mem.count) {
            size_t size = mem.count * sizeof(hash_t);
            uint8_t *chunk = malloc(size);
            if (chunk) {
                n = kread(addr + sizeof(struct trust_mem), chunk, size);
                if (n == size) {
                    hash_t *tmp = realloc(allkern, size + numkern * sizeof(hash_t));
                    if (tmp) {
                        allkern = tmp;
                        memcpy(allkern + numkern, chunk, size);
                        numkern += mem.count;
                    }
                }
                free(chunk);
            }
        }
        addr = mem.next;
    }
    
    qsort(allkern, numkern, sizeof(hash_t), compar);
}

int
grab_hashes(const char *root, size_t (*kread)(uint64_t, void *, size_t), uint64_t amfi, uint64_t top)
{
    int rv;
    int isdir;
    struct stat st;
    
    rv = stat(root, &st);
    if (rv) {
        return rv;
    }
    
    prep_amfi(kread, amfi);
    prep_kern(kread, top);
    
    if (S_ISDIR(st.st_mode)) {
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
        void *h = dlopen("/usr/lib/libmis.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (h) {
            MISValidateSignature = (int (*)())dlsym(h, "MISValidateSignature");
        }
#endif
        isdir = 1;
        rv = callback(root, &isdir, 0);
        if (rv == 0 && isdir) {
            rv = dtw(root, callback, 1);
        }
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
        MISValidateSignature = NULL;
        if (h) {
            dlclose(h);
        }
#endif
    } else {
        isdir = 0;
        rv = callback(root, &isdir, 0);
    }
#ifndef MALLOC
    MALLOC(0);
#endif
    
    qsort(allhash, numhash, sizeof(hash_t), compar);
    return rv;
}

#ifdef HAVE_MAIN
static size_t
readcb(uint64_t addr, void *buf, size_t sz)
{
    size_t n;
    int fd = open("krnl", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    n = pread(fd, buf, sz, addr);
    if (n != sz) {
        return -1;
    }
    close(fd);
    return n;
}

/*int
main(int argc, char **argv)
{
    int rv;
    unsigned j;
    
    if (argc < 2) {
        return -1;
    }
    
    rv = grab_hashes(argv[1], readcb, 0x6613B0, 0);
    if (rv) {
        return rv;
    }
    
    for (j = 0; j < numhash; j++) {
        int i;
        for (i = 0; i < 20; i++) {
            printf("%02x", allhash[j][i]);
        }
        printf("\n");
    }
    
    free(allhash);
    free(allkern);
    free(amfitab);
    return 0;
}*/
#endif
