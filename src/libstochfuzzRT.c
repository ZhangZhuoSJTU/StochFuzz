#include "config.h"

#include <libunwind.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/types.h>

#define IP_OFFSET_IN_CURSOR 3

typedef int (*unw_step_fn_type)(unw_cursor_t*);

typedef struct retaddr_entity_t {
    uint32_t shadow;
    uint32_t original;
} Retaddr;

typedef struct retaddr_mapping_t {
    size_t n;
    unw_step_fn_type real_unw_step;
    Retaddr addrs[];
} RetaddrMapping;

static void __runtime_mremap(const char* filename, void* addr, size_t length,
                             int prot) {
    // msync the data
    if (msync(addr, length, MS_SYNC)) {
        fprintf(stderr, "msync failed: %s\n", strerror(errno));
        exit(MY_ERR_CODE);
    }

    // munmap the underlying memory
    if (munmap(addr, length)) {
        fprintf(stderr, "munmap failed: %s\n", strerror(errno));
        exit(MY_ERR_CODE);
    }

    // open file
    int fd = open(filename, (prot & PROT_WRITE) ? O_RDWR : O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s failed: %s\n", filename, strerror(errno));
        exit(MY_ERR_CODE);
    }

    // mmap file
    if (mmap(addr, length, prot, MAP_SHARED | MAP_FIXED, fd, 0) != addr) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        exit(MY_ERR_CODE);
    }

    // close fd
    if (close(fd)) {
        fprintf(stderr, "close failed: %s\n", strerror(errno));
        exit(MY_ERR_CODE);
    }
}

static unw_word_t __runtime_retaddr_translate(RetaddrMapping* mapping,
                                              unw_word_t ip) {
    size_t low_id = 0;
    size_t high_id = mapping->n - 1;

    if (mapping->addrs[low_id].shadow > ip ||
        mapping->addrs[high_id].shadow < ip) {
        return ip;
    }

    if (mapping->addrs[low_id].shadow == ip) {
        return mapping->addrs[low_id].original;
    }
    if (mapping->addrs[high_id].shadow == ip) {
        return mapping->addrs[high_id].original;
    }

    size_t mid_id = (low_id + high_id) >> 1;
    while (low_id + 1 != high_id) {
        if (mapping->addrs[mid_id].shadow < ip) {
            low_id = mid_id;
        } else if (mapping->addrs[mid_id].shadow > ip) {
            high_id = mid_id;
        } else {
            return mapping->addrs[mid_id].original;
        }

        mid_id = (low_id + high_id) >> 1;
    }

    return ip;
}

int _ULx86_64_step(unw_cursor_t* cursor) {
    if (!RW_PAGE_INFO(retaddr_mapping_used)) {
        fprintf(stderr, "stochfuzz's -r option is disabled!\n");
        exit(MY_ERR_CODE);
    }

    RetaddrMapping* mapping =
        (RetaddrMapping*)RW_PAGE_INFO(retaddr_mapping_base);

    if (!mapping->real_unw_step) {
        // first check size
        if (sizeof(addr_t) != sizeof(unw_word_t)) {
            fprintf(stderr, "inconsistent size of addr_t and unw_word_t");
            exit(MY_ERR_CODE);
        }

        // get basic information
        void* retaddr_mapping_base = (void*)RW_PAGE_INFO(retaddr_mapping_base);
        size_t retaddr_mapping_size = RW_PAGE_INFO(retaddr_mapping_size);
        const char* retaddr_mapping_path = RW_PAGE_INFO(retaddr_mapping_path);

        // update mapping prot
        __runtime_mremap(retaddr_mapping_path, retaddr_mapping_base,
                         retaddr_mapping_size, PROT_READ | PROT_WRITE);

        // find the real address
        struct link_map* l_current = _r_debug.r_map;
        while (l_current) {
            if (strstr(l_current->l_name, "libunwind.so")) {
                break;
            }
            l_current = l_current->l_next;
        }
        if (!l_current) {
            fprintf(stderr, "Cannot find libunwind handle\n");
            exit(MY_ERR_CODE);
        }
        mapping->real_unw_step =
            (unw_step_fn_type)(l_current->l_addr + STEP_OFFSET);

        // remapping as non-writable
        __runtime_mremap(retaddr_mapping_path, retaddr_mapping_base,
                         retaddr_mapping_size, PROT_READ);
    }

    int rv = (*(mapping->real_unw_step))(cursor);

    unw_word_t* typed_cursor = (unw_word_t*)cursor;
    unw_word_t base_ip = RW_PAGE_INFO(program_base);

    unw_word_t ip = typed_cursor[IP_OFFSET_IN_CURSOR] - base_ip;
    unw_word_t new_ip = __runtime_retaddr_translate(mapping, ip);
    typed_cursor[IP_OFFSET_IN_CURSOR] = new_ip + base_ip;

    return rv;
}
