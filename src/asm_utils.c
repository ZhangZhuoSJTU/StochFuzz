#include <fcntl.h>

#include "asm_syscall.c"

#define Z_UTILS __attribute__((unused)) static inline

#ifdef DEBUG
#define utils_puts(s, b) __utils_puts(s, b)
#define utils_error(s, e) __utils_error(s, e)
#else
#define utils_puts(s, b)
#define utils_error(s, e)                 \
    do {                                  \
        if (e) {                          \
            sys_kill(/*pid=*/0, SIGKILL); \
            asm volatile("ud2");          \
            __builtin_unreachable();      \
        }                                 \
    } while (0)
#endif

Z_UTILS void __utils_puts(const char *s, bool newline) {
    const char *buf = s;
    const char *cur = s;
    for (; *cur != '\0'; cur++)
        ;
    sys_write(STDERR_FILENO, buf, cur - buf);

    if (newline) {
        const char newline = '\n';
        sys_write(STDERR_FILENO, &newline, 1);
    }
}

Z_UTILS void utils_num2hexstr(char *s, uint64_t n) {
    uint64_t r = 0x1000000000000000;
    while (r != 0) {
        char c = n / r;
        if (c < 10) {
            *(s++) = '0' + c;
        } else {
            *(s++) = 'a' + c - 10;
        }
        n %= r;
        r /= 0x10;
    }
}

Z_UTILS unsigned long utils_hexstr2num(const char **str_ptr) {
    const char *str = *str_ptr;
    unsigned long x = 0;
    while (true) {
        char c = *str++;
        if (c >= '0' && c <= '9') {
            x <<= 4;
            x |= (unsigned long)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            x <<= 4;
            x |= (unsigned long)(10 + c - 'a');
        } else {
            *str_ptr = str;
            return x;
        }
    }
}

Z_UTILS void utils_output_number(uint64_t n) {
    char *s = (char *)(RW_PAGE_ADDR + RW_PAGE_USED_SIZE + 0x50);
    *(s + 16) = '\x00';
    utils_num2hexstr(s, n);
    utils_puts(s, true);
}

Z_UTILS void __utils_error(const char *err_str, bool need_exit) {
    utils_puts(err_str, true);
    if (need_exit) {
        sys_kill(/*pid=*/0, SIGKILL);
        asm volatile("ud2");
        __builtin_unreachable();
    }
}

Z_UTILS size_t utils_strcpy(char *dst, char *src) {
    for (size_t i = 0;; i++) {
        dst[i] = src[i];
        if (!src[i]) {
            return i;
        }
    }
}

/*
 * Load external file.
 */
Z_UTILS size_t utils_mmap_external_file(const char *filename,
                                        unsigned long addr, int prot) {
    // Step (0): prepare error string
#ifdef DEBUG
    char s_[16];
    s_[0] = 'm';
    s_[1] = 'm';
    s_[2] = 'a';
    s_[3] = 'p';
    s_[4] = ' ';
    s_[5] = 'f';
    s_[6] = 'a';
    s_[7] = 'i';
    s_[8] = 'l';
    s_[9] = 'e';
    s_[10] = 'd';
    s_[11] = '\n';
    s_[12] = '\x00';
    s_[13] = ' ';
    s_[14] = '\x00';
#endif

    // Step (1): open file
    int fd = sys_open(filename, O_RDONLY, 0);
    if (fd < 0) {
        utils_puts(filename, false);
        utils_puts(s_ + 13, false);
        utils_error(s_, true);
    }

    // Step (2): get file size
    struct stat buf = {};
    if (sys_fstat(fd, &buf)) {
        utils_error(s_, true);
    }
    size_t fd_size = buf.st_size;
    if (fd_size != (fd_size >> PAGE_SIZE_POW2) << PAGE_SIZE_POW2) {
        char s[0x20] = "";
        utils_num2hexstr(s, fd_size);
        utils_puts(s, false);
        utils_error(s_, true);
    }

    // Step (3): mmap file
#ifdef BINARY_SEARCH_INVALID_CRASH
    // make gdb able to set breakpoints at mmapped pages
    if (sys_mmap(addr, fd_size, prot, MAP_PRIVATE | MAP_FIXED, fd, 0) != addr) {
#else
    if (sys_mmap(addr, fd_size, prot, MAP_SHARED | MAP_FIXED, fd, 0) != addr) {
#endif
        utils_error(s_, true);
    }
    if (sys_close(fd)) {
        utils_error(s_, true);
    }

    return fd_size;
}
