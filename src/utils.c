#include "utils.h"

#include <errno.h>
#include <stdarg.h>
#include <time.h>

/*
 * Lookup table function
 */
#define __INVALID_LOOKUP_TABLE_CELL_NUM ((uint64_t)(-1L))

static uint64_t __lookup_table_cell_num = __INVALID_LOOKUP_TABLE_CELL_NUM;

void z_lookup_table_init_cell_num(uint64_t text_size) {
    if (__lookup_table_cell_num != __INVALID_LOOKUP_TABLE_CELL_NUM) {
        EXITME("duplicated initization for lookup table cell number");
    }
    __lookup_table_cell_num =
        ((((text_size - 1) >> PAGE_SIZE_POW2) + 1) << PAGE_SIZE_POW2);
    if (__lookup_table_cell_num > LOOKUP_TABLE_MAX_CELL_NUM) {
        EXITME("too big cell number: %#lx", __lookup_table_cell_num);
    }
    z_info("cell number of lookup table: %#lx", __lookup_table_cell_num);
}

uint64_t z_lookup_table_get_cell_num() {
    if (__lookup_table_cell_num == __INVALID_LOOKUP_TABLE_CELL_NUM) {
        EXITME("non-initizated lookup table cell number");
    }
    return __lookup_table_cell_num;
}

#undef __INVALID_LOOKUP_TABLE_CELL_NUM

/*
 * Log session
 */
static const char *level_names[] = {"TRACE", "DEBUG", "INFO",
                                    "WARN",  "ERROR", "FATAL"};

static const char *level_colors[] = {COLOR_PURPLE, COLOR_CYAN, COLOR_GREEN,
                                     COLOR_YELLOW, COLOR_RED,  COLOR_MAGENTA};

static int log_level = 0;

Z_API void z_log_set_level(int level) { log_level = level; }

Z_API void z_log(int level, const char *file, int line, const char *fmt, ...) {
    if (level < log_level) {
        return;
    }

    time_t t = time(NULL);
    struct tm *lt = localtime(&t);

    va_list args;
    char buf[16];
    buf[strftime(buf, sizeof(buf), "%H:%M:%S", lt)] = '\0';
    fprintf(stderr, "%s %s%-5s" COLOR_RESET " ", buf, level_colors[level],
            level_names[level]);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, " " COLOR_GRAY ":%s:%d" COLOR_RESET " ", file, line);
    fprintf(stderr, "\n");
    fflush(stderr);
}

/*
 * General methods
 */
static bool is_srand = false;

Z_API int z_rand() {
    if (!is_srand) {
        srand(time(NULL));
        is_srand = true;
    }

    return rand();
}

Z_API void z_exit(int status) { exit(status); }

Z_API FILE *z_fopen(const char *pathname, const char *mode) {
    FILE *out = fopen(pathname, mode);
    if (out == NULL) {
        z_error("fopen: %d (%s)", errno, strerror(errno));
        z_exit(errno);
    }
    return out;
}

Z_API void z_fclose(FILE *stream) {
    if (fclose(stream) != 0) {
        z_error("fclose: %d (%s)", errno, strerror(errno));
        z_exit(errno);
    }
}

Z_API void z_fseek(FILE *stream, long offset, int whence) {
    if (fseek(stream, offset, whence) != 0) {
        z_error("fseek: %d (%s)", errno, strerror(errno));
        z_exit(errno);
    }
}

Z_API long z_ftell(FILE *stream) {
    long out = ftell(stream);
    if (out == -1) {
        z_error("ftell: %d (%s)", errno, strerror(errno));
        z_exit(errno);
    }
    return out;
}

Z_API size_t z_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fread(ptr, size, nmemb, stream);
}

Z_API size_t z_fwrite(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

Z_API int z_chmod(const char *pathname, mode_t mode) {
    return chmod(pathname, mode);
}

Z_API int z_access(const char *path, int mode) { return access(path, mode); }

Z_API void *z_alloc(size_t nmemb, size_t size) {
    void *out = calloc(nmemb, size);
    if (out == NULL) {
        EXITME("calloc: run out of memory");
    }
    return out;
}

Z_API void *z_realloc(void *ptr, size_t size) {
    void *out = realloc(ptr, size);
    if (out == NULL) {
        EXITME("realloc: run out of memory");
    }
    return out;
}

Z_API void z_free(void *ptr) { free(ptr); }

/*
 * String methods
 */
Z_API char *z_strcat(const char *s1, const char *s2) {
    char *s = z_alloc(z_strlen(s1) + z_strlen(s2) + 0x10, sizeof(char));
    z_strcpy(s, s1);
    z_strcpy(s + z_strlen(s1), s2);

    return s;
}

Z_API char *z_strstr(const char *haystack, const char *needle) {
    return strstr(haystack, needle);
}

Z_API char *z_strdup(const char *s) {
    char *o = strdup(s);
    if (o == NULL)
        EXITME("strdup: run out of memory");
    return o;
}

Z_API int z_strcmp(const char *s1, const char *s2) { return strcmp(s1, s2); }

Z_API size_t z_strlen(const char *s) { return strlen(s); }

Z_API void z_strcpy(char *dst, const char *src) { strcpy(dst, src); }

Z_API char *z_strchr(const char *s, int c) { return strchr(s, c); }
/*
 * Keystone
 */
ks_engine *ks = NULL;
size_t ks_count = 0;
size_t ks_size = 0;
const unsigned char *ks_encode = NULL;
unsigned char ks_encode_fast[0x10];

/*
 * Capstone
 */
csh cs;
size_t cs_count;
const cs_insn *cs_inst;

/*
 * TPDispatcher
 */
TPDispatcher *tp;
size_t tp_size;
const uint8_t *tp_code;

/*
 * System settings
 */
SysConfig sys_config = {
    .mode = SYSMODE_NONE,
    .trace_pc = false,
    .count_conflict = false,
    .disable_opt = false,
    .safe_ret = false,
    .force_pdisasm = false,
    .force_linear = false,
    .timeout = SYS_TIMEOUT,
};
