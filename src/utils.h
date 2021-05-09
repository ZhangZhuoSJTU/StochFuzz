#ifndef __UTILS_H
#define __UTILS_H

#include "afl_config.h"
#include "config.h"
#include "tp_dispatcher.h"

#include <capstone/capstone.h>
#include <keystone/keystone.h>

/*
 * Color
 */
#define COLOR_BLACK "\x1b[30m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_GRAY "\x1b[90m"
#define COLOR_PURPLE "\x1b[94m"
#define COLOR_BRIGHT "\x1b[1;97m"
#define COLOR_RESET "\x1b[0m"
#define COLOR(color, str) COLOR_##color str COLOR_RESET

/*
 * Bit aligments
 */
// floor alignment:
//  e.g., for 12-bits alignment, 0x1000 -> 0x1000, 0x1001 -> 0x1000
#define BITS_ALIGN_FLOOR(addr, bits) (((addr) >> (bits)) << (bits))
// cell alignment:
//  e.g., for 12-bits alignment, 0x1000 -> 0x1000, 0x1001 -> 0x2000
#define BITS_ALIGN_CELL(addr, bits) (((((addr)-1) >> (bits)) + 1) << (bits))

/*
 * Lookup table
 */
void z_lookup_table_init_cell_num(uint64_t text_size);
uint64_t z_lookup_table_get_cell_num();

/*
 * Log session
 */
Z_API void z_log(int level, const char *file, int line, const char *fmt, ...);
Z_API void z_log_set_level(int level);

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

#ifdef DEBUG
#define z_trace(...) z_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define z_debug(...) z_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define z_info(...) z_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define z_warn(...) z_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define z_error(...) z_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define z_fatal(...) z_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#else
#define z_trace(...)
#define z_debug(...)
#define z_info(...) z_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define z_warn(...) z_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define z_error(...) z_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define z_fatal(...) z_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#endif

// print message
#define z_sayf(...) fprintf(stderr, __VA_ARGS__)

/*
 * Unreachable
 */
#define EXITME(...)           \
    do {                      \
        z_error(__VA_ARGS__); \
        z_exit(MY_ERR_CODE);  \
    } while (0)

/*
 * General methods (wrapper of glibc alloc/file/string function)
 */
Z_API void z_exit(int status);

Z_API FILE *z_fopen(const char *pathname, const char *mode);
Z_API void z_fclose(FILE *stream);
Z_API void z_fseek(FILE *stream, long offset, int whence);
Z_API long z_ftell(FILE *stream);
Z_API size_t z_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
Z_API size_t z_fwrite(void *ptr, size_t size, size_t nmemb, FILE *stream);
Z_API int z_access(const char *path, int mode);
Z_API int z_chmod(const char *pathname, mode_t mode);

Z_API void *z_alloc(size_t nmemb, size_t size);
Z_API void *z_realloc(void *ptr, size_t size);
Z_API void z_free(void *ptr);

Z_API int z_rand();

Z_API char *z_strcat(const char *s1, const char *s2);
Z_API int z_strcmp(const char *s1, const char *s2);
Z_API char *z_strstr(const char *haystack, const char *needle);
Z_API char *z_strdup(const char *s);
Z_API size_t z_strlen(const char *s);
Z_API void z_strcpy(char *dst, const char *src);
Z_API char *z_strchr(const char *s, int c);

#define z_alloc_printf(_str...)                 \
    ({                                          \
        char *_tmp;                             \
        size_t _len = snprintf(NULL, 0, _str);  \
        if (_len < 0) {                         \
            EXITME("Whoa, snprintf() fails?!"); \
        }                                       \
        _tmp = z_alloc(_len + 1, sizeof(char)); \
        snprintf(_tmp, _len + 1, _str);         \
        _tmp;                                   \
    })
#define z_snprintf(...) snprintf(__VA_ARGS__)
#define z_sscanf(...) sscanf(__VA_ARGS__)

/*
 * Keystone
 */
extern ks_engine *ks;
extern size_t ks_count;
extern size_t ks_size;
extern const unsigned char *ks_encode;
extern unsigned char ks_encode_fast[0x10];

#define KS_INIT                                                       \
    do {                                                              \
        if (ks == NULL) {                                             \
            if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) { \
                EXITME("fail on ks_open()");                          \
            }                                                         \
        }                                                             \
    } while (0)

#define KS_FINI                                                 \
    do {                                                        \
        if (ks_encode != NULL && ks_encode != ks_encode_fast) { \
            ks_free((unsigned char *)ks_encode);                \
        }                                                       \
        if (ks != NULL) {                                       \
            ks_close(ks);                                       \
        }                                                       \
    } while (0)

#define KS_BUFMAX 0x300

// for quick assembly
#define KS_ASM_CALL(cur_addr, tar_addr)                           \
    do {                                                          \
        ks_encode_fast[0] = '\xe8';                               \
        *(int *)(ks_encode_fast + 1) = (tar_addr) - (cur_addr)-5; \
        if (ks_encode != NULL && ks_encode != ks_encode_fast) {   \
            ks_free((unsigned char *)ks_encode);                  \
        }                                                         \
        ks_size = 5;                                              \
        ks_count = 1;                                             \
        ks_encode = ks_encode_fast;                               \
    } while (0)

#define KS_ASM_JMP(cur_addr, tar_addr)                            \
    do {                                                          \
        ks_encode_fast[0] = '\xe9';                               \
        *(int *)(ks_encode_fast + 1) = (tar_addr) - (cur_addr)-5; \
        if (ks_encode != NULL && ks_encode != ks_encode_fast) {   \
            ks_free((unsigned char *)ks_encode);                  \
        }                                                         \
        ks_size = 5;                                              \
        ks_count = 1;                                             \
        ks_encode = ks_encode_fast;                               \
    } while (0)

// XXX: note that  KS_ASM_CONST_MOV can only mov to an address smaller than
// 0x7fffffff, and can only store a value smaller than 0x7fffffff
#define KS_ASM_CONST_MOV(mem, val)                                            \
    do {                                                                      \
        if (ks_encode != NULL && ks_encode != ks_encode_fast) {               \
            ks_free((unsigned char *)ks_encode);                              \
        }                                                                     \
        long mem_ = (mem);                                                    \
        long val_ = (val)&0x7FFFFFFF;                                         \
        if (mem_ > 0x7FFFFFFF) {                                              \
            EXITME("KS_ASM_CONST_MOV stores to a large address: %#lx", mem_); \
        }                                                                     \
        memcpy(ks_encode_fast,                                                \
               "\x48\xC7\x04\x25\xDD\xDD\xDD\xDD\xFF\xFF\xFF\xFF", 12);       \
        memcpy(ks_encode_fast + 4, &(mem_), 4);                               \
        memcpy(ks_encode_fast + 8, &(val_), 4);                               \
        ks_size = 12;                                                         \
        ks_count = 1;                                                         \
        ks_encode = ks_encode_fast;                                           \
    } while (0)

#define KS_ASM(addr, ...)                                                    \
    do {                                                                     \
        char code[KS_BUFMAX];                                                \
        if (snprintf(code, KS_BUFMAX, __VA_ARGS__) >= KS_BUFMAX) {           \
            EXITME("assembly code is too long:\n%s", code);                  \
        }                                                                    \
        if (ks_encode != NULL && ks_encode != ks_encode_fast)                \
            ks_free((unsigned char *)ks_encode);                             \
        if (ks_asm(ks, code, addr, (unsigned char **)(&ks_encode), &ks_size, \
                   &ks_count) != KS_ERR_OK) {                                \
            EXITME("fail on ks_asm:\n%s", code);                             \
        }                                                                    \
    } while (0)

/*
 * Capstone
 */
extern csh cs;
extern size_t cs_count;
extern const cs_insn *cs_inst;

#define CS_SHOW_INST(i) \
    "(%#lx:\t%s %s)", (i)->address, (i)->mnemonic, (i)->op_str

#define CS_INVALID_CSH 0

#define CS_DETAIL_ON                                                \
    do {                                                            \
        if (cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) { \
            EXITME("fail on cs_option()");                          \
        }                                                           \
    } while (0)

#define CS_DETAIL_OFF                                                \
    do {                                                             \
        if (cs_option(cs, CS_OPT_DETAIL, CS_OPT_OFF) != CS_ERR_OK) { \
            EXITME("fail on cs_option()");                           \
        }                                                            \
    } while (0)

#define CS_INIT                                                       \
    do {                                                              \
        if (cs == CS_INVALID_CSH) {                                   \
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) { \
                EXITME("fail on cs_open()");                          \
            }                                                         \
            CS_DETAIL_ON;                                             \
        }                                                             \
    } while (0)

#define CS_FINI                                    \
    do {                                           \
        if (cs_inst != NULL)                       \
            cs_free((cs_insn *)cs_inst, cs_count); \
        if (cs != CS_INVALID_CSH)                  \
            cs_close(&cs);                         \
    } while (0)

#define CS_DISASM_RAW(ptr, size, addr, count)                              \
    do {                                                                   \
        if (cs_inst != NULL)                                               \
            cs_free((cs_insn *)cs_inst, cs_count);                         \
        cs_count =                                                         \
            cs_disasm(cs, ptr, size, addr, count, (cs_insn **)(&cs_inst)); \
    } while (0)

#define CS_DISASM(rptr, addr, count)                               \
    do {                                                           \
        CS_DISASM_RAW((rptr)->raw_ptr, (rptr)->size, addr, count); \
    } while (0)

/*
 * TPDispatcher
 */
extern TPDispatcher *tp;
extern size_t tp_size;
extern const uint8_t *tp_code;

#define TP_INIT                            \
    do {                                   \
        if (tp == NULL)                    \
            tp = z_tp_dispatcher_create(); \
    } while (0)

#define TP_FINI                          \
    do {                                 \
        if (tp != NULL)                  \
            z_tp_dispatcher_destroy(tp); \
    } while (0)

#define TP_EMIT(type, ...)                                                  \
    do {                                                                    \
        if (tp == NULL)                                                     \
            TP_INIT;                                                        \
        tp_code = z_tp_dispatcher_emit_##type(tp, &tp_size, ##__VA_ARGS__); \
    } while (0)

/*
 * System
 */
#define __PRE_CHECK                                                         \
    do {                                                                    \
        if (AFL_PREV_ID_PTR != RW_PAGE_INFO_ADDR(afl_prev_id)) {            \
            EXITME("invalid AFL_PREV_ID_PTR value: %#lx v/s %#lx",          \
                   AFL_PREV_ID_PTR, RW_PAGE_INFO_ADDR(afl_prev_id));        \
        }                                                                   \
        if (RW_PAGE_SIZE < RW_PAGE_USED_SIZE) {                             \
            EXITME("use too much space on RW_PAGE: %#lx v/s %#lx",          \
                   RW_PAGE_SIZE, RW_PAGE_USED_SIZE);                        \
        }                                                                   \
        if (CRS_MAP_SIZE < CRS_USED_SIZE) {                                 \
            EXITME("use too much space on CRS PAGE: %#lx v/s %#lx",         \
                   CRS_MAP_SIZE, CRS_USED_SIZE);                            \
        }                                                                   \
        if (SIGUSR1 != 10) {                                                \
            EXITME("SIGUSR1 is not equal to 10 on this machine");           \
        }                                                                   \
        if (SHADOW_CODE_ADDR >= LOOKUP_TABLE_ADDR) {                        \
            EXITME(                                                         \
                "the address of the shadow code is higher than the one of " \
                "lookup table.");                                           \
        }                                                                   \
    } while (0)

#define Z_INIT       \
    do {             \
        __PRE_CHECK; \
        KS_INIT;     \
        CS_INIT;     \
        TP_INIT;     \
    } while (0)

#define Z_FINI   \
    do {         \
        KS_FINI; \
        CS_FINI; \
        TP_FINI; \
    } while (0)

/*
 * System settings
 */
typedef enum system_mode_t {
    SYSMODE_NONE,
    SYSMODE_DAEMON,
    SYSMODE_RUN,
    SYSMODE_PATCH,
    SYSMODE_DISASM,
    SYSMODE_VIEW,
} SysMode;

typedef struct system_config_t {
    SysMode mode;

    bool trace_pc;
    bool count_conflict;
    bool disable_opt;
    bool safe_ret;
    bool force_pdisasm;
    bool force_linear;  // secret option

    int32_t log_level;

    uint64_t timeout;
} SysConfig;

extern SysConfig sys_config;

#endif
