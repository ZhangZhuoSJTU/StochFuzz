#ifndef __CONFIG_H
#define __CONFIG_H

/*
 * Include basic headers
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Tool name and version
 */
#define OURTOOL "stoch-fuzz"
#define VERSION "0.2.0"

/*
 * Default system settings
 */
#define SYS_TIMEOUT 1000

/*
 * Magic string to indicate the file is patched
 */
#define MAGIC_STRING "2015.05.02 Shanghai"

/*
 * Genral macro and types
 */
#define STRING(x) STRING_2(x)
#define STRING_2(x) #x

// error code for EXITME
#define MY_ERR_CODE 233

#define Z_API __attribute__((visibility("hidden")))
#define Z_PRIVATE __attribute__((visibility("hidden"))) static inline
#define Z_PUBLIC __attribute__((visibility("default")))
#define Z_RESERVED __attribute__((unused))

#define PAGE_SIZE_POW2 PAGE_SHIFT

#define ADDR_MAX SIZE_MAX

/*
 * Invalid information
 */
#define INVALID_ADDR ADDR_MAX
#define INVALID_FD -1
#define INVALID_SHM_ID -1
#define INVALID_PID 0

/*
 * Re-define type
 */
typedef size_t addr_t;
typedef void PhantomType;
typedef long double double128_t;

/*
 * XXX:
 *  + SHADOW_CODE_ADDR: random address based on ASLR/PIE
 *  + RW_PAGE_ADDR: fixed address
 *  + LOOKUP_TABLE_ADDR: fixed address
 */
#define SHADOW_CODE_ADDR 0x12190000

/*
 * [RW_PAGE_ADDR] The meta information needed during loading
 */
typedef struct __loading_info_t {
    void *program_base;

    uint64_t afl_prev_id;

    uint64_t client_pid;

    uint64_t prev_pc;

    char shadow_path[0x100];
    uint64_t shadow_size;

    char lookup_tab_path[0x100];
    uint64_t lookup_tab_size;

    char pipe_path[0x100];

    bool daemon_attached;

} __LoadingInfo;

#define RW_PAGE_ADDR 0x300000
#define RW_PAGE_SIZE PAGE_SIZE
#define RW_PAGE_USED_SIZE sizeof(__LoadingInfo)
#define RW_PAGE_INFO_ADDR(f) (RW_PAGE_ADDR + offsetof(__LoadingInfo, f))
#define RW_PAGE_INFO(field) (((__LoadingInfo *)RW_PAGE_ADDR)->field)

/*
 * Prefix and suffix for additional files
 */
#define TEMPFILE_NAME_PREFIX "." OURTOOL "."
#define LOOKUP_TABNAME_PREFIX ".lookup."
#define TRAMPOLINES_NAME_PREFIX ".shadow."
#define CRASHPOINT_LOG_PREFIX ".crashpoint."
#define PIPE_FILENAME_PREFIX ".pipe."
#define PDISASM_FILENAME_PREFIX ".pdisasm."
#define BACKUP_FILE_SUFFIX ".bak"
#define PATCHED_FILE_SUFFIX ".patch"
#define PHANTOM_FILE_SUFFIX ".phantom"

/*
 * Lookup table
 */
extern void z_lookup_table_init_cell_num(uint64_t text_size);
extern uint64_t z_lookup_table_get_cell_num();

#define LOOKUP_TABLE_INIT_CELL_NUM(x) z_lookup_table_init_cell_num(x)

#define LOOKUP_TABLE_CELL_SIZE_POW2 2
#define LOOKUP_TABLE_CELL_SIZE (1 << LOOKUP_TABLE_CELL_SIZE_POW2)
#define LOOKUP_TABLE_CELL_MASK ((1UL << (LOOKUP_TABLE_CELL_SIZE * 8)) - 1)
#define LOOKUP_TABLE_CELL_NUM z_lookup_table_get_cell_num()

#define LOOKUP_TABLE_SIZE (LOOKUP_TABLE_CELL_SIZE * LOOKUP_TABLE_CELL_NUM)

#define LOOKUP_TABLE_MAX_CELL_NUM 0x8000000
#define LOOKUP_TABLE_MAX_SIZE \
    (LOOKUP_TABLE_CELL_SIZE * LOOKUP_TABLE_MAX_CELL_NUM)

#define LOOKUP_TABLE_ADDR ((1UL << 31) - LOOKUP_TABLE_MAX_SIZE)

/*
 * Crash check
 */
// For exit code usage, check https://tldp.org/LDP/abs/html/exitcodes.html for
// more information
#define IS_SUSPECT_STATUS(s) (WIFSIGNALED(s) && (WTERMSIG(s) == SIGUSR1))

/*
 * Define struct with type info
 */
typedef struct meta_struct_t {
    const char *__type;
} MetaStruct;

#define STRUCT(name, content) \
    typedef struct name##_t { \
        const char *__type;   \
        struct content;       \
    } name

#define STRUCT_REALNAME(type) struct type##_t

#define STRUCT_TYPE(var) ((MetaStruct *)var)->__type

#define STRUCT_ALLOC(type)                    \
    ({                                        \
        type *var = z_alloc(1, sizeof(type)); \
        var->__type = #type;                  \
        var;                                  \
    })

/*
 * Setter and Getter
 *      OTYPE: type of object (e.g., Binary)
 *      ONAME: name of object (e.g., binary)
 *      FTYPE: type of filed (e.g., Elf_Info *)
 *      FNAME: name of filed (e.g., elf)
 */
#define DECLARE_SETTER(OTYPE, ONAME, FTYPE, FNAME) \
    Z_API void z_##ONAME##_##set_##FNAME(OTYPE *ONAME, FTYPE FNAME)

#define DEFINE_SETTER(OTYPE, ONAME, FTYPE, FNAME)                     \
    Z_API void z_##ONAME##_##set_##FNAME(OTYPE *ONAME, FTYPE FNAME) { \
        assert(ONAME != NULL);                                        \
        ONAME->FNAME = FNAME;                                         \
    }

#define DECLARE_GETTER(OTYPE, ONAME, FTYPE, FNAME) \
    Z_API FTYPE z_##ONAME##_##get_##FNAME(OTYPE *ONAME)

#define DEFINE_GETTER(OTYPE, ONAME, FTYPE, FNAME)         \
    Z_API FTYPE z_##ONAME##_##get_##FNAME(OTYPE *ONAME) { \
        assert(ONAME != NULL);                            \
        return ONAME->FNAME;                              \
    }

#define OVERLOAD_SETTER(OTYPE, ONAME, FTYPE, FNAME) \
    Z_API void z_##ONAME##_##set_##FNAME(OTYPE *ONAME, FTYPE FNAME)

#define OVERLOAD_GETTER(OTYPE, ONAME, FTYPE, FNAME) \
    Z_API FTYPE z_##ONAME##_##get_##FNAME(OTYPE *ONAME)

#endif
