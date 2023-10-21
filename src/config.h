/*
 * config.h
 * Copyright (C) 2021 Zhuo Zhang, Xiangyu Zhang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
#define VERSION "1.1.0"

/*
 * Magic string to indicate the file is patched
 */
#define MAGIC_STRING "2015.05.02 Shanghai Snow"
#define MAGIC_NUMBER 0x527569787565

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
 *  + SIGNAL_STACK_ADDR: random address based on ASLR/PIE
 *  + RETADDR_MAPPING_ADDR: random address based on ASLR/PIE
 *  + LOOKUP_TABLE_ADDR: random address based on ASLR/PIE
 *  + RW_PAGE_ADDR: fixed address
 *  + AFL_MAP_ADDR: fixed address
 *  + CRS_MAP_ADDR: fixed address
 *
 * Note that, RW_PAGE_ADDR can only be fixed because we need it to access the
 * programb base on the runtime. On the contrary, AFL_MAP_ADDR and CRS_MAP_ADDR
 * should have not been fixed, but they indeed are mainly due to the keystone
 * bug that is related to address redirecting.
 */
// XXX: see http://ref.x86asm.net/coder64.html for x64 encoding
#define SHADOW_CODE_ADDR 0x1f1f8000

// XXX: SIGSTKSZ is now a run-time variable, which makes compilation of loader
// and forkserver failed.
// Check discussion below:
//  https://public-inbox.org/libc-alpha/87y2ew8i1w.fsf@igel.home/T/
// Some references:
//  https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/bits/sigstack.h.html#30
//  https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/bits/sigstksz.h.html#28
#ifndef SIGNAL_STACK_SIZE
#error "SIGNAL_STACK_SIZE should be determined before compilation"
#endif
// XXX: we pick a high address to avoid overflow with other important pages
#define SIGNAL_STACK_ADDR (0x100000000 + SIGNAL_STACK_SIZE)

#define RETADDR_MAPPING_ADDR (SIGNAL_STACK_ADDR + SIGNAL_STACK_SIZE)

/*
 * [RW_PAGE_ADDR] The meta information needed during loading
 */
// XXX: members with addr_t are runtime address (especially for PIE)
typedef struct __loading_info_t {
    addr_t program_base;

    uint64_t afl_prev_id;

    uint64_t client_pid;

    uint64_t prev_pc;

    char shadow_path[0x100];
    uint64_t shadow_size;
    addr_t shadow_base;

    char lookup_tab_path[0x100];
    uint64_t lookup_tab_size;
    addr_t lookup_tab_base;

    char pipe_path[0x100];

    char shared_text_path[0x100];
    uint64_t shared_text_size;
    addr_t shared_text_base;

    char retaddr_mapping_path[0x100];
    uint64_t retaddr_mapping_size;
    addr_t retaddr_mapping_base;
    bool retaddr_mapping_used;

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
#define SHARED_TEXT_PREFIX ".text."
#define RETADDR_MAPPING_PREFIX ".ret."
#define CRASHPOINT_LOG_PREFIX ".crashpoint."
#define PIPE_FILENAME_PREFIX ".pipe."
#define PDISASM_FILENAME_PREFIX ".pdisasm."
#define METADATA_FILENAME_PREFIX ".meta."
#define CODE_SEGMENT_FILE_SUFFIX ".code.segments"
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

// in case of conflicting with asan shadow memory
#define LOOKUP_TABLE_ADDR ((0x7fff8000) - LOOKUP_TABLE_MAX_SIZE)

/*
 * Crash check
 */
// For exit code usage, check https://tldp.org/LDP/abs/html/exitcodes.html for
// more information.
// It is lucky that we can play with the high 16 bits of status.
#define __RS(s) ((s) & (0xffff))          // __REAL_STATUS
#define __SF(s) (!!((s) & (0xffff0000)))  // __SELF_FIRED
#define PACK_STATUS(s, r) ((((r) << 16) & (0xffff0000)) | (((s) & (0xffff))))
#define IS_SUSPECT_STATUS(s) \
    (__SF(s) && WIFSIGNALED(__RS(s)) && (WTERMSIG(__RS(s)) == SIGKILL))
#define IS_ABNORMAL_STATUS(s) \
    (__SF(s) || (!WIFEXITED(__RS(s)) && WIFSIGNALED(__RS(s))))
// XXX: AFL uses SIGKILL to terminate a timeouted process (same as us)
#define IS_TIMEOUT_STATUS(s) \
    (!__SF(s) && WIFSIGNALED(__RS(s)) && (WTERMSIG(__RS(s)) == SIGKILL))

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
