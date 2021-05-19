#ifndef __LIBRARY_FUNCTIONS_H
#define __LIBRARY_FUNCTIONS_H

#include "../config.h"

// whether the library function will return to caller
typedef enum lcfg_info_t {
    LCFG_OBJ,  // this is not an imported function but an object
    LCFG_UNK,
    LCFG_RET,
    LCFG_TERM,
} LCFGInfo;

// whether the retaddr pushed by `call` instructions is used
typedef enum lra_info_t {
    LRA_OBJ,  // this is not an imported function but an object
    LRA_UNK,
    LRA_USED,
    LRA_UNUSED,
} LRAInfo;

typedef struct lfunc_info_t {
    const char *name;
    LCFGInfo cfg_info;
    LRAInfo ra_info;
} LFuncInfo;

Z_API void z_libfunc_init();

Z_API void z_libfunc_fini();

Z_API const LFuncInfo *z_libfunc_get_info(const char *name);

Z_API const LFuncInfo *z_libfunc_default();

#endif
