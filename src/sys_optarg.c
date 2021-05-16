#include "sys_optarg.h"
#include "utils.h"

SysOptArgs sys_optargs = {
    .mode = SYSMODE_NONE,
    .trace_pc = false,
    .count_conflict = false,
    .disable_opt = false,
    .safe_ret = false,
    .instrument_early = false,
    .force_pdisasm = false,
    .force_linear = false,
    .log_level = LOG_INFO,
    .timeout = SYS_TIMEOUT,
    .check_execs = SYS_CHECK_EXECS,
};
