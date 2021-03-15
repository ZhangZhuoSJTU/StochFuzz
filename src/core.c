#include "core.h"
#include "crs_config.h"
#include "elf_.h"
#include "utils.h"

#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

/*
 * System clean up
 */
static Core *__core = NULL;

// callback function for exit
static void __core_atexit(void) {
    if (__core) {
        z_core_destroy(__core);
    }
    system("rm -f " TEMPFILE_NAME_PREFIX "*");
}

// stop signal handling
static void __core_handle_stop_sig(int _sig_id) {
    __core_atexit();
    kill(getpid(), SIGKILL);
}

// timeout handling
static void __core_handle_timeout(int _sig_id) {
    if (__core && __core->client_pid != INVALID_PID) {
        z_warn("client timeout");
        kill(__core->client_pid, SIGKILL);
    }
}

// setup all signal handlers
static void __core_setup_signal_handlers(void) {
    struct sigaction sa;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

    /* Various ways of saying "stop". */

    sa.sa_handler = __core_handle_stop_sig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Exec timeout notifications. */

    sa.sa_handler = __core_handle_timeout;
    sigaction(SIGALRM, &sa, NULL);
}

// avoid duplicate setting (in case there are two instances of core)
static bool __core_signal_handled = false;

// setup environment needed by core
static void __core_environment_setup(void) {
    atexit(__core_atexit);
    if (!__core_signal_handled) {
        __core_setup_signal_handlers();
        __core_signal_handled = true;
    }
}

/*
 * Getter and Setter
 */
DEFINE_GETTER(Core, core, GHashTable *, crashpoints);

/*
 * Set clock for client timeout
 */
Z_PRIVATE void __core_set_client_clock(Core *core, pid_t client_pid);

/*
 * Cancel clock for client timeout
 */
Z_PRIVATE void __core_cancel_client_clock(Core *core, pid_t client_pid);

/*
 * Read crashpoint information from logfile
 */
Z_PRIVATE void __core_read_crashpoint_log(Core *core);

/*
 * Update a crashpoint's information
 */
Z_PRIVATE void __core_update_crashpoint_type(Core *core, addr_t addr,
                                             CPType type);

/*
 * Log down crashpoints' informationnn
 */
Z_PRIVATE void __core_write_crashpoint_log(Core *core);

/*
 * Apply all logged crashpoints
 */
Z_PRIVATE void __core_apply_logged_crashpoints(Core *core);

/*
 * Handler a new address
 */
Z_PRIVATE void __core_handle_single_new_address(Core *core, addr_t addr,
                                                CPType cp_type);

/*
 * Setup Shared memory of CRS
 */
Z_PRIVATE void __core_setup_shm(Core *core);

/*
 * Clean up
 */
Z_PRIVATE void __core_clean_environment(Core *core);

/*
 * Setup a unix domain socker for core
 */
Z_PRIVATE void __core_setup_unix_domain_socket(Core *core);

Z_PRIVATE void __core_set_client_clock(Core *core, pid_t client_pid) {
    core->client_pid = client_pid;
    core->it.it_value.tv_sec = (sys_config.timeout / 1000);
    core->it.it_value.tv_usec = (sys_config.timeout % 1000) * 1000;
    setitimer(ITIMER_REAL, &core->it, NULL);
}

Z_PRIVATE void __core_cancel_client_clock(Core *core, pid_t client_pid) {
    if (client_pid != core->client_pid) {
        EXITME("inconsistent client_pid");
    }
    core->client_pid = INVALID_PID;
    core->it.it_value.tv_sec = 0;
    core->it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &core->it, NULL);
}

Z_PRIVATE void __core_setup_unix_domain_socket(Core *core) {
    if (core->sock_fd != INVALID_FD) {
        EXITME("multiple pipelines detected");
    }

    // get pipe filename
    ELF *e = z_binary_get_elf(core->binary);
    const char *pipe_filename = z_elf_get_pipe_filename(e);

    // check filename length
    struct sockaddr_un server;
    if (z_strlen(pipe_filename) >= sizeof(server.sun_path)) {
        EXITME("pipe filename is too long: %s", pipe_filename);
    }

    // set socket
    core->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (core->sock_fd < 0) {
        EXITME("opening unix domain socket error");
    }
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, pipe_filename);

    // bind socket
    if (bind(core->sock_fd, (struct sockaddr *)&server,
             sizeof(struct sockaddr_un))) {
        EXITME("binding stream socket error");
    }
}

Z_PRIVATE void __core_apply_logged_crashpoints(Core *core) {
#define __SHOW_CP(addr, type)                                                  \
    do {                                                                       \
        z_info("logged crashpoint [%s%s%s%s%s]: " COLOR(GREEN, "%#lx"),        \
               ((type)&CP_INTERNAL) ? "internal" : "",                         \
               (((type)&CP_INTERNAL) && ((type)&CP_EXTERNAL)) ? "|" : "",      \
               ((type)&CP_EXTERNAL) ? "external" : "",                         \
               (((type) & (CP_INTERNAL | CP_EXTERNAL)) && ((type)&CP_RETADDR)) \
                   ? "|"                                                       \
                   : "",                                                       \
               ((type)&CP_RETADDR) ? "retaddr" : "", addr);                    \
    } while (0)

#define __APPLY_CPS(filter)                                     \
    do {                                                        \
        GHashTableIter iter;                                    \
        gpointer key, value;                                    \
        g_hash_table_iter_init(&iter, core->crashpoints);       \
                                                                \
        while (g_hash_table_iter_next(&iter, &key, &value)) {   \
            addr_t addr = (addr_t)key;                          \
            addr_t type = (CPType)value & (filter);             \
            if (!type) {                                        \
                continue;                                       \
            }                                                   \
            __SHOW_CP(addr, type);                              \
            __core_handle_single_new_address(core, addr, type); \
        }                                                       \
    } while (0)

    // we do this in two round, where we first ignore CP_RETADDR, and then we
    // only work on CP_RETADDR. So that we can make sure all blocks are
    // identified before building ret bridgs.
    __APPLY_CPS(~CP_RETADDR);
    __APPLY_CPS(CP_RETADDR);

#undef __APPLY_CPS
#undef __SHOW_CP
}

Z_PRIVATE void __core_update_crashpoint_type(Core *core, addr_t addr,
                                             CPType type) {
    CPType type_ =
        (CPType)g_hash_table_lookup(core->crashpoints, GSIZE_TO_POINTER(addr));
    if ((type | type_) != type_) {
        // this check is very important, which is used to avoid modifying
        // core->crashpoints and invalidating any iterator associated with the
        // hash table
        g_hash_table_insert(core->crashpoints, GSIZE_TO_POINTER(addr),
                            GSIZE_TO_POINTER(type | type_));
    }
}

Z_PRIVATE void __core_read_crashpoint_log(Core *core) {
    if (z_access(core->crashpoint_log, F_OK)) {
        z_trace("log file for crashpoints (%s) does not exist",
                core->crashpoint_log);
        return;
    }

    Buffer *buffer = z_buffer_read_file(core->crashpoint_log);
    CrashPoint *cp = (CrashPoint *)z_buffer_get_raw_buf(buffer);
    size_t file_size = z_buffer_get_size(buffer);
    for (size_t i = 0; i < file_size; i += sizeof(CrashPoint), cp++) {
        // handle virtual crashpoints
        if (cp->type & VCP_CALLEE) {
            z_rewriter_set_returned_callees(core->rewriter, cp->addr);
            if (!(cp->type = cp->type & (~VCP_CALLEE))) {
                continue;
            }
        }

        __core_update_crashpoint_type(core, cp->addr, cp->type);
    }

    z_buffer_destroy(buffer);
}

Z_PRIVATE void __core_write_crashpoint_log(Core *core) {
    // before write crashpoints, we need to store unlogged retaddr crashpoints
    {
        GHashTable *unlogged_retaddr_crashpoints =
            z_rewriter_get_unlogged_retaddr_crashpoints(core->rewriter);

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, unlogged_retaddr_crashpoints);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            addr_t addr = (addr_t)key;
            __core_update_crashpoint_type(core, addr, CP_RETADDR);
        }
    }

    // update VCP_CALLEE
    {
        GHashTable *returned_callees =
            z_rewriter_get_returned_callees(core->rewriter);

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, returned_callees);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            addr_t addr = (addr_t)key;
            __core_update_crashpoint_type(core, addr, VCP_CALLEE);
        }
    }

    {
#ifndef BINARY_SEARCH_INVALID_CRASH
        // write down all crashpoints
        FILE *f = z_fopen(core->crashpoint_log, "wb");
        CrashPoint cp = {
            .addr = INVALID_ADDR,
            .type = CP_NONE,
        };

        GHashTableIter iter;
        gpointer key, value;
        g_hash_table_iter_init(&iter, core->crashpoints);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            cp.addr = (addr_t)key;
            cp.type = (CPType)value;
            if (z_fwrite(&cp, sizeof(CrashPoint), 1, f) != 1) {
                EXITME("error on writing crashpoint log file");
            }
        }

        z_fclose(f);
#endif
    }
}

Z_PRIVATE void __core_setup_shm(Core *core) {
    // step (0). check shared memory is already setup
    if (core->shm_id != INVALID_SHM_ID) {
        EXITME("multiple CRS shared memory detected");
    }
    // step (1). set shared memory id
    core->shm_id =
        shmget(IPC_PRIVATE, CRS_MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (core->shm_id < 0) {
        EXITME("failed: shmget()");
    }

    // step (2). set shared memory address
    core->shm_addr = (addr_t)shmat(core->shm_id, NULL, 0);
    if (core->shm_addr == (addr_t)-1) {
        EXITME("failed: shmat()");
    }
}

Z_PRIVATE void __core_clean_environment(Core *core) {
    if (core->shm_id != INVALID_SHM_ID) {
        shmctl(core->shm_id, IPC_RMID, NULL);
        core->shm_id = INVALID_SHM_ID;
        core->shm_addr = INVALID_ADDR;
    }

    if (core->sock_fd != INVALID_FD) {
        close(core->sock_fd);
        core->sock_fd = INVALID_FD;
    }

    ELF *e = z_binary_get_elf(core->binary);
    const char *pipe_filename = z_elf_get_pipe_filename(e);
    if (!z_access(pipe_filename, F_OK)) {
        remove(pipe_filename);
    }
}

Z_PRIVATE void __core_handle_single_new_address(Core *core, addr_t addr,
                                                CPType cp_type) {
    if (!(cp_type & CP_RETADDR)) {
        z_rewriter_rewrite(core->rewriter, addr);
    }
    if (!(cp_type & CP_INTERNAL)) {
        // XXX: note that if it is a retaddr crashpoint, its shadow address
        // should not be a trampoline code.
        addr_t shadow_addr = z_rewriter_get_shadow_addr(core->rewriter, addr);
        assert(shadow_addr != INVALID_ADDR);
        z_patcher_build_bridge(core->patcher, addr, shadow_addr);
    }

    // update crashpoint log
    __core_update_crashpoint_type(core, addr, cp_type);
}

Z_PUBLIC int z_core_perform_dry_run(Core *core, int argc, const char **argv) {
    // update original file
    const char *filename = z_binary_get_original_filename(core->binary);
    assert(!z_strcmp(filename, argv[0]));

    // create phantom file, instead of removing the original file
    const char *patched_filename = z_strcat(filename, PATCHED_FILE_SUFFIX);
    z_binary_save(core->binary, patched_filename);
    z_info("start dry run: %s", patched_filename);

    // prepare a shaow argv_ with argv[0] replaced by patched_filename
    const char **argv_ = z_alloc(argc + 1, sizeof(const char *));
    assert(!argv[argc]);  // the last pointer should be NULL
    for (int i = 1; i <= argc; i++) {
        argv_[i] = argv[i];
    }
    argv_[0] = patched_filename;

#ifdef NDEBUG
    int dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd < 0) {
        EXITME("unable to open /dev/null");
    }
#endif

    while (true) {
        // we have to build new pipe each round, to avoid multi-thread problems
        int st_pipe[2];
        if (pipe(st_pipe) < 0) {
            EXITME("pipe() failed");
        }

        z_core_detach(core);
        pid_t pid = fork();
        if (pid == 0) {
            // isolate the process and configure standard descriptors (including
            // process group)
            if (setsid() < 0) {
                EXITME("setsid() failed");
            }

            // child
            if (dup2(st_pipe[1], CRS_DATA_FD) < 0) {
                EXITME("dup2() failed");
            }

            close(st_pipe[0]);
            close(st_pipe[1]);
#ifdef NDEBUG
            dup2(dev_null_fd, 0);
            dup2(dev_null_fd, 1);
            dup2(dev_null_fd, 2);
            close(dev_null_fd);
#endif
            execv(argv_[0], (char **)argv_);
            exit(0);
        } else {
            // parent
            z_info("start child process [%d]", pid);

            close(st_pipe[1]);
            int signal_fd = st_pipe[0];

            // set clock
            __core_set_client_clock(core, pid);

            int status = 0;
            if (waitpid(pid, &status, 0) < 0) {
                EXITME("waitpid failed");
            }
            z_info("child process exit with %#lx", status);

            // cancel clock
            __core_cancel_client_clock(core, pid);

            z_core_attach(core);
            addr_t crash_rip = 0;
            if (IS_SUSPECT_STATUS(status)) {
                z_info("potential patch crash");
                read(signal_fd, (char *)(&crash_rip), 8);
                close(st_pipe[0]);
                addr_t addr = crash_rip;
                CPType cp_type = CP_NONE;

                if (!z_core_validate_address(core, &addr, &cp_type)) {
                    z_error("real crash! %#lx", addr);
                    z_free(argv_);
                    z_free((char *)patched_filename);
                    return status;
                }

                z_core_new_address(core, addr, cp_type);
            } else {
                close(st_pipe[0]);
                z_free(argv_);
                z_free((char *)patched_filename);
                return status;
            }
        }
    }
}

Z_PUBLIC Core *z_core_create(const char *pathname) {
    __core_environment_setup();

    if (__core) {
        EXITME("there can only be one Core instance");
    }

    z_info("patch binary file: \"%s\"", pathname);
    if (z_strchr(pathname, '/')) {
        // TODO: it is a ugly approach to check working directory, change it
        // when possible
        EXITME("please make sure " OURTOOL
               " running under the same directory with the target bianry (no "
               "slash symbol).");
    }

    Core *core = STRUCT_ALLOC(Core);

    core->binary = z_binary_open(pathname);
    core->disassembler = z_disassembler_create(core->binary);
    core->rewriter = z_rewriter_create(core->disassembler);
    core->patcher = z_patcher_create(core->disassembler);

    core->crashpoints =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    core->crashpoint_log = z_strcat(CRASHPOINT_LOG_PREFIX, pathname);
    __core_read_crashpoint_log(core);

    core->client_pid = INVALID_PID;
    core->it.it_interval.tv_sec = 0;
    core->it.it_interval.tv_usec = 0;
    core->it.it_value.tv_sec = 0;
    core->it.it_value.tv_usec = 0;

    core->shm_id = INVALID_SHM_ID;
    core->shm_addr = INVALID_ADDR;

    core->sock_fd = INVALID_FD;

    __core = core;

    return core;
}

Z_PUBLIC void z_core_activate(Core *core) {
    z_patcher_patch_all(core->patcher);

    z_rewriter_rewrite_beyond_main(core->rewriter);
    z_rewriter_rewrite_main(core->rewriter);

    // XXX: it seems not a good idea to do pre-disassembly (linear-disassembly)
    // z_rewriter_heuristics_rewrite(core->rewriter);

    __core_apply_logged_crashpoints(core);
}

Z_PUBLIC void z_core_destroy(Core *core) {
    __core_clean_environment(core);

    __core_write_crashpoint_log(core);

    z_patcher_destroy(core->patcher);
    z_rewriter_destroy(core->rewriter);
    z_disassembler_destroy(core->disassembler);
    z_binary_destroy(core->binary);

    g_hash_table_destroy(core->crashpoints);
    z_free((char *)core->crashpoint_log);

    z_free(core);

    __core = NULL;
}

Z_PUBLIC void z_core_detach(Core *core) {
    z_binary_set_elf_state(core->binary, ELFSTATE_DISABLE | ELFSTATE_CONNECTED);
}

Z_PUBLIC void z_core_attach(Core *core) {
    z_binary_set_elf_state(core->binary, ELFSTATE_CONNECTED);
}

// XXX: note that z_core_new_address's parameter *cp_type* must be a single type
// (e.g., CP_INTERNAL), instead of multiple types (e.g., CP_RETADDR |
// CP_EXTERNAL)
Z_PUBLIC void z_core_new_address(Core *core, addr_t addr, CPType cp_type) {
    if (cp_type == CP_RETADDR) {
        // for CP_RETADDR, we want to also update other retaddrs who share the
        // same callee with the found one

        Buffer *retaddrs =
            z_rewriter_new_validate_retaddr(core->rewriter, addr);
        size_t n = z_buffer_get_size(retaddrs) / sizeof(addr_t);
        addr_t *addrs = (addr_t *)z_buffer_get_raw_buf(retaddrs);
        z_info("we found %d CP_RETADDR sharing the same callee", n);

        for (int i = 0; i < n; i++) {
            __core_handle_single_new_address(core, addrs[i], cp_type);
        }

        z_buffer_destroy(retaddrs);
    } else {
        assert(!(cp_type & CP_RETADDR));
        __core_handle_single_new_address(core, addr, cp_type);
    }

    /*
     * TODO: re-analyze probability here
     */
}

Z_PUBLIC bool z_core_validate_address(Core *core, addr_t *addr_ptr,
                                      CPType *cp_type) {
    assert(core != NULL);
    addr_t addr = *addr_ptr;

    // check invalid address first
    if (addr == INVALID_ADDR) {
        return false;
    }

    if ((int64_t)addr < 0) {
        // it is caused by a missed ujmp/ucall entry
        addr = (~addr) + 1;
        if (z_disassembler_is_within_disasm_range(core->disassembler, addr) &&
            !z_disassembler_is_potential_inst_entrypoint(core->disassembler,
                                                         addr)) {
            z_info("find new address [internal]: \033[32m%#x\033[0m", addr);
            *addr_ptr = addr;
            *cp_type = CP_INTERNAL;
            return true;
        } else {
            return false;
        }
    } else {
        // it is cause by patch
        if (!z_patcher_check(core->patcher, addr)) {
            return false;
        }
        // XXX: retaddr patch may cause crash when enabling pdisasm
        if (!z_disassembler_fully_support_prob_disasm(core->disassembler) &&
            z_rewriter_check_retaddr_crashpoint(core->rewriter, addr)) {
            z_info("find new address [retaddr]: \033[32m%#x\033[0m", addr);
            *cp_type = CP_RETADDR;
        } else {
            z_info("find new address [external]: \033[32m%#x\033[0m", addr);
            *cp_type = CP_EXTERNAL;
        }
        *addr_ptr = addr;
        return true;
    }
}

Z_PUBLIC void z_core_start_daemon(Core *core, int notify_fd) {
    const char *filename = z_binary_get_original_filename(core->binary);

    // first dry run w/o any parameter to find some crashpoint during init
    // XXX: dry run must be performed before setting up shm
    const char *argv[2] = {NULL, NULL};
    argv[0] = filename;
    z_core_perform_dry_run(core, 1, argv);

    // create phantom file, instead of removing the original file
    const char *phantom_filename = z_strcat(filename, PHANTOM_FILE_SUFFIX);
    z_binary_create_snapshot(core->binary, phantom_filename);
    z_info(
        "phantom file is create, please execute %s to communicate with the "
        "daemon",
        phantom_filename);
    z_free((char *)phantom_filename);

    __core_setup_shm(core);
    __core_setup_unix_domain_socket(core);

    /*
     * Main body to handle on-the-fly patch
     */
    // step (0). listen on core->sock_fd
    if (listen(core->sock_fd, 1)) {
        EXITME("listen unix domain socket failed");
    }

    // step (1). comm connection
    //  step (1.0). notify if necessar
    if (notify_fd != INVALID_FD) {
        if (write(notify_fd, &core->sock_fd, 4) != 4) {
            EXITME("fail to notify parent process");
        }
        close(notify_fd);
        notify_fd = INVALID_FD;
    }
    //  step (1.1). wait connection
    int comm_fd = accept(core->sock_fd, NULL, NULL);
    z_info("daemon gets connection for comm");
    //  step (1.2). send out shm_id and wait for response (handshake)
    int afl_attached = 0;
    {
        assert(sizeof(core->shm_id) == 4);
        if (write(comm_fd, &core->shm_id, sizeof(core->shm_id)) !=
            sizeof(core->shm_id)) {
            EXITME("fail to send shm_id");
        }
        if (read(comm_fd, &afl_attached, 4) != 4) {
            EXITME("fail to recv respone");
        }
    }

    // step (2). output basic information
    if (afl_attached) {
        z_info("AFL detected: %d", afl_attached);
    } else {
        z_info("no AFL attached: %d", afl_attached);
    }
    z_info("daemon handshake successes");

    // step (3). communicate with the client
    //      + if it is not a crash (normal exit), directly stop the daemon. note
    //      that when AFL is attached, no any normal status can be recevied;
    //      + if it is a real crash, the daemon sends CRS_STATUS_CRASH to notify
    //      the client, and (a.) stop the daemon when AFL is not attached or
    //      (b.) continue a new round when AFL is attached;
    //      + if it is a patch crash, the daemon sends CRS_STATUS_NONE/_REMMAP
    //      to guide the client do the on-the-fly patch.
    while (true) {
        /*
         * step (3.1). recv program status from the client
         */
        int status = 0;
        if (read(comm_fd, &status, 4) != 4) {
            EXITME("fail to recv status");
        }
        if (WIFSIGNALED(status)) {
            z_info("get status code: %#x (signal: %d)", status,
                   WTERMSIG(status));
        } else if (WIFEXITED(status)) {
            z_info("get status code: %#x (exit: %d)", status,
                   WEXITSTATUS(status));
        } else {
            z_info("get status code: %#x (stopped? signal: %d)", status,
                   WSTOPSIG(status));
        }

        /*
         * step (3.2). if not patched crash, direct break from the loop
         */
        if (!IS_SUSPECT_STATUS(status)) {
            z_info("the client is not terminated/stopped by a patched crash");
            goto NOT_PATCHED_CRASH;
        }

        /*
         * step (3.3). check returning status and get patch commands
         */
        int crs_status = CRS_STATUS_NONE;
        {
            // step (3.3.0). recv crashed rip from shm
            CPType cp_type = CP_NONE;
            addr_t addr = CRS_INFO_BASE(core->shm_addr, crash_ip);

            // step (3.3.1). check INVALID and update
            if (addr == CRS_INVALID_IP) {
                EXITME(
                    "client exits as SUSPECT_STATUS but no suspected address "
                    "is sent to daemon");
                break;
            }
            CRS_INFO_BASE(core->shm_addr, crash_ip) = CRS_INVALID_IP;

            // step (3.3.2). if any crashed rip is found, it means it is caused
            // by sigsegv
            z_info("find current crash rip: " COLOR(GREEN, "%#lx"), addr);

            // step (3.3.3). validate crashed rip
            if (!z_core_validate_address(core, &addr, &cp_type)) {
                z_info(COLOR(RED, "real crash!"));
                // notify the client that it is a real crash
                crs_status = CRS_STATUS_CRASH;
                if (write(comm_fd, &crs_status, 4) != 4) {
                    EXITME("fail to notify real crash");
                }
                goto NOT_PATCHED_CRASH;
            }

            // step (3.3.4). patch
            z_info("patched crash, prepare patch guidance");
            z_core_new_address(core, addr, cp_type);
        }

        /*
         * step (3.4). check shadow file
         */
        if (z_binary_check_state(core->binary, ELFSTATE_SHADOW_EXTENDED)) {
            z_info("underlying shadow file is extended");
            crs_status = CRS_STATUS_REMMAP;

            // do not forget to disable the shadow_extened flag
            z_binary_set_elf_state(core->binary,
                                   ELFSTATE_SHADOW_EXTENDED | ELFSTATE_DISABLE);
        }

        /*
         * step (3.5). sync binary
         */
        // XXX: according to the following link, it seems the fsync is used to
        // sync changed pages from RAM to the file. It means, those changes made
        // by the daemon is already visible to the phantom file even without
        // fsync. Hence, to improve the performance when the underlying files
        // are relatively large, we disable the fsync.
        //
        // https://unix.stackexchange.com/questions/474946/are-sharing-a-memory-mapped-file-and-sharing-a-memory-region-implemented-based-o
        //
        // z_binary_fsync(core->binary);

        /*
         * step (3.6). send status
         */
        if (write(comm_fd, &crs_status, 4) != 4) {
            EXITME("fail to send crs status");
        }

        /*
         * step (3.7). continue on patching while checking timeout
         */
        {
            // step (3.7.1). set clock
            pid_t client_pid = INVALID_PID;
            if (read(comm_fd, &client_pid, 4) != 4) {
                EXITME("fail to recv client_pid [befor execution]");
            }
            __core_set_client_clock(core, client_pid);

            // step (3.7.2). cancel clock
            if (read(comm_fd, &client_pid, 4) != 4) {
                EXITME("fail to recv client_pid [after execution]");
            }
            __core_cancel_client_clock(core, client_pid);
        }
        // step (3.7.3). continue
        continue;

    NOT_PATCHED_CRASH:
        if (!afl_attached) {
            goto DAEMON_STOP;
        }
    }

DAEMON_STOP:
    __core_clean_environment(core);
}
