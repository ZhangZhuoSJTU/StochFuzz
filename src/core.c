/*
 * core.c
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
 * Functions and Macros copied and pasted from AFL source code
 */
#define __AFL_ROL64(_x, _r) \
    ((((uint64_t)(_x)) << (_r)) | (((uint64_t)(_x)) >> (64 - (_r))))

Z_PRIVATE uint32_t __afl_hash32(const void *key, uint32_t len, uint32_t seed) {
    const uint64_t *data = (uint64_t *)key;
    uint64_t h1 = seed ^ len;

    len >>= 3;

    while (len--) {
        uint64_t k1 = *data++;

        k1 *= 0x87c37b91114253d5ULL;
        k1 = __AFL_ROL64(k1, 31);
        k1 *= 0x4cf5ad432745937fULL;

        h1 ^= k1;
        h1 = __AFL_ROL64(h1, 27);
        h1 = h1 * 5 + 0x52dce729;
    }

    h1 ^= h1 >> 33;
    h1 *= 0xff51afd7ed558ccdULL;
    h1 ^= h1 >> 33;
    h1 *= 0xc4ceb9fe1a85ec53ULL;
    h1 ^= h1 >> 33;

    return h1;
}

/*
 * Clean cached files
 */
Z_PRIVATE void __core_clean_cache(const char *pathname);

/*
 * Check whether the binary and cached files are valid, and update the meta file
 * if needed.
 */
Z_PRIVATE void __core_check_binary(const char *pathname,
                                   RewritingOptArgs *opts);

/*
 * Get the hash value of current afl bitmap
 */
Z_PRIVATE uint32_t __core_get_bitmap_hash(Core *core);

/*
 * Set clock for client timeout
 */
Z_PRIVATE void __core_set_client_clock(Core *core, pid_t client_pid);

/*
 * Cancel clock for client timeout
 */
Z_PRIVATE void __core_cancel_client_clock(Core *core, pid_t client_pid);

/*
 * Setup shared memory of CRS
 */
Z_PRIVATE void __core_setup_shm(Core *core);

/*
 * Setup shared memory of AFL
 */
Z_PRIVATE void __core_setup_afl_shm(Core *core, int afl_shm_id);

/*
 * Clean up
 */
Z_PRIVATE void __core_clean_environment(Core *core);

/*
 * Setup a unix domain socker for core
 */
Z_PRIVATE void __core_setup_unix_domain_socket(Core *core);

Z_PRIVATE void __core_clean_cache(const char *pathname) {
#define __RM_CACHE(prefix, binary)                       \
    do {                                                 \
        const char *filename = z_strcat(prefix, binary); \
        if (!z_access(filename, F_OK)) {                 \
            if (remove(filename)) {                      \
                EXITME("failed to remove %s", filename); \
            }                                            \
        }                                                \
        z_free((void *)filename);                        \
    } while (0)

    __RM_CACHE(LOOKUP_TABNAME_PREFIX, pathname);
    __RM_CACHE(TRAMPOLINES_NAME_PREFIX, pathname);
    __RM_CACHE(SHARED_TEXT_PREFIX, pathname);
    __RM_CACHE(RETADDR_MAPPING_PREFIX, pathname);
    __RM_CACHE(CRASHPOINT_LOG_PREFIX, pathname);
    __RM_CACHE(PIPE_FILENAME_PREFIX, pathname);
    __RM_CACHE(PDISASM_FILENAME_PREFIX, pathname);
    __RM_CACHE(METADATA_FILENAME_PREFIX, pathname);

#undef __RM_CACHE
}

Z_PRIVATE void __core_check_binary(const char *pathname,
                                   RewritingOptArgs *opts) {
    // step 1. check pathname
    z_info("patch binary file: \"%s\"", pathname);
    if (z_strchr(pathname, '/')) {
        // TODO: it is a ugly approach to check working directory, change it
        // when possible
        EXITME("please make sure " OURTOOL
               " running under the same directory with the target bianry (no "
               "slash symbol).");
    }

    // step 2. collect metadate
    Buffer *binary_buf = z_buffer_read_file(pathname);
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_MD5);
    g_checksum_update(checksum, z_buffer_get_raw_buf(binary_buf),
                      z_buffer_get_size(binary_buf));
    const char *checksum_str = g_checksum_get_string(checksum);
    z_info("MD5(%s) = %s", pathname, checksum_str);

    // step 3. check metadata if needed
    const char *metadata_filename =
        z_strcat(METADATA_FILENAME_PREFIX, pathname);
    if (!z_access(metadata_filename, F_OK)) {
        Buffer *metadata_buf = z_buffer_read_file(metadata_filename);
        size_t metadata_size = z_buffer_get_size(metadata_buf);
        const uint8_t *metadata = z_buffer_get_raw_buf(metadata_buf);

        if (metadata_size !=
            sizeof(RewritingOptArgs) + z_strlen(checksum_str) + 1) {
            z_info("inconsistent size of cache metadata, remove cached files");
            __core_clean_cache(pathname);
        } else if (memcmp(metadata, opts, sizeof(RewritingOptArgs))) {
            z_info("inconsistent rewriting options, remove cached files");
            __core_clean_cache(pathname);
        } else if (z_strcmp((const char *)metadata + sizeof(RewritingOptArgs),
                            checksum_str)) {
            z_info("inconsistent binaries, remove cached files");
            __core_clean_cache(pathname);
        }

        z_buffer_destroy(metadata_buf);
    }

    // step 4. update medadata file
    {
        Buffer *metadata_buf = z_buffer_create(NULL, 0);

        z_buffer_append_raw(metadata_buf, (const uint8_t *)opts,
                            sizeof(RewritingOptArgs));
        z_buffer_append_raw(metadata_buf, (const uint8_t *)checksum_str,
                            z_strlen(checksum_str));
        z_buffer_push(metadata_buf, '\x00');

        z_buffer_write_file(metadata_buf, metadata_filename);

        z_buffer_destroy(metadata_buf);
    }

    // step 5. free
    g_checksum_free(checksum);
    z_buffer_destroy(binary_buf);
    z_free((void *)metadata_filename);
}

Z_PRIVATE uint32_t __core_get_bitmap_hash(Core *core) {
    if (!core->afl_trace_bits) {
        // checking runs are not enabled
        return 0;
    } else {
        return __afl_hash32(core->afl_trace_bits, AFL_MAP_SIZE, AFL_HASH_CONST);
    }
}

Z_PRIVATE void __core_set_client_clock(Core *core, pid_t client_pid) {
    core->client_pid = client_pid;
    core->it.it_value.tv_sec = (core->opts->timeout / 1000);
    core->it.it_value.tv_usec = (core->opts->timeout % 1000) * 1000;
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
    if (core->shm_addr == INVALID_ADDR) {
        EXITME("failed: shmat()");
    }
}

Z_PRIVATE void __core_setup_afl_shm(Core *core, int afl_shm_id) {
    // initial checking
    if (core->opts->check_execs == 0) {
        EXITME("checking runs are disabled");
    }
    if (!z_disassembler_fully_support_prob_disasm(core->disassembler)) {
        EXITME(
            "checking runs are disabled when pdisasm is not fully supported");
    }
    if (afl_shm_id == INVALID_SHM_ID) {
        EXITME("invalid afl_shm_id");
    }

    core->afl_trace_bits = shmat(afl_shm_id, NULL, 0);
    if (core->afl_trace_bits == (void *)-1) {
        EXITME("failed: shmat() for AFL");
    }

    z_info("setup the shared memory of AFL at %p", core->afl_trace_bits);
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

Z_PUBLIC int z_core_perform_dry_run(Core *core, int argc, const char **argv) {
    // update original file
    const char *filename = z_binary_get_original_filename(core->binary);
    assert(!z_strcmp(filename, argv[0]));

    // create phantom file, instead of removing the original file
    const char *patched_filename = z_strcat(filename, PATCHED_FILE_SUFFIX);
    z_binary_save(core->binary, patched_filename);
    z_info("start dry run: %s", patched_filename);

    // get .text information
    ELF *e = z_binary_get_elf(core->binary);
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    addr_t text_addr = text->sh_addr;
    size_t text_size = text->sh_size;

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

            // set LD_PRELOAD if needed
            if (core->opts->r.safe_ret && getenv("STOCHFUZZ_PRELOAD")) {
                setenv("LD_PRELOAD", getenv("STOCHFUZZ_PRELOAD"), 1);
            }

            execv(argv_[0], (char **)argv_);
            exit(0);
        } else {
            // parent
            z_trace("start child process [%d]", pid);

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

            addr_t crash_rip = CRS_INVALID_IP;
            // XXX: this read may fail when the status is not suspect
            read(signal_fd, (char *)(&crash_rip), 8);
            close(st_pipe[0]);

            uint32_t cov = __core_get_bitmap_hash(core);
            CRSStatus crs_status = z_diagnoser_new_crashpoint(
                core->diagnoser, status, crash_rip, cov, false);

            if (crs_status == CRS_STATUS_CRASH ||
                crs_status == CRS_STATUS_NORMAL) {
                z_free(argv_);
                z_free((char *)patched_filename);
                return status;
            }

            // TODO: try to fix this somehow (no idea how currently)
            if (crs_status == CRS_STATUS_DEBUG) {
                // XXX: note that alought it is high likely that the self
                // correction procedure works fine when the crash_rip is on
                // .text sectoin, it is still possible that ASLR can cause some
                // problems.
                // TODO: handle the *extremely* corner case.
                if (IS_SUSPECT_STATUS(status) &&
                    (crash_rip < text_addr ||
                     crash_rip >= text_addr + text_size)) {
                    EXITME(
                        "self correction procedure under dry run mode is "
                        "problematic due to ASLR");
                }
            }
        }
    }
}

Z_PUBLIC Core *z_core_create(const char *pathname, SysOptArgs *opts) {
    if (__core) {
        EXITME("there can only be one Core instance");
    }

    __core_environment_setup();

    __core_check_binary(pathname, &opts->r);

    Core *core = STRUCT_ALLOC(Core);

    core->opts = opts;

    core->binary = z_binary_open(pathname, core->opts->r.instrument_early);
    if (core->opts->r.safe_ret && !core->opts->r.instrument_early) {
        ELF *e = z_binary_get_elf(core->binary);
        if (z_elf_is_statically_linked(e)) {
            z_warn(
                "it is a statically-linked ELF file, make sure you DO NOT set "
                "LD_PRELOAD when running the phantom file.");
        }
    }

    core->disassembler = z_disassembler_create(core->binary, &core->opts->r);
    core->rewriter = z_rewriter_create(core->disassembler, &core->opts->r);
    core->patcher = z_patcher_create(core->disassembler, &core->opts->r);
    core->diagnoser = z_diagnoser_create(core->patcher, core->rewriter,
                                         core->disassembler, &core->opts->r);

    z_diagnoser_read_crashpoint_log(core->diagnoser);

    core->client_pid = INVALID_PID;
    core->it.it_interval.tv_sec = 0;
    core->it.it_interval.tv_usec = 0;
    core->it.it_value.tv_sec = 0;
    core->it.it_value.tv_usec = 0;

    core->shm_id = INVALID_SHM_ID;
    core->shm_addr = INVALID_ADDR;

    core->afl_trace_bits = NULL;

    core->sock_fd = INVALID_FD;

    __core = core;

    return core;
}

Z_PUBLIC void z_core_activate(Core *core) {
    z_patcher_initially_patch(core->patcher);

    z_rewriter_initially_rewrite(core->rewriter);

    // XXX: it seems not a good idea to do pre-disassembly (linear-disassembly)
    // due to the heavy overhead of forking a process
    // z_rewriter_heuristics_rewrite(core->rewriter);

    z_diagnoser_apply_logged_crashpoints(core->diagnoser);
}

Z_PUBLIC void z_core_destroy(Core *core) {
    if (!__core) {
        EXITME("detected an unrestrained core object");
    }

    __core_clean_environment(core);

    z_diagnoser_write_crashpoint_log(core->diagnoser);

    z_diagnoser_destroy(core->diagnoser);
    z_patcher_destroy(core->patcher);
    z_rewriter_destroy(core->rewriter);
    z_disassembler_destroy(core->disassembler);
    z_binary_destroy(core->binary);

    z_free(core);

    __core = NULL;
}

Z_PUBLIC void z_core_detach(Core *core) {
    z_binary_set_elf_state(core->binary, ELFSTATE_DISABLE | ELFSTATE_CONNECTED);
}

Z_PUBLIC void z_core_attach(Core *core) {
    z_binary_set_elf_state(core->binary, ELFSTATE_CONNECTED);
}

Z_PUBLIC void z_core_start_daemon(Core *core, int notify_fd) {
    const char *filename = z_binary_get_original_filename(core->binary);

    // first dry run w/o any parameter to find some crashpoint during init
    // XXX: dry run must be performed before setting up shm
    // XXX: when -e option is given, we do not need to perform such dry runs
    if (!core->opts->r.instrument_early) {
        // before dry run, we first patch the main function as directly
        // returning. As such, we can try our best to avoid the error diagnosis
        // during dry run
        addr_t shadow_main_addr = z_binary_get_shadow_main(core->binary);
        uint8_t ret_byte = 0xc3;
        uint8_t ori_byte = 0;
        z_patcher_unsafe_patch(core->patcher, shadow_main_addr, 1, &ret_byte,
                               &ori_byte);

        const char *argv[2] = {NULL, NULL};
        argv[0] = filename;
        z_core_perform_dry_run(core, 1, argv);

        // repair the main
        z_patcher_unsafe_patch(core->patcher, shadow_main_addr, 1, &ori_byte,
                               NULL);
    }

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
    //  step (1.2). handshake:
    //      * send out shm_id
    //      * recv afl_attached
    //      * recv afl_shm_id
    //      * send core->opts->check_execs (useless when AFL is not attached)
    int afl_attached = 0;
    int afl_shm_id = INVALID_SHM_ID;
    // checking runs are enabled only if
    //      * AFL is attached
    //      * Prob Disassembly is fully supported
    //      * core->opts->check_execs is not zero
    bool check_run_enabled = false;
    {
        assert(sizeof(core->shm_id) == 4);
        if (write(comm_fd, &core->shm_id, sizeof(core->shm_id)) !=
            sizeof(core->shm_id)) {
            EXITME("fail to send shm_id");
        }
        if (read(comm_fd, &afl_attached, 4) != 4) {
            EXITME("fail to recv afl_attached");
        }

        // update checking run information based on whether AFL is attached
        check_run_enabled =
            !!(afl_attached &&
               z_disassembler_fully_support_prob_disasm(core->disassembler) &&
               core->opts->check_execs > 0);
        uint32_t check_execs =
            (check_run_enabled ? core->opts->check_execs : 0);

        if (read(comm_fd, &afl_shm_id, sizeof(afl_shm_id)) !=
            sizeof(afl_shm_id)) {
            EXITME("fail to recv alf_shm_id");
        }
        if (write(comm_fd, &check_execs, 4) != 4) {
            EXITME("fail to send check_execs");
        }

        // simple validation
        if (afl_attached && afl_shm_id == INVALID_SHM_ID) {
            EXITME("AFL is attached but the daemon does not get AFL_SHM_ID");
        }
        if (!afl_attached && afl_shm_id != INVALID_SHM_ID) {
            EXITME("AFL is notattached but the daemon gets AFL_SHM_ID");
        }
        if (check_run_enabled && !afl_attached) {
            EXITME("checking runs are only enabled when AFL is attched");
        }
    }

    // step (2). output basic information and setup AFL shared memory
    if (afl_attached) {
        z_info("AFL detected: %d", afl_attached);
        if (check_run_enabled) {
            // XXX: we only setup the shared memory for AFL when checking runs
            // are enabled
            // XXX: in other words, core->afl_trace_bits indicates whether the
            // checking runs are enabled or not
            __core_setup_afl_shm(core, afl_shm_id);
        }
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
    //      + if it is a patch crash, the daemon sends
    //      CRS_STATUS_NOTHING/_REMMAP to guide the client do the on-the-fly
    //      patch.
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
            // I have been confused by the status handling for a long time at
            // the early time, so I comment it down here for convenience.
            //
            // XXX: theoretically, this branch happens only when
            // WTERMSIG(status) == 0x7f, which covers WIFSTOPPED(status) see:
            //
            //  * WTERMSIG(status)    = ((status) & 0x7f)
            //  * WIFEXITED(status)   = (WTERMSIG(status) == 0)
            //  * WIFSIGNALED(status) =
            //              (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)
            //  * WIFSTOPPED(status)  = (((status) & 0xff) == 0x7f)
            //
            // It is very interesting to see how glibc construct such status:
            //
            //  For WTERMSIG(status) and WIFEXITED(status):
            //      * __W_EXITCODE(ret, sig) = ((ret) << 8 | (sig))
            //  For WIFSTOPPED(status):
            //      * __W_STOPCODE(sig) = ((sig) << 8 | 0x7f)
            //
            z_info("get status code: %#x (stopped? signal: %d)", status,
                   WSTOPSIG(status));
        }

        /*
         * step (3.2). get crash rip and coverage
         */
        addr_t crash_rip = CRS_INFO_BASE(core->shm_addr, crash_ip);
        CRS_INFO_BASE(core->shm_addr, crash_ip) = CRS_INVALID_IP;

        uint32_t cov = __core_get_bitmap_hash(core);

        /*
         * step (3.3). check returning status and get patch commands
         */
        // XXX: we use int to guarantee a 4-byte integer
        int crs_status = z_diagnoser_new_crashpoint(
            core->diagnoser, status, crash_rip, cov, check_run_enabled);

        if (crs_status == CRS_STATUS_CRASH) {
            if (write(comm_fd, &crs_status, 4) != 4) {
                EXITME("fail to notify real crash");
            }
            goto NOT_PATCHED_CRASH;
        }

        if (crs_status == CRS_STATUS_NORMAL) {
            if (check_run_enabled) {
                // notify the fork server about the result of checking runs
                if (write(comm_fd, &crs_status, 4) != 4) {
                    EXITME("fail to notify real crash");
                }
            } else if (afl_attached) {
                EXITME(
                    "CRS_STATUS_NORMAL is invalid when afl is attached but "
                    "checking runs are disabled");
            }
            goto NOT_PATCHED_CRASH;
        }

        /*
         * step (3.4). sync binary
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
         * step (3.5). send status
         */
        if (write(comm_fd, &crs_status, 4) != 4) {
            EXITME("fail to send crs status");
        }

        /*
         * step (3.6). continue on patching while checking timeout
         */
        {
            // step (3.6.1). set clock
            pid_t client_pid = INVALID_PID;
            if (read(comm_fd, &client_pid, 4) != 4) {
                EXITME("fail to recv client_pid [befor execution]");
            }
            __core_set_client_clock(core, client_pid);

            // step (3.6.2). cancel clock
            if (read(comm_fd, &client_pid, 4) != 4) {
                EXITME("fail to recv client_pid [after execution]");
            }
            __core_cancel_client_clock(core, client_pid);
        }
        // step (3.6.3). continue
        continue;

    NOT_PATCHED_CRASH:
        if (!afl_attached) {
            goto DAEMON_STOP;
        }
    }

DAEMON_STOP:
    __core_clean_environment(core);
}
