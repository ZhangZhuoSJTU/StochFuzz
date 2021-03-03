/*
 * Workflow of different components (AFL, ZeroPatch, fork server, and client):
 *
 *   +--------- pre-handshake (shm) -----------+
 *   |               +-- pre-handshake (shm) --+
 *   |               |                         |
 * +-+-+        +----+----+              +-----+-----+                +------+
 * |AFL|        |ZeroPatch|              |fork server|                |client|
 * +-+-+        +----+----+              +-----+-----+                +------+
 *   |               |                         |
 *   |               |   [trigger execution]   |   [   new client  &  ]
 *   +--------------{|}----------------------->|   [handshake (socket)]
 *   |               |                         +------------------------>|
 *   |               |                         |                         |
 *   |               |                         |   [ status (wait4) & ]  |
 *   |               |  [ status (socket) & ]  |   [crashsite (socket)]  x crash
 *   |               |  [  crashsite (shm)  ]  |<------------------------+
 *   |               |<------------------------+
 *   |               |                         |
 *   |     validate  |  [ trigger (socket) & ] |
 *   |     crashsite ~  [  patch cmd (shm)   ] |
 *   |     (if fake) +------------------------>|
 *   |               |                         ~ patch self and re-mmap
 *   |               |                         |
 *   |               |                         |   [   new client  &  ]
 *   |               |                         |   [handshake (socket)]
 *   |               |                         +------------------------>|
 *   |               |                         |                         |
 *   |               |                         |   [ status (wait4) & ]  |
 *   |               |  [ status (socket) & ]  |   [crashsite (socket)]  x crash
 *   |               |  [  crashsite (shm)  ]  |<------------------------+
 *   |               |<------------------------+
 *   |               |                         |
 *   |     validate  |  [ trigger (socket) & ] |
 *   |     crashsite ~  [  crash cmd (shm)   ] |
 *   |     (if real) +------------------------>|
 *   |               |                         |
 *   |               |    [status (socket)]    |
 *   |<-------------{|}------------------------+
 *   |               |                         |
 *   |               |                         |
 *   |               | [trigger new execution] |   [   new client  &  ]
 *   +--------------{|}----------------------->|   [handshake (socket)]
 *   |               |                         +------------------------>|
 *   |               |                         |                         |
 *   |               |                         |     [status (wait4)]    | exit
 *   |               |    [status (socket)]    |<------------------------+
 *   |<-------------{|}------------------------+
 *
 */

#include "fork_server.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "asm_utils.c"

extern const char magic_string[];
extern const char no_daemon_str[];
extern const char getenv_err_str[];
extern const char afl_shmat_err_str[];
extern const char crs_shmat_err_str[];
extern const char hello_err_str[];
extern const char read_err_str[];
extern const char fork_err_str[];
extern const char wait4_err_str[];
extern const char mumap_err_str[];
extern const char pipe_err_str[];
extern const char dup2_err_str[];
extern const char env_setting_err_str[];
extern const char socket_err_str[];
extern const char msync_err_str[];
extern const char cmd_err_str[];
extern const char pipe_filename_err_str[];

extern const char afl_shm_env[];

#ifdef DEBUG
extern const char afl_attached_str[];
#endif

#define NO_SHM_ID -233

asm(".globl _entry\n"
    ".type _entry,@function\n"
    "_entry:\n"

    // (1) push all registers
    "\tpushq %r15;\n"
    "\tpushq %r14;\n"
    "\tpushq %r13;\n"
    "\tpushq %r12;\n"
    "\tpushq %r11;\n"
    "\tpushq %r10;\n"
    "\tpushq %r9;\n"
    "\tpushq %r8;\n"
    "\tpushq %rcx;\n"
    "\tpushq %rdx;\n"
    "\tpushq %rsi;\n"
    "\tpushq %rdi;\n"

    // (2) get envp into %rdi
    "\tmovq %rdx, %rdi;\n"

    // (3) call fork_server_start()
    "\tcallq fork_server_start;\n"

    // (?) restore context
    "\tpopq %rdi;\n"
    "\tpopq %rsi;\n"
    "\tpopq %rdx;\n"
    "\tpopq %rcx;\n"
    "\tpopq %r8;\n"
    "\tpopq %r9;\n"
    "\tpopq %r10;\n"
    "\tpopq %r11;\n"
    "\tpopq %r12;\n"
    "\tpopq %r13;\n"
    "\tpopq %r14;\n"
    "\tpopq %r15;\n"

    // (?) jump to following code
    "\tjmp __etext;\n"

    // magic_str
    ASM_STRING(magic_string, MAGIC_STRING)
    // no_daemon_str
    ASM_STRING(no_daemon_str, "fork server: no daemon found, switch to dry run")
    // getenv_err_str
    ASM_STRING(getenv_err_str, "fork server: environments not found")
    // afl_shmat_err_str
    ASM_STRING(afl_shmat_err_str, "fork server: shmat error (AFL)")
    // crs_shmat_err_str
    ASM_STRING(crs_shmat_err_str, "fork server: shmat error (CRS)")
    // hello_err_str
    ASM_STRING(hello_err_str, "fork server: hello error")
    // read_err_str
    ASM_STRING(read_err_str, "fork server: read error")
    // fork_err_str
    ASM_STRING(fork_err_str, "fork server: fork error")
    // wait4_err_str
    ASM_STRING(wait4_err_str, "fork server: wait4 error")
    // mumap_err_str
    ASM_STRING(mumap_err_str, "fork server: mumap error")
    // pipe_err_str
    ASM_STRING(pipe_err_str, "fork server: pipe error")
    // socket_err_str
    ASM_STRING(socket_err_str, "fork server: socket error")
    // msync_err_str
    ASM_STRING(msync_err_str, "fork server: msync error")
    // dup2_err_str
    ASM_STRING(dup2_err_str, "fork server: dup2 error")
    // cmd_err_str
    ASM_STRING(cmd_err_str, "fork server: invalid patch command type")
    // pipe_filename_err_str
    ASM_STRING(pipe_filename_err_str, "fork server: pipe filename too long")
    // env_setting_err_str
    ASM_STRING(env_setting_err_str,
               "fork server: fuzzing without daemon running")

#ifdef DEBUG
    // afl_attached_str
    ASM_STRING(afl_attached_str, "fork server: AFL detected")
#endif

    // AFL's shm environment variable
    ASM_STRING(afl_shm_env, AFL_SHM_ENV));

/*
 * Atoi without any safe check
 */
static inline int fork_server_atoi(char *s) {
    int val = 0;
    bool is_neg = false;

    if (*s == '-') {
        s++;
        is_neg = true;
    }

    while (*s)
        val = val * 10 + (*(s++) - '0');

    if (is_neg) {
        val = -val;
    }

    return val;
}

/*
 * Get shm_id from environment.
 */
static inline int fork_server_get_shm_id(char **envp) {
    char *s;
    while ((s = *(envp++))) {
        // hand-written strcmp with "__AFL_SHM_ID="
        if (*(unsigned long *)s != 0x48535f4c46415f5f) {
            continue;
        }
        if (*(unsigned int *)(s + 8) != 0x44495f4d) {
            continue;
        }
        if (*(s + 12) != '=') {
            continue;
        }

        return fork_server_atoi(s + 13);
    }

    utils_debug_puts(getenv_err_str, true);
    return NO_SHM_ID;
}

/*
 * Patch guided by CRS patch commands, return whether shadow_code needs sync.
 */
static inline bool fork_server_patch(int n) {
    bool shadow_need_sync = true;

    CRSCmd *cmd = (CRSCmd *)(CRS_MAP_ADDR);
    for (int i = 0; i < n; i++, cmd++) {
        if (cmd->type == CRS_CMD_REMMAP) {
            // munmap current shadow file
            if (sys_munmap(
                    (uint64_t)(RW_PAGE_INFO(program_base)) + SHADOW_CODE_ADDR,
                    RW_PAGE_INFO(shadow_size))) {
                utils_error(mumap_err_str, true);
            }
            // remmap it
            RW_PAGE_INFO(shadow_size) = utils_mmap_external_file(
                RW_PAGE_INFO(shadow_path),
                (uint64_t)(RW_PAGE_INFO(program_base)) + SHADOW_CODE_ADDR,
                PROT_READ | PROT_EXEC);
            // we do not need to sync the file right now
            shadow_need_sync = false;
        } else if (cmd->type == CRS_CMD_REWRITE) {
            // patch one by one
            for (int j = 0; j < cmd->size; j++) {
                *((char *)(RW_PAGE_INFO(program_base) + cmd->addr + j)) =
                    cmd->buf[j];
            }
        } else {
            utils_error(cmd_err_str, true);
        }
    }

    return shadow_need_sync;
}

Z_RESERVED static inline void fork_server_output_number(uint64_t n) {
    char *s = (char *)(RW_PAGE_ADDR + RW_PAGE_USED_SIZE + 0x50);
    *(s + 16) = '\x00';
    utils_num2hexstr(s, n);
    utils_puts(s, true);
}

/*
 * Start fork server and do random patch.
 */
NO_INLINE void fork_server_start(char **envp) {
    // step (0). try to connect to the core's daemon
    //  step (0.1). create sock_fd
    int sock_fd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        utils_error(socket_err_str, true);
    }
    //  step (0.2). construct sockaddr
    struct sockaddr_un server;
    server.sun_family = AF_UNIX;
#ifdef DEBUG
    size_t n_ = utils_strcpy(server.sun_path, RW_PAGE_INFO(pipe_path));
    if (n_ >= sizeof(server.sun_path)) {
        utils_error(pipe_filename_err_str, true);
    }
#else
    utils_strcpy(server.sun_path, RW_PAGE_INFO(pipe_path));
#endif
    //  step (0.3). connect to daemon
    if (sys_connect(sock_fd, (struct sockaddr *)&server,
                    sizeof(struct sockaddr_un)) < 0) {
        // daemon is not setup, direct return (dry_run)
        sys_close(sock_fd);
        // make sure fork server is not setup
        if (fork_server_get_shm_id(envp) != NO_SHM_ID) {
            utils_error(env_setting_err_str, true);
        }
        utils_debug_puts(no_daemon_str, true);
        return;
    }

    // step (2). dup2 sock_fd to CRS_DAEMON_FD
    if (sys_dup2(sock_fd, CRS_DAEMON_FD) < 0) {
        utils_error(dup2_err_str, true);
    }
    sys_close(sock_fd);

    // step (3). read crs_shm_id from daemon and respond
    int crs_shm_id = 0;
    if (sys_read(CRS_DAEMON_FD, (char *)&crs_shm_id, 4) != 4) {
        utils_error(hello_err_str, true);
    }
    if (sys_write(CRS_DAEMON_FD, (char *)&crs_shm_id, 4) != 4) {
        utils_error(hello_err_str, true);
    }

    // step (4). get fork server information (whether AFL is attached)
    int afl_shm_id = fork_server_get_shm_id(envp);
    bool afl_attached = (afl_shm_id != NO_SHM_ID);
    if (afl_attached) {
        utils_debug_puts(afl_attached_str, true);
    }

    // step (5). close CRS_FORKSRV_FD and CRS_FORKSRV_FD + 1
    sys_close(CRS_FORKSRV_FD);
    sys_close(CRS_FORKSRV_FD + 1);

    // step (6) [if: AFL_ATTACHED].
    //      munmap the fake AFL_SHARED_MEMORY and mmap the real one
    if (afl_attached) {
        if (sys_munmap(AFL_MAP_ADDR, AFL_MAP_SIZE) != 0) {
            utils_error(mumap_err_str, true);
        }
        if ((size_t)sys_shmat(afl_shm_id, (const void *)AFL_MAP_ADDR,
                              SHM_RND) != AFL_MAP_ADDR) {
            utils_error(afl_shmat_err_str, true);
        }
    }

    // step (7). mmap CRS_SHARED_MEMORY
    if ((size_t)sys_shmat(crs_shm_id, (const void *)CRS_MAP_ADDR, SHM_RND) !=
        CRS_MAP_ADDR) {
        utils_error(crs_shmat_err_str, true);
    }

    // step (8). [if: AFL_ATTACHED]
    //      send 4-byte "hello" message to AFL
    int __afl_temp_data = 0x19961219;
    if (afl_attached) {
        if (sys_write(AFL_FORKSRV_FD + 1, (char *)&__afl_temp_data, 4) != 4) {
            utils_error(hello_err_str, true);
        }
    }

    // step (9). while-loop
    bool crs_loop = false;
    pid_t __afl_fork_pid;

    // step (9.0). create pipe for transferring crashsite
    int crash_pipe[2];
    if (sys_pipe(crash_pipe) < 0) {
        utils_error(pipe_err_str, true);
    }

    while (1) {
        // step (9.1). [if: AFL_ATTACHED && !CRS_LOOP]
        //      wait AFL's signal
        if (afl_attached && !crs_loop) {
            if (sys_read(AFL_FORKSRV_FD, (char *)&__afl_temp_data, 4) != 4) {
                utils_error(read_err_str, true);
            }
        }

        // step (9.2). do fork
        __afl_fork_pid = sys_fork();
        if (__afl_fork_pid < 0) {
            utils_error(fork_err_str, true);
        }

        if (__afl_fork_pid == 0) {
            // step (9.child). dup2 crash_pipe and close all other sockets
            if (sys_dup2(crash_pipe[1], CRS_FORKSRV_FD + 1) < 0) {
                utils_error(dup2_err_str, true);
            }

            sys_close(crash_pipe[0]);
            sys_close(crash_pipe[1]);
            sys_close(AFL_FORKSRV_FD);
            sys_close(AFL_FORKSRV_FD + 1);
            sys_close(CRS_DAEMON_FD);

            RW_PAGE_INFO(afl_prev_id) = 0;
            break;
        } else {
            // step (9.3). [if: AFL_ATTACHED && !CRS_LOOP]
            //      tell AFL that the client is started
            if (afl_attached && !crs_loop) {
                sys_write(AFL_FORKSRV_FD + 1, (char *)&__afl_fork_pid, 4);
            }

            // step (9.4). wait till the client stop
            if (sys_wait4(__afl_fork_pid, &__afl_temp_data, 2, NULL) < 0) {
                utils_error(wait4_err_str, true);
            }

            // step (9.5). check the client's status
            if (WIFSIGNALED(__afl_temp_data)) {
                // step (9.6). if crashed, sent to the daemon to validate
                uint64_t crash_rip = 0;
                sys_read(crash_pipe[0], (char *)(&crash_rip), 8);

                // step (9.7). clear pipe
                char _data[0x400];
                sys_write(crash_pipe[1], _data, 1);
                sys_read(crash_pipe[0], _data, 0x400);

                // step (9.8). notify the daemon and wait response
                *((uint64_t *)CRS_MAP_ADDR) = crash_rip;
                sys_write(CRS_DAEMON_FD, (char *)&__afl_temp_data, 4);
                sys_read(CRS_DAEMON_FD, (char *)&__afl_temp_data, 4);

                // step (9.9). if we need patch, do patch and notify the daemon
                if (__afl_temp_data >= 0) {
                    bool shadow_need_sync = fork_server_patch(__afl_temp_data);

                    // fsync shadow code and lookup table
                    if (sys_msync(LOOKUP_TABLE_ADDR,
                                  RW_PAGE_INFO(lookup_tab_size), MS_SYNC)) {
                        utils_error(msync_err_str, true);
                    }
                    if (shadow_need_sync) {
                        if (sys_msync((uint64_t)(RW_PAGE_INFO(program_base)) +
                                          SHADOW_CODE_ADDR,
                                      RW_PAGE_INFO(shadow_size), MS_SYNC)) {
                            utils_error(msync_err_str, true);
                        }
                    }

                    crs_loop = true;
                } else {
                    // REAL CREASH
                    //      [if: AFL_ATTCHED]: notify AFL and loop
                    //      [if: !AFL_ATTACHED]: crash
                    crs_loop = false;
                    if (afl_attached) {
                        sys_write(AFL_FORKSRV_FD + 1, (char *)&__afl_temp_data,
                                  4);
                    } else {
                        asm volatile("ud2");
                        __builtin_unreachable();
                    }
                }
            } else {
                // step (9.normal).
                //      [if: AFL_ATTCHED]: notify AFL and loop
                //      [if: !AFL_ATTACHED]: exit as normal
                crs_loop = false;
                if (afl_attached) {
                    sys_write(AFL_FORKSRV_FD + 1, (char *)&__afl_temp_data, 4);
                } else {
                    // notify the daemon is exited normally
                    sys_write(CRS_DAEMON_FD, (char *)&__afl_temp_data, 4);
                    sys_exit(0);
                }
            }
        }
    }

    return;
}
