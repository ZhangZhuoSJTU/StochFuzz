CC = clang

CFLAGS = -Wall -Wno-unused-command-line-argument -fPIC -pie -ffast-math -D_GNU_SOURCE
LDFLAGS =

SHELLCODE_CFLAGS = -Wall -fno-stack-protector -fno-jump-tables -fpie -O3 -D_GNU_SOURCE

LIBNAME = libstochfuzz

ifeq ($(shell ../test/check_avx512 2>/dev/null; echo $$?), 0)
	AVX_CFLAGS = -mavx512f -DAVX512
else
	AVX_CFLAGS =
endif

ifneq ($(origin DEBUG_REWRITER), undefined)
ifneq ($(origin DEBUG_PATCHER), undefined)
$(error we cannot debug rewriter and patcher at the same time)
endif
endif

ifneq ($(origin DEBUG_REWRITER), undefined)
	CFLAGS += -DBINARY_SEARCH_INVALID_CRASH -DBINARY_SEARCH_DEBUG_REWRITER=$(strip $(DEBUG_REWRITER))
	SHELLCODE_CFLAGS += -DBINARY_SEARCH_INVALID_CRASH -DBINARY_SEARCH_DEBUG_REWRITER=$(strip $(DEBUG_REWRITER))
endif

ifneq ($(origin DEBUG_PATCHER), undefined)
	CFLAGS += -DBINARY_SEARCH_INVALID_CRASH -DBINARY_SEARCH_DEBUG_PATCHER=$(strip $(DEBUG_PATCHER))
	SHELLCODE_CFLAGS += -DBINARY_SEARCH_INVALID_CRASH -DBINARY_SEARCH_DEBUG_PATCHER=$(strip $(DEBUG_PATCHER))
endif

ifeq ($(TRACE_PC), yes)
	CFLAGS += -DTRACE_PC
	SHELLCODE_CFLAGS += -DTRACE_PC
endif

ifeq ($(NOPTIMIZATION), yes)
	CFLAGS += -DNOPTIMIZATION
	SHELLCODE_CFLAGS += -DNOPTIMIZATION
endif

ifeq ($(COUNT_CONFLICT), yes)
	CFLAGS += -DCOUNT_CONFLICT
	SHELLCODE_CFLAGS += -DCOUNT_CONFLICT
endif

ifeq ($(NGENERIC_PIC), yes)
	CFLAGS += -DNGENERIC_PIC
	SHELLCODE_CFLAGS += -DNGENERIC_PIC
endif

ifeq ($(NPROB_DISASM), yes)
	CFLAGS += -DNPROB_DISASM
	SHELLCODE_CFLAGS += -DNPROB_DISASM
endif

# glib
CFLAGS += $(shell PKG_CONFIG_PATH=$(realpath ..)/glib/lib/x86_64-linux-gnu/pkgconfig/ pkg-config --cflags glib-2.0)
LDFLAGS += -lpthread

# keystone
CFLAGS += -I $(realpath ..)/keystone/include
LDFLAGS += -lstdc++ -lm

# capstone
CFLAGS += -I $(realpath ..)/capstone/include
LDFLAGS +=

OBJS=\
	 binary.o \
	 buffer.o \
	 elf_.o \
	 utils.o \
	 interval_splay.o \
	 mem_file.o \
	 restricted_ptr.o \
	 tp_dispatcher.o \
	 disassembler.o \
	 rewriter.o \
	 patcher.o \
	 inst_analyzer.o \
	 capstone_.o \
	 core.o

debug: CFLAGS += -g -O0 -fsanitize=address -fno-omit-frame-pointer -DDEBUG
debug: SHELLCODE_CFLAGS += -DDEBUG
debug: executable

profile: CFLAGS += -pg -O2 -DNDEBUG
profile: SHELLCODE_CFLAGS += -DNDEBUG
profile: executable

release: CFLAGS += -O2 -DNDEBUG
release: SHELLCODE_CFLAGS += -DNDEBUG
release: executable

executable: $(OBJS)
	ar rcs $(LIBNAME).a $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(OBJS) $(realpath ..)/glib/lib/x86_64-linux-gnu/libglib-2.0.a $(realpath ..)/keystone/build/llvm/lib/libkeystone.a $(realpath ..)/capstone/libcapstone.a -o $(LIBNAME).so
	$(CC) $(CFLAGS) $(LDFLAGS) frontend.c $(LIBNAME).a $(realpath ..)/glib/lib/x86_64-linux-gnu/libglib-2.0.a $(realpath ..)/keystone/build/llvm/lib/libkeystone.a $(realpath ..)/capstone/libcapstone.a -o tool

loader:
	$(CC) $(SHELLCODE_CFLAGS) -c loader.c
	$(CC) -nostdlib -o loader.out loader.o -Wl,--entry=_entry
	objcopy --dump-section .text=loader.bin loader.out
	xxd -i loader.bin > loader_bin.c

fork_server:
	$(CC) $(SHELLCODE_CFLAGS) $(AVX_CFLAGS) -c fork_server.c
	$(CC) -nostdlib -o fork_server.out fork_server.o -Wl,--entry=_entry
	objcopy --dump-section .text=fork_server.bin fork_server.out
	xxd -i fork_server.bin > fork_server_bin.c

tps:
	$(MAKE) -C trampolines

handlers:
	python rewriter_handlers/generate.py rewriter_handlers

binary.o: loader fork_server tps handlers

define test_succ
	cd test && ${1} ${2} ${3} ${4}
endef

define test_fail
	cd test && ! ${1} ${2} ${3} ${4}
endef

test:
	rm -rf test; cp -r ../test test
	$(call test_succ, ../tool, patch, bzip2.no.pie, )
	$(call test_succ, ../tool, run, bzip2.no.pie, --help)
	$(call test_succ, ../tool, run, bzip2.no.pie, -kfd test.c.bz2)
	$(call test_succ, ../tool, view, bzip2.no.pie, )
	$(call test_succ, ../tool, run, libpng-1.2.56, seed.png)
	$(call test_succ, ../tool, view, libpng-1.2.56, )
	$(call test_fail, ../tool, run, crash, mdzz)
	$(call test_succ, ../tool, view, crash, )
	$(call test_succ, ../tool, patch, openssl-1.0.1f, )
	$(call test_succ, ../tool, run, openssl-1.0.1f, leak-268f0e85f4bc45cbaf4d257222b830eac18977f3)
	$(call test_succ, ../tool, view, openssl-1.0.1f, )
	$(call test_succ, ../tool, run, hello, )
	$(call test_succ, ../tool, view, hello, )
	$(call test_succ, ../tool, run, rar, e -o+ -mt3 -- test.rar)
	$(call test_succ, ../tool, view, rar, )
ifneq ($(NGENERIC_PIC), yes)
ifeq ($(NPROB_DISASM), yes)
	$(call test_succ, ../tool, run, z3, -smt2 ex.smt2)
endif
endif
	# test daemon
	rm -rf test; cp -r ../test test
	$(call test_succ, ./test_daemon.sh, ../tool, bzip2.no.pie, -kfd test.c.bz2)
	$(call test_succ, ./test_daemon.sh, ../tool, libpng-1.2.56, seed.png)
	$(call test_succ, ./test_daemon.sh, ../tool, openssl-1.0.1f, leak-268f0e85f4bc45cbaf4d257222b830eac18977f3)
	$(call test_succ, ./test_daemon.sh, ../tool, rar, e -o+ -mt3 -- test.rar)
ifeq ($(NPROB_DISASM), yes)
	$(call test_succ, ./test_daemon.sh, ../tool, hello, )
ifneq ($(NGENERIC_PIC), yes)
	$(call test_succ, ./test_daemon.sh, ../tool, z3, -smt2 ex.smt2)
endif
endif

clean:
	rm -rf $(OBJS) *.out *.bin *.o *.a *.so *_bin.c tool test/
	$(MAKE) -C trampolines clean

SOURCES:=$(OBJS:.o=.c)
HDEADERS:=$(OBJS:.o=.h)
SOURCES += loader.c fork_server.c frontend.c asm_syscall.c asm_utils.c
SOURCES += rewriter_handlers/*.c rewriter_handlers/*.in
SOURCES += prob_disasm/*.c
SOURCES += prob_disasm/prob_disasm_complete/*.c
HDEADERS += address_dictionary.h loader.h fork_server.h config.h afl_config.h crs_config.h $(LIBNAME).h

format:
	clang-format -sort-includes -style=file -i $(SOURCES)
	clang-format -sort-includes -style=file -i $(HDEADERS)
	$(MAKE) -C trampolines format
