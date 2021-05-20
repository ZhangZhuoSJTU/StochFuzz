CC = clang

CFLAGS = -Wall -Wno-unused-command-line-argument -fPIC -pie -ffast-math -D_GNU_SOURCE
LDFLAGS =

SHELLCODE_CFLAGS = -Wall -fno-stack-protector -fno-jump-tables -fpie -O3 -D_GNU_SOURCE

LIBNAME = $(shell find . -regex './lib[^\.\/]*\.h' | tr -d '/' | cut -d '.' -f2)
TOOLNAME = $(shell grep '^\#define OURTOOL ' config.h | cut -d '"' -f2)
VERSION = $(shell grep '^\#define VERSION ' config.h | cut -d '"' -f2)

ifeq ($(shell ../test/check_avx512 2>/dev/null; echo $$?), 0)
	AVX_CFLAGS = -mavx512f -DAVX512
else
	AVX_CFLAGS =
endif

ifneq ($(origin DEBUG_REWRITER), undefined)
	CFLAGS += -DBINARY_SEARCH_INVALID_CRASH -DBINARY_SEARCH_DEBUG_REWRITER=$(strip $(DEBUG_REWRITER))
	SHELLCODE_CFLAGS += -DBINARY_SEARCH_INVALID_CRASH -DBINARY_SEARCH_DEBUG_REWRITER=$(strip $(DEBUG_REWRITER))
endif

# note that the new SINGLE_SUCC_OPT is not well test, as such we add an option to disable it
ifneq ($(origin SINGLE_SUCC_OPT), undefined)
ifeq ('$(SINGLE_SUCC_OPT)', 'disable')
	CFLAGS += -DNSINGLE_SUCC_OPT
	SHELLCODE_CFLAGS += -DNSINGLE_SUCC_OPT
endif
endif

ifneq ($(origin CONSERVATIVE_PATCH), undefined)
ifeq ('$(CONSERVATIVE_PATCH)', 'enable')
	CFLAGS += -DCONSERVATIVE_PATCH
	SHELLCODE_CFLAGS += -DCONSERVATIVE_PATCH
endif
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
	sys_optarg.o \
	disassembler.o \
	rewriter.o \
	patcher.o \
	ucfg_analyzer.o \
	capstone_.o \
	diagnoser.o \
	library_functions/library_functions.o \
	core.o

.PHONY: clean format

debug: CFLAGS += -g -O0 -fsanitize=address -fno-omit-frame-pointer -DDEBUG
debug: SHELLCODE_CFLAGS += -DDEBUG
debug: executable

profile: CFLAGS += -pg -O2 -DNDEBUG
profile: SHELLCODE_CFLAGS += -DNDEBUG
profile: executable

release: CFLAGS += -O2 -DNDEBUG
release: SHELLCODE_CFLAGS += -DNDEBUG
release: executable

executable: loader fork_server tps handlers library_functions_load $(OBJS)
	ar rcs $(LIBNAME).a $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(OBJS) $(realpath ..)/glib/lib/x86_64-linux-gnu/libglib-2.0.a $(realpath ..)/keystone/build/llvm/lib/libkeystone.a $(realpath ..)/capstone/libcapstone.a -o $(LIBNAME).so
	$(CC) $(CFLAGS) $(LDFLAGS) frontend.c $(LIBNAME).a $(realpath ..)/glib/lib/x86_64-linux-gnu/libglib-2.0.a $(realpath ..)/keystone/build/llvm/lib/libkeystone.a $(realpath ..)/capstone/libcapstone.a -o $(TOOLNAME)

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
	python3 rewriter_handlers/generate.py rewriter_handlers

library_functions_load:
	python3 library_functions/generate.py lib.csv library_functions

define test_succ
	cd test && ( ${1} )
endef

define test_fail
	cd test && ( ! ${1} )
endef

define test_whatever
	cd test && ( ${1} || true )
endef

test:
	rm -rf test; cp -r ../test test
	$(call test_succ, ../$(TOOLNAME) -P $(TEST_OPTIONS) -- bzip2.no.pie)
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- bzip2.no.pie --help)
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- bzip2.no.pie -kfd test.c.bz2)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- bzip2.no.pie )
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- libpng-1.2.56 seed.png)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- libpng-1.2.56)
	$(call test_fail, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- crash mdzz)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- crash )
	$(call test_succ, ../$(TOOLNAME) -P $(TEST_OPTIONS) -- openssl-1.0.1f)
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- openssl-1.0.1f leak-268f0e85f4bc45cbaf4d257222b830eac18977f3)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- openssl-1.0.1f)
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- hello)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- hello)
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- rar e -o+ -mt3 -- test.rar)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- rar)
	$(call test_fail, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- timeout mdzz)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- timeout)
ifneq ($(findstring -n,$(TEST_OPTIONS)), -n)
	$(call test_whatever, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- unintentional_crash mdzz)
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- unintentional_crash)
	$(call test_succ, ../$(TOOLNAME) -V $(TEST_OPTIONS) -- unintentional_crash)
endif
ifeq ($(findstring -e,$(TEST_OPTIONS)), -e)
	$(call test_fail, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- no_main mdzz)
	$(call test_succ, ../$(TOOLNAME) -R $(TEST_OPTIONS) -- no_main)
endif
ifneq ($(findstring -r,$(TEST_OPTIONS)), -r)
ifneq ($(findstring -f,$(TEST_OPTIONS)), -f)
	$(call test_whatever, ../$(TOOLNAME) -R -t 5000 $(TEST_OPTIONS) -- z3 -smt2 ex.smt2) # this test may fail due to the memory limit of Github Actions
endif
endif
	# test daemon
	rm -rf test; cp -r ../test test
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' bzip2.no.pie -kfd test.c.bz2)
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' libpng-1.2.56 seed.png)
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' openssl-1.0.1f leak-268f0e85f4bc45cbaf4d257222b830eac18977f3)
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' rar e -o+ -mt3 -- test.rar)
	$(call test_fail, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' crash mdzz)
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' crash)
ifneq ($(findstring -n,$(TEST_OPTIONS)), -n)
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' unintentional_crash mdzz)
endif
ifneq ($(findstring -f,$(TEST_OPTIONS)), -f)
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' hello)
endif
ifeq ($(findstring -e,$(TEST_OPTIONS)), -e)
	$(call test_succ, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' no_main mdzz)
endif
	$(call test_fail, ./test_daemon.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' timeout mdzz)
	$(call test_succ, cat timeout.daemon.log)
	$(call test_succ, grep -F 'get status code: 0x9 (signal: 9)' timeout.daemon.log)

GOOGLE_FTS=\
    boringssl-2016-02-12 \
    c-ares-CVE-2016-5180 \
    freetype2-2017 \
    guetzli-2017-3-30 \
    harfbuzz-1.3.2 \
    json-2017-02-12 \
    lcms-2017-03-21 \
    libarchive-2017-01-04 \
    libjpeg-turbo-07-2017 \
    libpng-1.2.56 \
    libssh-2017-1272 \
    libxml2-v2.9.2 \
    llvm-libcxxabi-2017-01-27 \
    openssl-1.0.1f \
    openssl-1.0.2d \
    openssl-1.1.0c \
    openthread-2018-02-27 \
    pcre2-10.00 \
    proj4-2017-08-14 \
    re2-2014-12-09 \
    sqlite-2016-11-14 \
    vorbis-2017-12-11 \
    woff2-2016-05-06 \
    wpantund-2018-02-27

prepare_google_fts:
	rm -rf test; cp -r ../benchmark test; cp ../test/test_daemon_ignore_asan_sof.sh test

$(GOOGLE_FTS): prepare_google_fts
	$(call test_succ, ./test_daemon_ignore_asan_sof.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' $@.normal $@.seed)
	$(call test_succ, ./test_daemon_ignore_asan_sof.sh ../$(TOOLNAME) '$(TEST_OPTIONS)' $@.inline $@.seed)
	$(call test_succ, rm -f .pdisasm.$@.normal .pdisasm.$@.inline)
	$(call test_succ, grep -F "SUMMARY: AddressSanitizer: stack-overflow" $@.normal.daemon.log || ../$(TOOLNAME) -R $(TEST_OPTIONS) -- $@.normal $@.seed || grep -F "we encounter a rewriting error" $@.normal.daemon.log)
	$(call test_succ, grep -F "SUMMARY: AddressSanitizer: stack-overflow" $@.inline.daemon.log || ../$(TOOLNAME) -R $(TEST_OPTIONS) -- $@.inline $@.seed || grep -F "we encounter a rewriting error" $@.inline.daemon.log)

benchmark: prepare_google_fts $(GOOGLE_FTS)

clean:
	rm -rf $(OBJS) *.out *.bin *.o *.a *.so *_bin.c $(TOOLNAME) test/
	$(MAKE) -C trampolines clean

SOURCES:=$(OBJS:.o=.c)
HEADERS:=$(OBJS:.o=.h)
SOURCES += loader.c fork_server.c frontend.c asm_syscall.c asm_utils.c
SOURCES += rewriter_handlers/*.c rewriter_handlers/*.in
SOURCES += prob_disasm/*.c
SOURCES += prob_disasm/prob_disasm_complete/*.c
HEADERS += address_dictionary.h loader.h fork_server.h config.h afl_config.h crs_config.h $(LIBNAME).h

format:
	clang-format -sort-includes -style=file -i $(SOURCES)
	clang-format -sort-includes -style=file -i $(HEADERS)
	$(MAKE) -C trampolines format
