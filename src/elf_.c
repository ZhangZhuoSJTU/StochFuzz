/*
 * __elf_parse_relocation in elf_.c
 *
 * URL: https://github.com/kubo/plthook
 *
 * ------------------------------------------------------
 *
 * Copyright 2013-2019 Kubo Takehiro <kubo@jiubao.org>
 * Copyright (C) 2021 Zhuo Zhang, Xiangyu Zhang
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the authors.
 *
 */
// XXX: __elf_parse_relocation is modified based on
// https://github.com/kubo/plthook/blob/master/plthook_elf.c

/*
 * other parts of elf_.c
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

// XXX: note that we have multiple streams under an ELF file. Make sure you are
// handling the correct stream(s)

#include "elf_.h"
#include "buffer.h"
#include "capstone_.h"
#include "crs_config.h"
#include "interval_splay.h"
#include "loader.h"
#include "mem_file.h"
#include "restricted_ptr.h"
#include "utils.h"

#include <capstone/capstone.h>

#include <errno.h>

#define EXTEND_ZONE_NUM 1
#define ZONE_SIZE PAGE_SIZE
#define GUARD_SIZE 8

// it seems DEBUG version has much bigger fork_server and loader
#ifdef DEBUG
#define LOADER_ZONE_SIZE (ZONE_SIZE * 3)
#else
#define LOADER_ZONE_SIZE (ZONE_SIZE * 2)
#endif

#define TRAMPOLINES_INIT_SIZE (ZONE_SIZE * 0x100)
#define RETADDR_MAPPING_INIT_SIZE ZONE_SIZE

/*
 * Define special getter and setter for ELF
 */
// XXX: such elements all locate on the main stream
#define ELF_DEFINE_SETTER(OTYPE, ONAME, FTYPE, FNAME)                        \
    Z_API void z_##ONAME##_##set_##FNAME(OTYPE *ONAME, FTYPE FNAME) {        \
        assert(ONAME != NULL);                                               \
        if (FNAME == NULL)                                                   \
            ONAME->FNAME##_off = SIZE_MAX;                                   \
        else {                                                               \
            ONAME->FNAME##_off =                                             \
                ((uint8_t *)FNAME) - z_mem_file_get_raw_buf(ONAME->stream);  \
            assert(ONAME->FNAME##_off < z_mem_file_get_size(ONAME->stream)); \
        }                                                                    \
    }

#define ELF_DEFINE_GETTER(OTYPE, ONAME, FTYPE, FNAME)              \
    Z_API FTYPE z_##ONAME##_##get_##FNAME(OTYPE *ONAME) {          \
        assert(ONAME != NULL);                                     \
        if (ONAME->FNAME##_off == SIZE_MAX)                        \
            return NULL;                                           \
        else                                                       \
            return (FTYPE)(z_mem_file_get_raw_buf(ONAME->stream) + \
                           ONAME->FNAME##_off);                    \
    }

/*
 * Private structure for vmapping
 */
STRUCT(FChunk, {
    _MEM_FILE *stream;
    size_t offset;
    size_t size;
    bool extendable;
});

DEFINE_GETTER(FChunk, fchunk, _MEM_FILE *, stream);
DEFINE_GETTER(FChunk, fchunk, bool, extendable);
DEFINE_GETTER(FChunk, fchunk, size_t, offset);
DEFINE_GETTER(FChunk, fchunk, size_t, size);
DEFINE_SETTER(FChunk, fchunk, size_t, size);

Z_PRIVATE FChunk *z_fchunk_create(_MEM_FILE *stream, size_t offset, size_t size,
                                  bool extendable) {
    FChunk *fc = STRUCT_ALLOC(FChunk);
    fc->stream = stream;
    fc->offset = offset;
    fc->size = size;
    fc->extendable = extendable;
    return fc;
}

Z_PRIVATE void z_fchunk_destroy(FChunk *fc) { z_free(fc); }

/*
 * Find Elf64_Dyn by tag name
 */
Z_PRIVATE Elf64_Dyn *__elf_find_dyn_by_tag(ELF *e, Elf64_Xword tag);

/*
 * Fine Segment by virtual addr
 */
Z_PRIVATE Snode *__elf_find_segment_by_vaddr(ELF *e, addr_t vaddr);

/*
 * Open a file (ori_filename) and load data into _MEM_FILE
 */
Z_PRIVATE _MEM_FILE *__elf_open_file(ELF *e, const char *ori_filename);

/*
 * Valid the header of given ELF
 */
Z_PRIVATE void __elf_validate_header(_MEM_FILE *stream);

/*
 * Parse the program header
 */
Z_PRIVATE void __elf_parse_phdr(ELF *e);

/*
 * Parse the section header
 */
Z_PRIVATE void __elf_parse_shdr(ELF *e);

/*
 * Get relocation information
 */
Z_PRIVATE void __elf_parse_relocation(ELF *e);

/*
 * Detect and parse main function
 */
Z_PRIVATE void __elf_parse_main(ELF *e);

/*
 * Set relocation-preset for given ELF
 */
Z_PRIVATE void __elf_set_relro(ELF *e);

/*
 * Set virtual mapping for given ELF
 */
// Note that after this function, the main stream will be splitted into two
// pieces
Z_PRIVATE void __elf_set_virtual_mapping(ELF *e, const char *filename);

/*
 * Rewrite PT_NOTE
 */
Z_PRIVATE void __elf_rewrite_pt_note(ELF *e);

/*
 * Extend additional zones onto ELF
 */
Z_PRIVATE void __elf_extend_zones(ELF *e);

/*
 * Setup lookup table
 */
Z_PRIVATE void __elf_setup_lookup_table(ELF *e, const char *filename);

/*
 * Setup retaddr mapping
 */
Z_PRIVATE void __elf_setup_retaddr_mapping(ELF *e, const char *filename);

/*
 * Setup trampolines (shadow code)
 */
Z_PRIVATE void __elf_setup_trampolines(ELF *e, const char *filename);

/*
 * Setup shared .text section
 */
Z_PRIVATE void __elf_setup_shared_text(ELF *e, const char *filename);

/*
 * Setup pipeline file
 */
Z_PRIVATE void __elf_setup_pipe(ELF *e, const char *filename);

// TODO: raw pointer might lead to overflow, but we need effecience.
// In the furture, we need a better trade-off.
// Currently, we have checked the access will not be out of boundary in advance.
// Make sure all your raw-pointer access is valid.
/*
 * Get pointer from offset
 */
Z_PRIVATE void *__elf_stream_off2ptr(_MEM_FILE *stream, size_t off);

/*
 * Get offset from virtual address.
 * (the caller must know the addr is on which stream)
 */
Z_PRIVATE size_t __elf_stream_vaddr2off(ELF *e, addr_t addr);

/*
 * Setter and Getter
 */
ELF_DEFINE_SETTER(ELF, elf, Elf64_Ehdr *, ehdr);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Phdr *, phdr_note);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Phdr *, phdr_dynamic);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_shstrtab);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_text);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_init);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_fini);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_init_array);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_fini_array);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_plt);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_plt_got);
ELF_DEFINE_SETTER(ELF, elf, Elf64_Shdr *, shdr_plt_sec);
OVERLOAD_SETTER(ELF, elf, ELFState, state) {
    if (state & ELFSTATE_DISABLE) {
        // if is used to disable associated states
        state = state ^ ELFSTATE_DISABLE;
        if (state & ELFSTATE_CONNECTED) {
            z_mem_file_suspend(elf->stream);
        }
        elf->state &= (state ^ ELFSTATE_MASK);
    } else {
        if (state & ELFSTATE_CONNECTED) {
            z_mem_file_resume(elf->stream);
        }
        elf->state |= state;
    }
}

ELF_DEFINE_GETTER(ELF, elf, Elf64_Ehdr *, ehdr);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Phdr *, phdr_note);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Phdr *, phdr_dynamic);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_shstrtab);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_text);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_init);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_fini);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_init_array);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_fini_array);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_plt);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_plt_got);
ELF_DEFINE_GETTER(ELF, elf, Elf64_Shdr *, shdr_plt_sec);
DEFINE_GETTER(ELF, elf, addr_t, loader_addr);
DEFINE_GETTER(ELF, elf, addr_t, trampolines_addr);
DEFINE_GETTER(ELF, elf, addr_t, lookup_table_addr);
DEFINE_GETTER(ELF, elf, addr_t, shared_text_addr);
DEFINE_GETTER(ELF, elf, addr_t, retaddr_mapping_addr);
DEFINE_GETTER(ELF, elf, bool, is_pie);
DEFINE_GETTER(ELF, elf, addr_t, ori_entry);
DEFINE_GETTER(ELF, elf, const char *, lookup_tabname);
DEFINE_GETTER(ELF, elf, const char *, trampolines_name);
DEFINE_GETTER(ELF, elf, const char *, shared_text_name);
DEFINE_GETTER(ELF, elf, const char *, pipe_filename);
DEFINE_GETTER(ELF, elf, const char *, retaddr_mapping_name);

OVERLOAD_GETTER(ELF, elf, size_t, plt_n) { return g_hash_table_size(elf->plt); }

OVERLOAD_GETTER(ELF, elf, addr_t, main) {
    if (!elf->detect_main) {
        EXITME("the main function has not been automatically detected");
    }

    return elf->main;
}

OVERLOAD_GETTER(ELF, elf, addr_t, init) {
    if (!elf->detect_main) {
        EXITME("the main function has not been automatically detected");
    }

    return elf->init;
}

OVERLOAD_GETTER(ELF, elf, addr_t, fini) {
    if (!elf->detect_main) {
        EXITME("the main function has not been automatically detected");
    }

    return elf->fini;
}

OVERLOAD_GETTER(ELF, elf, addr_t, load_main) {
    if (!elf->detect_main) {
        EXITME("the main function has not been automatically detected");
    }

    return elf->load_main;
}

OVERLOAD_GETTER(ELF, elf, addr_t, load_init) {
    if (!elf->detect_main) {
        EXITME("the main function has not been automatically detected");
    }

    return elf->load_init;
}

OVERLOAD_GETTER(ELF, elf, addr_t, load_fini) {
    if (!elf->detect_main) {
        EXITME("the main function has not been automatically detected");
    }

    return elf->load_fini;
}

Z_PRIVATE size_t __elf_stream_vaddr2off(ELF *e, addr_t addr) {
    // Get corresponding segment
    Snode *segment = __elf_find_segment_by_vaddr(e, addr);
    if (segment == NULL) {
        EXITME("invalid virtual address [%#lx]", addr);
    }

    // Create Rptr
    FChunk *fc = (FChunk *)z_snode_get_data(segment);
    if (fc == NULL || z_strcmp(STRUCT_TYPE(fc), "FChunk")) {
        EXITME("get address into dynamically allocated space");
    }
    size_t off1 = addr - z_snode_get_lower_bound(segment);
    size_t off2 = z_fchunk_get_offset(fc);
    if (off1 >= z_fchunk_get_size(fc)) {
        EXITME("trying to read on zero-padding region");
    }

    return off1 + off2;
}

Z_PRIVATE _MEM_FILE *__elf_open_file(ELF *e, const char *ori_filename) {
    Buffer *buf = z_buffer_read_file(ori_filename);

    const char *buf_raw_buf = (const char *)z_buffer_get_raw_buf(buf);
    size_t buf_size = z_buffer_get_size(buf);

    // magic check for re-patch
    if (memmem(buf_raw_buf, buf_size, MAGIC_STRING, z_strlen(MAGIC_STRING))) {
        EXITME("try to re-instrument file \"%s\"", ori_filename);
    }

    _MEM_FILE *stream = z_mem_file_fopen((const char *)e->tmpnam, "w+");
    z_mem_file_fwrite((char *)buf_raw_buf, buf_size, sizeof(uint8_t), stream);

    // generate backup file
    const char *bak_filename = z_strcat(ori_filename, BACKUP_FILE_SUFFIX);
    z_buffer_write_file(buf, bak_filename);
    z_free((char *)bak_filename);
    z_buffer_destroy(buf);
    return stream;
}

Z_PRIVATE void *__elf_stream_off2ptr(_MEM_FILE *stream, size_t off) {
    assert(stream != NULL);

    if (z_mem_file_get_size(stream) <= off) {
        EXITME("invalid offset(%ld) from stream(%ld): %s", off,
               z_mem_file_get_size(stream), z_mem_file_get_filename(stream));
    }

    return (void *)(z_mem_file_get_raw_buf(stream) + off);
}

Z_PRIVATE void __elf_rewrite_pt_note(ELF *e) {
    // XXX: note that rewriter_pt_note should be applied on the main stream.
    assert(e != NULL);

    Elf64_Phdr *phdr = z_elf_get_phdr_note(e);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_X | PF_R;
    // XXX: e->loader_addr cannot be on the shared .text stream
    phdr->p_offset = __elf_stream_vaddr2off(e, e->loader_addr);
    phdr->p_vaddr = (Elf64_Addr)e->loader_addr;
    phdr->p_paddr = (Elf64_Addr)NULL;
    phdr->p_filesz = LOADER_ZONE_SIZE;
    phdr->p_memsz = LOADER_ZONE_SIZE;
    phdr->p_align = PAGE_SIZE;
}

Z_PRIVATE void __elf_setup_pipe(ELF *e, const char *filename) {
    assert(e != NULL);

    assert(!z_strchr(filename, '/'));
    e->pipe_filename = z_strcat(PIPE_FILENAME_PREFIX, filename);

    return;
}

Z_PRIVATE void __elf_setup_retaddr_mapping(ELF *e, const char *filename) {
    assert(e != NULL);

    // step (0). update retaddr_mapping_addr
    e->retaddr_mapping_addr = RETADDR_MAPPING_ADDR;

    // step (1). get filename
    assert(!z_strchr(filename, '/'));
    e->retaddr_mapping_name = z_strcat(RETADDR_MAPPING_PREFIX, filename);

    // step (2). create _MEM_FILE
    e->retaddr_mapping_stream =
        z_mem_file_fopen((const char *)e->retaddr_mapping_name, "w+");
    z_mem_file_pwrite(e->retaddr_mapping_stream, "", 1,
                      RETADDR_MAPPING_INIT_SIZE - 1);

    // step (3). insert into virtual mapping
    Snode *node = NULL;
    FChunk *fc = z_fchunk_create(e->retaddr_mapping_stream, 0,
                                 RETADDR_MAPPING_INIT_SIZE, true);
    node = z_snode_create(e->retaddr_mapping_addr, RETADDR_MAPPING_INIT_SIZE,
                          (void *)fc, (void (*)(void *))(&z_fchunk_destroy));
    if (!z_splay_insert(e->vmapping, node)) {
        EXITME("overlapped retaddr mapping");
    }

    // step (4). update mmapped informaiton
    node = z_snode_create(e->retaddr_mapping_addr, RETADDR_MAPPING_INIT_SIZE,
                          NULL, NULL);
    if (!z_splay_insert(e->mmapped_pages, node)) {
        EXITME("overlapped retaddr mapping");
    }
}

Z_PRIVATE void __elf_setup_lookup_table(ELF *e, const char *filename) {
    assert(e != NULL);

    // step (1). get address
    e->lookup_table_addr = LOOKUP_TABLE_ADDR;

    // step (2). get filename
    assert(!z_strchr(filename, '/'));
    e->lookup_tabname = z_strcat(LOOKUP_TABNAME_PREFIX, filename);

    // step (3). create _MEM_FILE
    e->lookup_table_stream =
        z_mem_file_fopen((const char *)e->lookup_tabname, "w+");
    z_mem_file_fix_size(e->lookup_table_stream, LOOKUP_TABLE_SIZE);
    z_mem_file_pwrite(e->lookup_table_stream, "", 1, LOOKUP_TABLE_SIZE - 1);

    // step (4). fill in pre-defined values
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    addr_t text_addr = text->sh_addr;
    size_t text_size = text->sh_size;
    addr_t cur_addr = text_addr;
    int64_t cell_val = -1;
    for (size_t i = 0; i < LOOKUP_TABLE_CELL_NUM; i++) {
        cell_val = -1;
        if (cur_addr < text_addr + text_size) {
            // For valid address, we initial it as its original value's opposite
            // value
            cell_val = -((int64_t)cur_addr);
        }
        cell_val &= LOOKUP_TABLE_CELL_MASK;
        z_mem_file_fwrite((uint8_t *)(&cell_val), sizeof(uint8_t),
                          LOOKUP_TABLE_CELL_SIZE, e->lookup_table_stream);
        cur_addr += 1;
    }
    assert(cell_val == (-1 & LOOKUP_TABLE_CELL_MASK));

    // step (5). insert into virtual mapping
    Snode *node = NULL;
    FChunk *fc =
        z_fchunk_create(e->lookup_table_stream, 0, LOOKUP_TABLE_SIZE, false);
    node = z_snode_create(e->lookup_table_addr, LOOKUP_TABLE_SIZE, (void *)fc,
                          (void (*)(void *))(&z_fchunk_destroy));
    if (!z_splay_insert(e->vmapping, node)) {
        EXITME("overlapped lookup table");
    }

    // step (6). update mmapped informaiton
    node = z_snode_create(e->lookup_table_addr, LOOKUP_TABLE_SIZE, NULL, NULL);
    if (!z_splay_insert(e->mmapped_pages, node)) {
        EXITME("overlapped lookup table");
    }
}

Z_PRIVATE void __elf_setup_shared_text(ELF *e, const char *filename) {
    assert(e != NULL);

    // step (0). get .text information
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    addr_t text_addr = text->sh_addr;
    size_t text_size = text->sh_size;
    size_t text_offset = text->sh_offset;

    addr_t aligned_addr = BITS_ALIGN_FLOOR(text_addr, PAGE_SIZE_POW2);
    size_t aligned_offset = BITS_ALIGN_FLOOR(text_offset, PAGE_SIZE_POW2);
    size_t aligned_size = BITS_ALIGN_CELL(
        text_size + text_offset - aligned_offset, PAGE_SIZE_POW2);

    e->shared_text_addr = aligned_addr;

    // step (1). get filename
    assert(!z_strchr(filename, '/'));
    e->shared_text_name = z_strcat(SHARED_TEXT_PREFIX, filename);

    // step (2). create _MEM_FILE
    e->shared_text_stream =
        z_mem_file_fopen((const char *)e->shared_text_name, "w+");
    z_mem_file_fix_size(e->shared_text_stream, aligned_size);
    z_mem_file_pwrite(e->shared_text_stream, "", 1, aligned_size - 1);

    // step (3). update data to _MEM_FILE
    // XXX: note that e->stream is alreay page-aligned, which means the
    // following memcpy is safe.
    uint8_t *base = z_mem_file_get_raw_buf(e->stream);
    uint8_t *src = base + aligned_offset;
    uint8_t *dst = z_mem_file_get_raw_buf(e->shared_text_stream);
    memcpy(dst, src, aligned_size);

    // step (4). generate virtual mapping information
    FChunk *fc = z_fchunk_create(e->shared_text_stream, 0, aligned_size, false);
    Snode *node = z_snode_create(aligned_addr, aligned_size, (void *)fc,
                                 (void (*)(void *))(&z_fchunk_destroy));

    // step (5). insert into virtual mapping
    if (!z_splay_insert(e->vmapping, node)) {
        EXITME("overlapped shared .text section");
    }

    // XXX: mapped_pages will be updated in __elf_set_virtual_mapping
}

Z_PRIVATE void __elf_setup_trampolines(ELF *e, const char *filename) {
    assert(e != NULL);

    // step (0). update trampolines_addr
    e->trampolines_addr = SHADOW_CODE_ADDR;

    // step (1). get filename
    assert(!z_strchr(filename, '/'));
    e->trampolines_name = z_strcat(TRAMPOLINES_NAME_PREFIX, filename);

    // step (2). create _MEM_FILE
    e->trampolines_stream =
        z_mem_file_fopen((const char *)e->trampolines_name, "w+");
    z_mem_file_pwrite(e->trampolines_stream, "", 1, TRAMPOLINES_INIT_SIZE - 1);

    // step (3). insert into virtual mapping
    Snode *node = NULL;
    FChunk *fc =
        z_fchunk_create(e->trampolines_stream, 0, TRAMPOLINES_INIT_SIZE, true);
    node = z_snode_create(e->trampolines_addr, TRAMPOLINES_INIT_SIZE,
                          (void *)fc, (void (*)(void *))(&z_fchunk_destroy));
    if (!z_splay_insert(e->vmapping, node)) {
        EXITME("overlapped trampolines");
    }

    // step (4). update mmapped informaiton
    node =
        z_snode_create(e->trampolines_addr, TRAMPOLINES_INIT_SIZE, NULL, NULL);
    if (!z_splay_insert(e->mmapped_pages, node)) {
        EXITME("overlapped trampolines");
    }
}

Z_PRIVATE void __elf_extend_zones(ELF *e) {
    assert(e != NULL);

    /*
     * A trick here to splite amongs new zones is to insert an eight-byte gap at
     * the end of each zone.
     */

    Snode *node;
    addr_t vaddr = BITS_ALIGN_CELL(e->max_addr, PAGE_SIZE_POW2);
    size_t offset = z_mem_file_get_size(e->stream);
    assert(offset % PAGE_SIZE == 0);

    size_t *zones[EXTEND_ZONE_NUM] = {&e->loader_addr};
    addr_t zones_addr[EXTEND_ZONE_NUM] = {vaddr};
    size_t zones_size[EXTEND_ZONE_NUM] = {LOADER_ZONE_SIZE};
    size_t zones_guard[EXTEND_ZONE_NUM] = {GUARD_SIZE};

    // Set zones
    for (size_t i = 0; i < EXTEND_ZONE_NUM; i++) {
        size_t zone_size = zones_size[i];
        size_t zone_guard = zones_guard[i];

        vaddr = zones_addr[i];
        *zones[i] = vaddr;

        FChunk *fc =
            z_fchunk_create(e->stream, offset, zone_size - zone_guard, false);
        node = z_snode_create(vaddr, zone_size - zone_guard, (void *)fc,
                              (void (*)(void *))(&z_fchunk_destroy));

        if (!z_splay_insert(e->vmapping, node)) {
            EXITME("overlapped zones");
        }
        z_info("zone base at %#lx with offset %#lx", vaddr, offset);

        assert(vaddr % PAGE_SIZE == 0);
        assert(zone_size % PAGE_SIZE == 0);
        node = z_snode_create(vaddr, zone_size, NULL, NULL);
        if (!z_splay_insert(e->mmapped_pages, node)) {
            EXITME("overlapped zones");
        }

        offset += zone_size;
    }

    // Extend file
    z_mem_file_pwrite(e->stream, "", 1, offset - 1);
}

Z_PRIVATE Snode *__elf_find_segment_by_vaddr(ELF *e, addr_t vaddr) {
    Snode *segment = z_splay_search(e->vmapping, vaddr);
    if (segment == NULL) {
        return NULL;
    }

    assert(vaddr >= z_snode_get_lower_bound(segment));
    assert(vaddr <= z_snode_get_upper_bound(segment));

    return segment;
}

Z_PRIVATE Elf64_Dyn *__elf_find_dyn_by_tag(ELF *e, Elf64_Xword tag) {
    Elf64_Phdr *dynamic_phdr = z_elf_get_phdr_dynamic(e);
    if (z_unlikely(!dynamic_phdr)) {
        EXITME("dynamic segment not found");
    }

    // get the first dyn
    // XXX: note that it is safe to use __elf_stream_off2ptr
    Elf64_Dyn *dyn =
        (Elf64_Dyn *)__elf_stream_off2ptr(e->stream, dynamic_phdr->p_offset);

    while (dyn->d_tag != DT_NULL) {
        if (dyn->d_tag == tag) {
            return dyn;
        }
        dyn++;
    }

    return (tag == DT_NULL ? dyn : NULL);
}

Z_RESERVED Z_PRIVATE void __elf_set_relro(ELF *e) {
    assert(e != NULL);

    Elf64_Phdr *dynamic_phdr = z_elf_get_phdr_dynamic(e);

    if (dynamic_phdr != NULL) {
        bool is_relro = false;
        Elf64_Dyn *dt_debug = NULL;
        Elf64_Dyn *iter = (Elf64_Dyn *)__elf_stream_off2ptr(
            e->stream, dynamic_phdr->p_offset);

        while (iter->d_tag != DT_NULL) {
            z_trace(
                "find dynamic section with d_tag: %#lx =? %#lx, and d_un "
                "%p",
                iter->d_tag, DT_BIND_NOW, iter->d_un);

            if (iter->d_tag == DT_DEBUG)
                dt_debug = iter;
            if (iter->d_tag == DT_BIND_NOW) {
                is_relro = true;
                break;
            }
            if (iter->d_tag == DT_FLAGS &&
                (iter->d_un.d_val & DF_BIND_NOW) != 0) {
                is_relro = true;
                break;
            }

            iter++;
        }

        if (is_relro) {
            z_info("binary is already RELRO");
        } else {
            if (dt_debug) {
                z_info(
                    "binary is not RELRO. Hence, we patch it into DT_DEBUG "
                    "entry.");
                dt_debug->d_tag = DT_FLAGS;
                dt_debug->d_un.d_val = DF_BIND_NOW;
            } else {
                z_warn(
                    "binary is not RELRO and has no DT_DEBUG entry. Hence, "
                    "we failed to patch it");
            }
        }
    } else {
        z_info("statically linked binary");
    }
}

#define __NUMBER_OF_GOTS 2
#define __NUMBER_OF_PLTS 3

// TODO: make sure PIE binaries would not cause any trouble
// TODO: if any section is missed, directly return errors instead of EXITME
Z_PRIVATE void __elf_parse_relocation(ELF *e) {
    // XXX: we use z_elf_read_all to avoid inter-stream data

    // step (0). init related field of ELF and return if statically-linked
    e->got = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    e->plt = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    if (!z_elf_get_phdr_dynamic(e)) {
        z_info("statically-linked binary does not have relocation information");
        return;
    }

    /*
     * step (1). collect necessary information
     */
    const Elf64_Dyn *dyn = NULL;
    const Elf64_Sym *dynsym = NULL;
    const char *dynstr = NULL;
    size_t dynstr_size = 0;
    const Elf64_Rela *rela_plt = NULL;
    size_t rela_plt_cnt = 0;
    const Elf64_Rela *rela_dyn = NULL;
    size_t rela_dyn_cnt = 0;

    // .dynstr size
    dyn = __elf_find_dyn_by_tag(e, DT_STRSZ);
    if (!dyn) {
        EXITME("fail to find DT_STRSZ");
    }
    dynstr_size = dyn->d_un.d_val;

    // .dynstr section
    dyn = __elf_find_dyn_by_tag(e, DT_STRTAB);
    if (!dyn) {
        EXITME("fail to find DT_STRTAB");
    }
    dynstr = z_alloc(dynstr_size + 1, sizeof(char));
    if (z_elf_read_all(e, dyn->d_un.d_ptr, dynstr_size, (void *)dynstr) !=
        dynstr_size) {
        EXITME("invalid synstr_size");
    }

    // .rela.plt section
    dyn = __elf_find_dyn_by_tag(e, DT_JMPREL);
    if (dyn) {
        addr_t rela_plt_addr = dyn->d_un.d_ptr;

        dyn = __elf_find_dyn_by_tag(e, DT_PLTRELSZ);
        if (!dyn) {
            EXITME("fail to find DT_PLTRELSZ when DT_JMPREL is found");
        }
        rela_plt_cnt = dyn->d_un.d_val / sizeof(Elf64_Rela);

        rela_plt = z_alloc(rela_plt_cnt, sizeof(Elf64_Rela));
        if (z_elf_read_all(e, rela_plt_addr, dyn->d_un.d_val,
                           (void *)rela_plt) != dyn->d_un.d_val) {
            EXITME("invalid size of .rela.plt");
        }

        if (!z_elf_get_shdr_plt(e)) {
            EXITME("fail to find .plt section when DT_JMPREL is found");
        }
    }

    // .rela.dyn section
    dyn = __elf_find_dyn_by_tag(e, DT_RELA);
    if (dyn) {
        addr_t rela_dyn_addr = dyn->d_un.d_ptr;

        size_t total_size = 0, elem_size = 0;

        dyn = __elf_find_dyn_by_tag(e, DT_RELASZ);
        if (!dyn) {
            EXITME("fail to find DT_RELASZ when DT_RELA is found");
        }
        total_size = dyn->d_un.d_val;

        dyn = __elf_find_dyn_by_tag(e, DT_RELAENT);
        if (!dyn) {
            EXITME("fail to find DT_RELAENT when DT_RELA is found");
        }
        elem_size = dyn->d_un.d_val;

        rela_dyn_cnt = total_size / elem_size;

        rela_dyn = z_alloc(rela_dyn_cnt, elem_size);
        if (z_elf_read_all(e, rela_dyn_addr, total_size, (void *)rela_dyn) !=
            total_size) {
            EXITME("invalid size of .rela.dyn");
        }
    }

    // check .rela.plt and .rela.dyn
    if (!rela_plt && !rela_dyn) {
        EXITME("fail to find neither DT_JMPREL nor DT_RELA");
    }

    const Elf64_Rela *gots[__NUMBER_OF_GOTS] = {rela_plt, rela_dyn};
    const size_t gots_cnt[__NUMBER_OF_GOTS] = {rela_plt_cnt, rela_dyn_cnt};
    const int gots_type[__NUMBER_OF_GOTS] = {R_X86_64_JUMP_SLOT,
                                             R_X86_64_GLOB_DAT};
    const char *gots_str[__NUMBER_OF_GOTS] = {".rela.plt", ".rela.dyn"};

    // let first quickly go though how many symbols we need
    size_t max_idx = 0;
    for (size_t k = 0; k < __NUMBER_OF_GOTS; k++) {
        const Elf64_Rela *got = gots[k];
        const size_t cnt = gots_cnt[k];
        const int type = gots_type[k];

        for (size_t i = 0; i < cnt; i++, got++) {
            if (ELF64_R_TYPE(got->r_info) == type) {
                size_t idx = ELF64_R_SYM(got->r_info);
                if (idx > max_idx) {
                    max_idx = idx;
                }
            }
        }
    }
    z_info("require %d symbols", max_idx + 1);

    // check sizeof(Elf64_Sym)
    dyn = __elf_find_dyn_by_tag(e, DT_SYMENT);
    if (!dyn) {
        EXITME("fail to find DT_SYMTAB");
    }
    if (dyn->d_un.d_val != sizeof(Elf64_Sym)) {
        EXITME("inconsistent size of Elf64_Sym: %#lx v/s %#lx", dyn->d_un.d_val,
               sizeof(Elf64_Sym));
    }

    // .dynsym section
    dyn = __elf_find_dyn_by_tag(e, DT_SYMTAB);
    if (!dyn) {
        EXITME("fail to find DT_SYMTAB");
    }
    dynsym = z_alloc(max_idx + 1, sizeof(Elf64_Sym));
    if (z_elf_read_all(e, dyn->d_un.d_ptr, sizeof(Elf64_Sym) * (max_idx + 1),
                       (void *)dynsym) != sizeof(Elf64_Sym) * (max_idx + 1)) {
        EXITME("symtab does not hold enough symbols");
    }

    /*
     * step (2). collect GOT information
     */
    for (size_t k = 0; k < __NUMBER_OF_GOTS; k++) {
        const Elf64_Rela *got = gots[k];
        const size_t cnt = gots_cnt[k];
        const int type = gots_type[k];
        const char *str = gots_str[k];

        for (size_t i = 0; i < cnt; i++, got++) {
            if (ELF64_R_TYPE(got->r_info) == type) {
                // get function name
                size_t idx = ELF64_R_SYM(got->r_info);
                idx = dynsym[idx].st_name;
                if (idx >= dynstr_size) {
                    EXITME("too big section header string table index: %#lx",
                           idx);
                }
                const char *func_name = dynstr + idx;

                // get function address
                const addr_t func_addr = (addr_t)(got->r_offset);

                const LFuncInfo *func_info = LB_QUERY(func_name);
                z_info("function GOT [%s]: %s @ %#lx | %s | %s ", str,
                       func_name, func_addr,
                       (func_info->cfg_info == LCFG_UNK
                            ? COLOR(YELLOW, "unknown")
                            : (func_info->cfg_info == LCFG_OBJ
                                   ? "object"
                                   : (func_info->cfg_info == LCFG_RET
                                          ? COLOR(GREEN, "returnable")
                                          : COLOR(RED, "terminated")))),
                       (func_info->ra_info == LRA_UNK
                            ? COLOR(YELLOW, "unknown")
                            : (func_info->ra_info == LRA_OBJ
                                   ? "object"
                                   : (func_info->ra_info == LRA_USED
                                          ? COLOR(RED, "used")
                                          : COLOR(GREEN, "unused")))));

                g_hash_table_insert(e->got, GSIZE_TO_POINTER(func_addr),
                                    (gpointer)func_info);
            }
        }
    }

    /*
     * step (3). collect PLT information
     */
    // we check .plt and .plt.got sections by check the instruction
    Elf64_Shdr *plts[__NUMBER_OF_PLTS] = {z_elf_get_shdr_plt(e),
                                          z_elf_get_shdr_plt_got(e),
                                          z_elf_get_shdr_plt_sec(e)};

    for (size_t k = 0; k < __NUMBER_OF_PLTS; k++) {
        Elf64_Shdr *plt = plts[k];
        if (!plt) {
            continue;
        }

        addr_t plt_addr = plt->sh_addr;
        size_t plt_size = plt->sh_size;
        size_t plt_entsize = plt->sh_entsize;
        if (!plt_addr || !plt_size) {
            EXITME("invalid .plt section");
        }
        if (!plt_entsize) {
            plt_entsize = plt_size;
        }

        size_t off = 0;
        uint8_t *ptr = z_alloc(plt_size, sizeof(uint8_t));
        if (z_elf_read_all(e, plt_addr, plt_size, ptr) != plt_size) {
            EXITME("fail to load data form PLT");
        }

        // TODO: the first element in .plt is reserved for resloving, remove it.
        while (off < plt_size) {
            const LFuncInfo *func_info = LB_DEFAULT();

            CS_DISASM_RAW(ptr + off, plt_size - off, plt_addr + off, 1);

            if (cs_inst->id == X86_INS_ENDBR64 &&
                off + cs_inst->size < plt_size) {
                // XXX: handle intel CET tech. Note that we may need to
                // carefully design our system about how to handle CET/IBT.
                size_t endbr64_size = cs_inst->size;
                CS_DISASM_RAW(ptr + off + endbr64_size,
                              plt_size - off - endbr64_size,
                              plt_addr + off + endbr64_size, 1);
            }

            addr_t got_addr = INVALID_ADDR;
            if (cs_count == 1 &&
                z_capstone_is_pc_related_ujmp(cs_inst, &got_addr)) {
                assert(got_addr != INVALID_ADDR);

                const LFuncInfo *got_info =
                    (const LFuncInfo *)g_hash_table_lookup(
                        e->got, GSIZE_TO_POINTER(got_addr));

                if (got_info) {
                    func_info = got_info;
                    z_info("function PLT: %s @ %#lx", func_info->name,
                           plt_addr + off);
                }
            }

            g_hash_table_insert(e->plt, GSIZE_TO_POINTER(plt_addr + off),
                                (gpointer)func_info);
            off += plt_entsize;
        }

        z_free(ptr);
    }

    /*
     * step (4). free allocated memory
     */
    z_free((void *)dynstr);
    z_free((void *)rela_plt);
    z_free((void *)rela_dyn);
    z_free((void *)dynsym);

    /*
     * step (5). change the value of DT_NULL to indicate this program is patched
     * by StochFuzz
     */
    Elf64_Dyn *dyn_ = __elf_find_dyn_by_tag(e, DT_NULL);
    if (!dyn_) {
        EXITME("DT_NULL not found");
    }
    dyn_->d_un.d_val = MAGIC_NUMBER;
}

#undef __NUMBER_OF_GOTS
#undef __NUMBER_OF_PLTS

Z_PRIVATE void __elf_parse_shdr(ELF *e) {
    Elf64_Ehdr *ehdr = z_elf_get_ehdr(e);
    size_t size = z_mem_file_ftell(e->stream);

    z_elf_set_shdr_shstrtab(e, NULL);
    z_elf_set_shdr_text(e, NULL);
    z_elf_set_shdr_init(e, NULL);
    z_elf_set_shdr_fini(e, NULL);
    z_elf_set_shdr_init_array(e, NULL);
    z_elf_set_shdr_fini_array(e, NULL);
    z_elf_set_shdr_plt(e, NULL);
    z_elf_set_shdr_plt_got(e, NULL);
    z_elf_set_shdr_plt_sec(e, NULL);

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((uint8_t *)ehdr + ehdr->e_shoff);

    // Get string table first
    uint16_t shstrndx = ehdr->e_shstrndx;
    z_elf_set_shdr_shstrtab(e, shdrs + shstrndx);
    Elf64_Shdr *shdr_shstrtab = z_elf_get_shdr_shstrtab(e);

    assert(shdr_shstrtab != NULL);
    assert(shdr_shstrtab->sh_type == SHT_STRTAB);

    if (shdr_shstrtab->sh_offset >= size ||
        shdr_shstrtab->sh_offset + shdr_shstrtab->sh_size > size) {
        EXITME("string table offset is too large");
    }
    const char *shstrtab =
        __elf_stream_off2ptr(e->stream, shdr_shstrtab->sh_offset);
    size_t shstrtab_sz = shdr_shstrtab->sh_size;

#ifdef DEBUG
    if (true) {
        size_t name_off = shdr_shstrtab->sh_name;
        assert(name_off < shstrtab_sz);
        const char *shstrtab_name = shstrtab + name_off;
        assert(!z_strcmp(shstrtab_name, ".shstrtab"));
    }
#endif

    // Get other section header
    for (unsigned i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *shdr = shdrs + i;
        size_t name_off = shdr->sh_name;
        if (name_off >= shstrtab_sz)
            continue;
        const char *shdr_name = shstrtab + name_off;

        if (!z_strcmp(shdr_name, ".text")) {
            if ((int64_t)shdr->sh_addr < 0 ||
                (int64_t)(shdr->sh_addr + shdr->sh_size) < 0) {
                EXITME("some addresses in .text section are negative");
            }
            z_elf_set_shdr_text(e, shdr);
            LOOKUP_TABLE_INIT_CELL_NUM(shdr->sh_size);
        } else if (!z_strcmp(shdr_name, ".init")) {
            z_elf_set_shdr_init(e, shdr);
        } else if (!z_strcmp(shdr_name, ".fini")) {
            z_elf_set_shdr_fini(e, shdr);
        } else if (!z_strcmp(shdr_name, ".init_array")) {
            z_elf_set_shdr_init_array(e, shdr);
        } else if (!z_strcmp(shdr_name, ".fini_array")) {
            z_elf_set_shdr_fini_array(e, shdr);
        } else if (!z_strcmp(shdr_name, ".plt")) {
            z_elf_set_shdr_plt(e, shdr);
        } else if (!z_strcmp(shdr_name, ".plt.got")) {
            z_elf_set_shdr_plt_got(e, shdr);
        } else if (!z_strcmp(shdr_name, ".plt.sec")) {
            z_elf_set_shdr_plt_sec(e, shdr);
        }
    }

    if (!z_elf_get_shdr_text(e)) {
        // TODO: .text is not always necessary.
        EXITME("cannot find .text section");
    }
    z_info("find .text section @ %#lx", z_elf_get_shdr_text(e)->sh_addr);

    // in some cases, init_/fini_array does not exist
    // assert(z_elf_get_shdr_init(e) != NULL);
    // assert(z_elf_get_shdr_fini(e) != NULL);
    // assert(z_elf_get_shdr_init_array(e) != NULL);
    // assert(z_elf_get_shdr_fini_array(e) != NULL);

    // static-linked binary may not have PLT
    // assert(z_elf_get_shdr_plt(e) != NULL);
    // assert(z_elf_get_shdr_plt_got(e) != NULL);

    if (z_elf_get_shdr_init(e)) {
        z_info("find .init section @ %#lx", z_elf_get_shdr_init(e)->sh_addr);
    }
    if (z_elf_get_shdr_fini(e)) {
        z_info("find .fini section @ %#lx", z_elf_get_shdr_fini(e)->sh_addr);
    }

    if (z_elf_get_shdr_init_array(e)) {
        z_info("find .init_array section @ %#lx",
               z_elf_get_shdr_init_array(e)->sh_addr);
    }
    if (z_elf_get_shdr_fini_array(e)) {
        z_info("find .fini_array section @ %#lx",
               z_elf_get_shdr_fini_array(e)->sh_addr);
    }

    if (z_elf_get_shdr_plt(e)) {
        z_info("find .plt section @ %#lx", z_elf_get_shdr_plt(e)->sh_addr);
    } else {
        z_info(".plt section not found");
    }

    if (z_elf_get_shdr_plt_got(e)) {
        z_info("find .plt.got section @ %#lx",
               z_elf_get_shdr_plt_got(e)->sh_addr);
    } else {
        z_info(".plt.got section not found");
    }

    if (z_elf_get_shdr_plt_sec(e)) {
        z_info("find .plt.sec section @ %#lx",
               z_elf_get_shdr_plt_sec(e)->sh_addr);
    } else {
        z_info(".plt.sec section not found");
    }
}

Z_PRIVATE void __elf_parse_phdr(ELF *e) {
    uint8_t *base = z_mem_file_get_raw_buf(e->stream);
    size_t size = z_mem_file_ftell(e->stream);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;

    // Entry point
    e->ori_entry = ehdr->e_entry;
    z_info("find entrypoint: %#lx", e->ori_entry);

    // Whether the ELF is compiled as PIE
    e->is_pie = ehdr->e_type == ET_EXEC ? false : true;
    if (e->is_pie) {
        z_info("try to handle PIE executable");
    } else {
        z_info("try to handle non-PIE executable");
    }

    z_elf_set_ehdr(e, ehdr);
    z_elf_set_phdr_note(e, NULL);
    z_elf_set_phdr_dynamic(e, NULL);

    // Locate phdr_note and phdr_dynamic
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(base + ehdr->e_phoff);
    for (unsigned i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = phdrs + i;
        if (phdr->p_type == PT_DYNAMIC)
            z_elf_set_phdr_dynamic(e, phdr);
        if (phdr->p_type == PT_NOTE)
            z_elf_set_phdr_note(e, phdr);
    }

    Elf64_Phdr *phdr_note = z_elf_get_phdr_note(e);
    if (phdr_note == NULL) {
        // TODO: currently we use a very naive but effective method to inject a
        // new segment, by modifying the PT_NOTE. However, it does not always
        // work. A better but more complex solution is to move the segment table
        // to a new place which makes it easior to add segments.
        EXITME("failed to parse ELF file [missing PT_NOTE segment]");
    }

    Elf64_Phdr *phdr_dynamic = z_elf_get_phdr_dynamic(e);
    if (phdr_dynamic != NULL &&
        phdr_dynamic->p_offset + phdr_dynamic->p_memsz > size) {
        EXITME("failed to parse ELF file [invalid dynamic section]");
    }

    z_trace("successfully parse ELF header");
}

Z_PRIVATE void __elf_validate_header(_MEM_FILE *stream) {
    size_t size = z_mem_file_ftell(stream);
    if (size < sizeof(Elf64_Ehdr)) {
        EXITME("failed to parse ELF EHDR [file is too small]");
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)z_mem_file_get_raw_buf(stream);

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        EXITME("failed to parse ELF EHDR [invalid magic number (%c%c%c%c)]",
               ehdr->e_ident[EI_MAG0], ehdr->e_ident[EI_MAG1],
               ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3]);
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        EXITME("failed to parse ELF EHDR [file is not 64bit]");
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        EXITME("failed to parse ELF EHDR [file is not little endian]");
    }

    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
        EXITME("failed to parse ELF EHDR [invalid version]");
    }

    if (ehdr->e_machine != EM_X86_64) {
        EXITME("failed to parse ELF EHDR [file is not x86_64]");
    }

    if (ehdr->e_phoff < sizeof(Elf64_Ehdr)) {
        EXITME("failed to parse ELF EHDR [invalid program header offset (%u)]",
               ehdr->e_phoff);
    }

    if (ehdr->e_phnum > PN_XNUM) {
        EXITME("failed to parse ELF EHDR [too many program headers (%d)]",
               ehdr->e_phnum);
    }

    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size) {
        EXITME("failed to parse ELF EHDR [invalid program headers]");
    }

    if (ehdr->e_shoff < sizeof(Elf64_Ehdr)) {
        EXITME("failed to parse ELF SHDR [invalid section header offset (%u)]",
               ehdr->e_shoff);
    }

    if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > size) {
        EXITME("failed to parse ELF EHDR [invalid section headers]");
    }

    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        EXITME("failed to parse ELF EHDR [file is not executable]");
    }
}

Z_PRIVATE void __elf_set_virtual_mapping(ELF *e, const char *filename) {
    // Get .text information
    Elf64_Shdr *text = z_elf_get_shdr_text(e);
    addr_t text_addr = text->sh_addr;
    size_t text_size = text->sh_size;

    size_t size = z_mem_file_ftell(e->stream);

    e->vmapping = z_splay_create(NULL);  // Do not support merging
    e->mmapped_pages = z_splay_create(&z_direct_merge);
    e->max_addr = 0;

    // Get segments table
    Elf64_Ehdr *ehdr = z_elf_get_ehdr(e);
    Elf64_Phdr *phdrs =
        (Elf64_Phdr *)__elf_stream_off2ptr(e->stream, ehdr->e_phoff);

    FChunk *fc = NULL;
    Snode *node = NULL;
    for (unsigned i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = phdrs + i;

        // We only consider PT_LOAD segment
        if (phdr->p_type != PT_LOAD)
            continue;

        // Get segment information
        //      1. vaddr
        addr_t vaddr = (addr_t)phdr->p_vaddr;
        //      2. offset
        size_t offset = (size_t)phdr->p_offset;
        //      3. filesz
        size_t filesz = (size_t)phdr->p_filesz;
        //      4. memsz
        size_t memsz = (size_t)phdr->p_memsz;
        assert(memsz >= filesz);
        if (offset + filesz > size) {
            EXITME("invalid segment [%ld, %ld]: larger than ELF size(%ld)",
                   offset, offset + filesz - 1, size);
        }

        // Update max virtual address
        if (e->max_addr < vaddr + memsz) {
            e->max_addr = vaddr + memsz;
        }

        if (text_addr >= vaddr && text_addr < vaddr + memsz) {
            if (!(phdr->p_flags & PF_X)) {
                EXITME(".text section is not executable");
            }

            // XXX: note that the shared .text section will be mapped in
            // page-level

            // step (0). make sure all .text are contained by file
            if (text_addr + text_size > vaddr + filesz) {
                EXITME("some data in .text section is not contained by file");
            }

            // step (1). first check whether we need to map the head part
            addr_t aligned_addr = BITS_ALIGN_FLOOR(text_addr, PAGE_SIZE_POW2);
            if (vaddr < aligned_addr) {
                assert(aligned_addr - vaddr <= filesz);
                fc = z_fchunk_create(e->stream, offset, aligned_addr - vaddr,
                                     false);
                node = z_snode_create(vaddr, aligned_addr - vaddr, (void *)fc,
                                      (void (*)(void *))(&z_fchunk_destroy));
                if (!z_splay_insert(e->vmapping, node)) {
                    EXITME("overlapped virtual addresses");
                }
            }

            // step (2). then check whether we need to map the tail part
            aligned_addr =
                BITS_ALIGN_CELL(text_addr + text_size, PAGE_SIZE_POW2);

            // update max_addr if needed
            if (e->max_addr < aligned_addr) {
                e->max_addr = aligned_addr;
            }

            if (aligned_addr < vaddr + memsz) {
                assert(aligned_addr > vaddr);

                // check which kind of node we need to insert
                if (aligned_addr - vaddr >= filesz) {
                    // it means the tail part is purely alloced
                    node = z_snode_create(
                        aligned_addr, vaddr + memsz - aligned_addr, NULL, NULL);
                } else {
                    // it means the tail part contains some data bytes
                    fc = z_fchunk_create(e->stream,
                                         offset + aligned_addr - vaddr,
                                         vaddr + filesz - aligned_addr, false);
                    node = z_snode_create(
                        aligned_addr, vaddr + memsz - aligned_addr, (void *)fc,
                        (void (*)(void *))(&z_fchunk_destroy));
                }

                if (!z_splay_insert(e->vmapping, node)) {
                    EXITME("overlapped virtual addresses");
                }
            }

            // step (3). setup shared .text section
            __elf_setup_shared_text(e, filename);
        } else {
            fc = z_fchunk_create(e->stream, offset, filesz, false);
            node = z_snode_create(vaddr, memsz, (void *)fc,
                                  (void (*)(void *))(&z_fchunk_destroy));
            if (!z_splay_insert(e->vmapping, node)) {
                EXITME("overlapeed virtual addresses");
            }
        }

        // For non-exec segment, we need to insert virtual uTP.
        // XXX: I totally forget what the following code does...
        // XXX: the segment containing .text does not go into this branch.
        if (!(phdr->p_flags & PF_X)) {
            addr_t gap_1_addr = BITS_ALIGN_FLOOR(vaddr, PAGE_SIZE_POW2);
            size_t gap_1_size = vaddr - gap_1_addr;
            if (gap_1_size > 0) {
                node = z_snode_create(gap_1_addr, gap_1_size, NULL, NULL);
                if (!z_splay_insert(e->vmapping, node)) {
                    EXITME("overlapped virtual uTPs");
                }
            }

            addr_t gap_2_addr = vaddr + memsz;
            size_t gap_2_size =
                PAGE_SIZE - (gap_2_addr & ((1 << PAGE_SIZE_POW2) - 1));
            if (gap_2_size > 0) {
                node = z_snode_create(gap_2_addr, gap_2_size, NULL, NULL);
                if (!z_splay_insert(e->vmapping, node)) {
                    EXITME("overlapped virtual uTPs");
                }
            }
        }

        // Update mmapped pages
        // XXX: the .text insertion does not impact the mapped pages
        assert(memsz != 0);
        addr_t mmap_addr = BITS_ALIGN_FLOOR(vaddr, PAGE_SIZE_POW2);
        size_t mmap_size = vaddr + memsz - mmap_addr;
        mmap_size = BITS_ALIGN_CELL(mmap_size, PAGE_SIZE_POW2);
        node = z_snode_create(mmap_addr, mmap_size, NULL, NULL);
        if (!z_splay_insert(e->mmapped_pages, node)) {
            EXITME("overlapped mapped addresses");
        }

        z_trace("find segment [%#lx, %#lx] @ %#lx", vaddr, vaddr + filesz - 1,
                offset);
    }

    // XXX: note that max_addr is only used to find the max address of those
    // segments in the orignal ELF, which excludes those pages mapped by us
    if (!e->max_addr) {
        EXITME("no loaded segment found");
    }
    z_trace("max address for original ELF: %#lx", e->max_addr - 1);

    // Add constant address into vmmaping
    if (!e->is_pie) {
        // For PIE binary, it is almost impossible to touch the constant
        // address, so we ignore them
        if (!z_splay_insert(
                e->vmapping,
                z_snode_create(RW_PAGE_ADDR, RW_PAGE_USED_SIZE, NULL, NULL))) {
            EXITME("constant address is occupied");
        }
        if (!z_splay_insert(
                e->mmapped_pages,
                z_snode_create(RW_PAGE_ADDR, RW_PAGE_SIZE, NULL, NULL))) {
            EXITME("constant address is occupied");
        }
        if (!z_splay_insert(
                e->vmapping,
                z_snode_create(AFL_MAP_ADDR, AFL_MAP_SIZE, NULL, NULL))) {
            EXITME("constant address is occupied");
        }
        if (!z_splay_insert(
                e->mmapped_pages,
                z_snode_create(AFL_MAP_ADDR, AFL_MAP_SIZE, NULL, NULL))) {
            EXITME("constant address is occupied");
        }
        if (!z_splay_insert(
                e->vmapping,
                z_snode_create(CRS_MAP_ADDR, CRS_MAP_SIZE, NULL, NULL))) {
            EXITME("constant address is occupied");
        }
        if (!z_splay_insert(
                e->mmapped_pages,
                z_snode_create(CRS_MAP_ADDR, CRS_MAP_SIZE, NULL, NULL))) {
            EXITME("constant address is occupied");
        }
    }

    // We additionally need to add those mapped pages whose address is based on
    // ASLR/PIE
    {
        if (!z_splay_insert(e->vmapping,
                            z_snode_create(SIGNAL_STACK_ADDR, SIGNAL_STACK_SIZE,
                                           NULL, NULL))) {
            EXITME("signal stack is occupied");
        }
        if (!z_splay_insert(e->mmapped_pages,
                            z_snode_create(SIGNAL_STACK_ADDR, SIGNAL_STACK_SIZE,
                                           NULL, NULL))) {
            EXITME("signal stack is occupied");
        }
    }
}

Z_PRIVATE void __elf_parse_main(ELF *e) {
    assert(e != NULL);

    if (!e->detect_main) {
        z_info(
            "we skip the detection of main function because we are going to "
            "instrument the fork server before the entrypoint");
        return;
    }

    // Try to identify the address of main function.

    // XXX: like AFL, we try to instrument the binary before main(). But we may
    // not always successfully locate the main() function.
    //  * https://github.com/google/AFL/tree/master/llvm_mode
    //  * https://github.com/talos-vulndev/afl-dyninst

    Rptr *cur_ptr = z_elf_vaddr2ptr(e, e->ori_entry);
    addr_t cur_addr = e->ori_entry;

    while (true) {
        if (z_rptr_is_null(cur_ptr)) {
            EXITME("invalid entrypoint or run out of segment");
        }

        CS_DISASM(cur_ptr, cur_addr, 1);

        // If searching all instructions in _start
        if ((cs_count == 0) || (cs_inst[0].id == X86_INS_CALL)) {
            EXITME(
                "no main function found, please use -e option to install the "
                "fork server at entrypoint");
        }
        z_trace("finding main: %#lx:\t%s %s", cs_inst[0].address,
                cs_inst[0].mnemonic, cs_inst[0].op_str);

        // Check load_main
        if (e->is_pie) {
            // For PIE binary, we check: lea rdi, [rip + xxx]
            if (cs_inst[0].id != X86_INS_LEA)
                goto NEXT;
            cs_x86_op *ops = cs_inst[0].detail->x86.operands;
            if (ops[0].type != X86_OP_REG)
                goto NEXT;
            if ((ops[1].type != X86_OP_MEM) ||
                (ops[1].mem.base != X86_REG_RIP) ||
                (ops[1].mem.index != X86_REG_INVALID))
                goto NEXT;
            switch (ops[0].reg) {
                case X86_REG_RCX:
                    e->init = ops[1].mem.disp + cs_inst[0].size + cur_addr;
                    e->load_init = cur_addr;
                    goto NEXT;
                case X86_REG_R8:
                    e->fini = ops[1].mem.disp + cs_inst[0].size + cur_addr;
                    e->load_fini = cur_addr;
                    goto NEXT;
                case X86_REG_RDI:
                    e->main = ops[1].mem.disp + cs_inst[0].size + cur_addr;
                    e->load_main = cur_addr;
                    goto LOOP_DONE;
                default:
                    goto NEXT;
            }
        } else {
            // For non-PIE binary, we check: mov rdi, xxx
            if (cs_inst[0].id != X86_INS_MOV)
                goto NEXT;
            cs_x86_op *ops = cs_inst[0].detail->x86.operands;
            if (ops[0].type != X86_OP_REG)
                goto NEXT;
            if (ops[1].type != X86_OP_IMM)
                goto NEXT;
            switch (ops[0].reg) {
                case X86_REG_R8:
                    e->fini = ops[1].imm;
                    e->load_fini = cur_addr;
                    goto NEXT;
                case X86_REG_RCX:
                    e->init = ops[1].imm;
                    e->load_init = cur_addr;
                    goto NEXT;
                case X86_REG_RDI:
                    e->main = ops[1].imm;
                    e->load_main = cur_addr;
                    goto LOOP_DONE;
                default:
                    goto NEXT;
            }
        }

    NEXT:
        cur_addr += cs_inst[0].size;
        z_rptr_inc(cur_ptr, uint8_t, cs_inst[0].size);
    }
LOOP_DONE:

    z_rptr_destroy(cur_ptr);
    z_info("find main function: %#lx", e->main);
    z_info("find init function: %#lx", e->init);
    z_info("find fini function: %#lx", e->fini);
}

Z_API ELF *z_elf_open(const char *ori_filename, bool detect_main) {
    ELF *e = STRUCT_ALLOC(ELF);

    e->detect_main = detect_main;

    memset(e->tmpnam, 0, TMPNAME_LEN);
    z_snprintf(e->tmpnam, TMPNAME_LEN, TMPNAME_FMT, z_rand());
    z_trace("use temp file: %s", e->tmpnam);

    _MEM_FILE *stream = __elf_open_file(e, ori_filename);

    // Step (0). Validate header
    __elf_validate_header(stream);

    // Step (1). Alloc ELF struct
    e->stream = stream;

    // Step (2). Parse program header
    __elf_parse_phdr(e);

    // Step (3). Parse section header
    __elf_parse_shdr(e);

    // Step (4). Do virtual mapping
    __elf_set_virtual_mapping(e, ori_filename);

    // Step (5). Extend loader/Trampolines zones onto file
    __elf_extend_zones(e);

    // Step (6). Setup lookup table
    __elf_setup_lookup_table(e, ori_filename);

    // Step (7). Setup trampolines (shadow code)
    __elf_setup_trampolines(e, ori_filename);

    // Step (8). Setup pipe file
    __elf_setup_pipe(e, ori_filename);

    // Step (9). Setup retaddr mapping
    __elf_setup_retaddr_mapping(e, ori_filename);

    // Step (10). Detect and parse main function
    __elf_parse_main(e);

    // Step (11). Rewrite PT_NOTE meta info
    __elf_rewrite_pt_note(e);

    // Step (12). Set RELRO for elf (REMOVE to allow gdb load library symbols)
    // XXX: AFL already set LD_BIND_NOW to stops the linker from doing extra
    // work post-fork()
    // __elf_set_relro(e);

    // step (13). Get relocation information
    __elf_parse_relocation(e);

    // step (14). link patched file
    char *patched_filename = z_strcat(ori_filename, PATCHED_FILE_SUFFIX);
    z_elf_save(e, patched_filename);
    z_free(patched_filename);

    // step (15). set state
    e->state = ELFSTATE_CONNECTED;

    return e;
}

Z_API Rptr *z_elf_vaddr2ptr(ELF *e, addr_t vaddr) {
    assert(e != NULL);

    // Get corresponding segment
    Snode *segment = __elf_find_segment_by_vaddr(e, vaddr);
    if (segment == NULL) {
        return NULL;
    }

    // Create Rptr
    FChunk *fc = (FChunk *)z_snode_get_data(segment);
    if (z_strcmp(STRUCT_TYPE(fc), "FChunk")) {
        z_trace("get address into dynamically allocated space");
        return NULL;
    }
    size_t off1 = vaddr - z_snode_get_lower_bound(segment);
    size_t off2 = z_fchunk_get_offset(fc);
    if (off1 >= z_fchunk_get_size(fc)) {
        z_trace("trying to read on zero-padding region");
        return NULL;
    }

    size_t size = z_snode_get_upper_bound(segment) - vaddr + 1;

    _MEM_FILE *stream = z_fchunk_get_stream(fc);

    return z_rptr_create(__elf_stream_off2ptr(stream, off1 + off2), size);
}

Z_API void z_elf_destroy(ELF *e) {
    z_splay_destroy(e->vmapping);
    z_splay_destroy(e->mmapped_pages);

    g_hash_table_destroy(e->got);
    g_hash_table_destroy(e->plt);

    z_free(e->retaddr_mapping_name);
    z_free(e->lookup_tabname);
    z_free(e->trampolines_name);
    z_free(e->shared_text_name);
    z_free(e->pipe_filename);

    z_mem_file_fclose(e->retaddr_mapping_stream);
    z_mem_file_fclose(e->lookup_table_stream);
    z_mem_file_fclose(e->trampolines_stream);
    z_mem_file_fclose(e->shared_text_stream);
    z_mem_file_fclose(e->stream);

    if (remove(e->tmpnam)) {
        EXITME("failed on remove %s: %s", e->tmpnam, strerror(errno));
    }

    z_free(e);
}

Z_API void z_elf_fsync(ELF *e) {
    assert(e != NULL);

    z_mem_file_fsync(e->lookup_table_stream);
    z_mem_file_fsync(e->trampolines_stream);
    z_mem_file_fsync(e->shared_text_stream);
    z_mem_file_fsync(e->stream);
}

Z_API void z_elf_save(ELF *e, const char *pathname) {
    // curently no need to update PT_NOTE, because trampolines are putting in
    // an individual file.

    // fsync
    z_elf_fsync(e);

    // check whether pathname exists. if so, remove it.
    if (!z_access(pathname, F_OK)) {
        if (remove(pathname)) {
            EXITME("failed on remove: %s (error: %s)", pathname,
                   strerror(errno));
        }
    }

    // create a symbolic link to e->tmpnam
    z_info("save patched file into %s", pathname);
    if (link(e->tmpnam, pathname)) {
        EXITME("failed on link: %s", strerror(errno));
    }
}

Z_API void z_elf_create_snapshot(ELF *e, const char *pathname) {
    z_elf_fsync(e);
    z_mem_file_save_as(e->stream, pathname);
}

Z_API size_t z_elf_read_all(ELF *e, addr_t addr, size_t n, void *buf) {
    assert(e != NULL);

    size_t cur_n = n;

    while (cur_n > 0) {
        size_t k = z_elf_read(e, addr, cur_n, buf);

        if (!k) {
            return n - cur_n;
        }

        cur_n -= k;
        buf += k;
        addr += k;
    }

    return n;
}

Z_API size_t z_elf_read(ELF *e, addr_t addr, size_t n, void *buf) {
    assert(e != NULL);

    Rptr *rptr = z_elf_vaddr2ptr(e, addr);
    if (z_rptr_is_null(rptr)) {
        z_error("invalid address: %#lx", addr);
        return 0;
    }

    size_t n_ = n < z_rptr_get_size(rptr) ? n : z_rptr_get_size(rptr);

    z_rptr_memcpy(buf, rptr, n_);
    z_rptr_destroy(rptr);
    return n_;
}

Z_API size_t z_elf_write(ELF *e, addr_t addr, size_t n, const void *buf) {
    assert(e != NULL);

    Snode *segment = __elf_find_segment_by_vaddr(e, addr);
    if (!segment) {
        EXITME("invalid address: %#lx", addr);
    }
    FChunk *fc = (FChunk *)z_snode_get_data(segment);

    if (z_fchunk_get_extendable(fc)) {
        // write on an extendable space
        addr_t segment_base_addr = z_snode_get_lower_bound(segment);
        _MEM_FILE *underlying_stream = z_fchunk_get_stream(fc);

        // XXX: similar to the false branch, the overhead of
        // __elf_stream_vaddr2off is small because the target snode is already
        // at the root of Splay
        size_t tp_off = __elf_stream_vaddr2off(e, segment_base_addr);
        assert(tp_off == 0);

        size_t write_off = addr - segment_base_addr + tp_off;
        if (z_mem_file_get_size(underlying_stream) < write_off) {
            EXITME("write on too bigger address: %#lx", addr);
        }

        // get old size
        size_t old_size = z_mem_file_get_size(underlying_stream) - tp_off;

        // We cannot directly use __elf_stream_vaddr2off here, as addr may not
        // in current virtual memroy.
        z_mem_file_pwrite(underlying_stream, buf, n, write_off);

        if (write_off + n == z_mem_file_get_size(underlying_stream)) {
            // XXX: if the underlying stream is fully written, we need to extend
            // it. For example, if the original address range is [0x1000,
            // 0x1100) and we wrote all the 0x100 bytes, next time we want to
            // write on address 0x1100. It sould be valid because the underlying
            // stream is extendable.
            z_mem_file_pwrite(underlying_stream, "", 1, write_off + n);
            assert(write_off + n < z_mem_file_get_size(underlying_stream));
        }

        // calculate new node
        size_t new_size = z_mem_file_get_size(underlying_stream) - tp_off;

        // update if new_size is not equal to old_size
        if (new_size != old_size) {
            assert(new_size > old_size);

            // delete previous node
            Snode *node = z_splay_delete(e->vmapping, segment_base_addr);
            assert(node != NULL);

            addr_t vaddr = z_snode_get_lower_bound(node);
            z_snode_set_len(node, new_size);
            z_fchunk_set_size((FChunk *)z_snode_get_data(node), new_size);

            // update virtual mapping
            if (!z_splay_insert(e->vmapping, node)) {
                EXITME("extend writing [new_size: %#lx, old_size: %#lx]",
                       new_size, old_size);
            }

            // update mapped pages
            node = z_snode_create(vaddr + old_size, new_size - old_size, NULL,
                                  NULL);
            if (!z_splay_insert(e->mmapped_pages, node)) {
                EXITME("extend writing");
            }

            // update state
            z_elf_set_state(e, ELFSTATE_SHADOW_EXTENDED);
        }
    } else {
        // other range

        // XXX: the overhead of re-searching splay is small because the target
        // snode is already at the root, so we re-invoke z_elf_vaddr2pter for
        // the easy understanding of the code
        Rptr *rptr = z_elf_vaddr2ptr(e, addr);
        z_rptr_memcpy(rptr, buf, n);
        z_rptr_destroy(rptr);
    }

    return n;
}

Z_API bool z_elf_check_region_free(ELF *e, Snode *region) {
    assert(e != NULL && region != NULL);
    return !z_splay_interval_overlap(e->vmapping, region);
}

Z_API bool z_elf_insert_utp(ELF *e, Snode *utp, addr_t *mmap_addr,
                            size_t *mmap_size) {
    assert(z_snode_get_data(utp) == NULL);
    assert(z_snode_get_len(utp) <= PAGE_SIZE);

    // insert utp first
    if (!z_splay_insert(e->vmapping, utp))
        return false;

    // calculate mmap page
    addr_t utp_mmap_lo =
        BITS_ALIGN_FLOOR(z_snode_get_lower_bound(utp), PAGE_SIZE_POW2);
    addr_t utp_mmap_up =
        BITS_ALIGN_FLOOR(z_snode_get_upper_bound(utp), PAGE_SIZE_POW2);

    // init values
    *mmap_addr = INVALID_ADDR;
    *mmap_size = 0;

    // check
    for (addr_t addr = utp_mmap_lo; addr <= utp_mmap_up; addr += PAGE_SIZE) {
        Snode *node = z_snode_create(addr, PAGE_SIZE, NULL, NULL);
        if (z_splay_insert(e->mmapped_pages, node)) {
            *mmap_addr = (*mmap_addr < addr ? *mmap_addr : addr);
            *mmap_size += PAGE_SIZE;
        } else {
            z_snode_destroy(node);
        }
    }

    if (*mmap_addr == INVALID_ADDR)
        *mmap_addr = 0;

    return true;
}

Z_API const LFuncInfo *z_elf_get_plt_info(ELF *e, addr_t addr) {
    return (const LFuncInfo *)g_hash_table_lookup(e->plt,
                                                  GSIZE_TO_POINTER(addr));
}

Z_API const LFuncInfo *z_elf_get_got_info(ELF *e, addr_t addr) {
    return (const LFuncInfo *)g_hash_table_lookup(e->got,
                                                  GSIZE_TO_POINTER(addr));
}

Z_API bool z_elf_check_state(ELF *e, ELFState state) {
    if (state & ELFSTATE_DISABLE) {
        EXITME(
            "check state function does not support disabling any state (state: "
            "%#x)",
            state);
    }

    return (e->state & state);
}

Z_API bool z_elf_is_statically_linked(ELF *e) {
    // XXX: linux kernel uses .INTERP segment to determine whether a dynmaic
    // linker is required, but here we use .DYNAMIC segment which is good enough
    // (like what readelf does)
    return !z_elf_get_phdr_dynamic(e);
}
