#include "elf_.h"
#include "buffer.h"
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

/*
 * Define special getter and setter for ELF
 */
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
});

DEFINE_GETTER(FChunk, fchunk, _MEM_FILE *, stream);
DEFINE_GETTER(FChunk, fchunk, size_t, offset);
DEFINE_GETTER(FChunk, fchunk, size_t, size);
DEFINE_SETTER(FChunk, fchunk, size_t, size);

Z_PRIVATE FChunk *z_fchunk_create(_MEM_FILE *stream, size_t offset,
                                  size_t size) {
    FChunk *fc = STRUCT_ALLOC(FChunk);
    fc->stream = stream;
    fc->offset = offset;
    fc->size = size;
    return fc;
}

Z_PRIVATE void z_fchunk_destroy(FChunk *fc) { z_free(fc); }

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
 * Get PLT information
 */
Z_PRIVATE void __elf_parse_plt(ELF *e);

/*
 * Parse other information of ELF (entrypoint, etc.)
 */
Z_PRIVATE void __elf_parse_other_info(ELF *e);

/*
 * Set relocation-preset for given ELF
 */
Z_PRIVATE void __elf_set_relro(ELF *e);

/*
 * Set virtual mapping for given ELF
 */
Z_PRIVATE void __elf_set_virtual_mapping(ELF *e);

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
 * Setup trampolines (shadow code)
 */
Z_PRIVATE void __elf_setup_trampolines(ELF *e, const char *filename);

/*
 * Setup pipeline file
 */
Z_PRIVATE void __elf_setup_pipe(ELF *e, const char *filename);

// TODO: Raw pointer might lead to overflow, but we need effecience.
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
DEFINE_GETTER(ELF, elf, addr_t, loader_addr);
DEFINE_GETTER(ELF, elf, addr_t, trampolines_addr);
DEFINE_GETTER(ELF, elf, addr_t, lookup_table_addr);
DEFINE_GETTER(ELF, elf, bool, is_pie);
DEFINE_GETTER(ELF, elf, addr_t, ori_entry);
DEFINE_GETTER(ELF, elf, addr_t, main);
DEFINE_GETTER(ELF, elf, addr_t, init);
DEFINE_GETTER(ELF, elf, addr_t, fini);
DEFINE_GETTER(ELF, elf, addr_t, load_main);
DEFINE_GETTER(ELF, elf, addr_t, load_init);
DEFINE_GETTER(ELF, elf, addr_t, load_fini);
DEFINE_GETTER(ELF, elf, const char *, lookup_tabname);
DEFINE_GETTER(ELF, elf, const char *, trampolines_name);
DEFINE_GETTER(ELF, elf, const char *, pipe_filename);
DEFINE_GETTER(ELF, elf, size_t, plt_n);

Z_PRIVATE size_t __elf_stream_vaddr2off(ELF *e, addr_t addr) {
    // Get corresponding segment
    Snode *segment = z_splay_search(e->vmapping, addr);
    if (segment == NULL) {
        EXITME("invalid virtual address [%#lx]", addr);
    }
    assert(addr >= z_snode_get_lower_bound(segment));
    assert(addr <= z_snode_get_upper_bound(segment));

    // Create Rptr
    FChunk *fc = (FChunk *)z_snode_get_data(segment);
    if (fc == NULL || z_strcmp(STRUCT_TYPE(fc), "FChunk")) {
        EXITME("get address into trampoline");
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
    assert(e != NULL);

    Elf64_Phdr *phdr = z_elf_get_phdr_note(e);
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_X | PF_R;
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

    /*
     * TODO: PIE FIX! as lookup table should locate at a fixed address anyway,
     * it does not need to insert into virtual mapping for PIE binary (PIE
     * binary's memory space is random)
     */

    // step (5). insert into virtual mapping
    Snode *node = NULL;
    FChunk *fc = z_fchunk_create(e->lookup_table_stream, 0, LOOKUP_TABLE_SIZE);
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
        z_fchunk_create(e->trampolines_stream, 0, TRAMPOLINES_INIT_SIZE);
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
    addr_t vaddr = ((e->max_addr >> PAGE_SIZE_POW2) + 1) << PAGE_SIZE_POW2;
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

        FChunk *fc = z_fchunk_create(e->stream, offset, zone_size - zone_guard);
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
                    "we "
                    "failed to patch it");
            }
        }
    } else {
        z_info("statically linked binary");
    }
}

// XXX: currently we only locate the entrypoints of each PLT entry. However, it
// will be very helpful if we can associate library function symbols with these
// entries.
Z_PRIVATE void __elf_parse_plt(ELF *e) {
    e->plt = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    e->plt_n = 0;

    Elf64_Shdr *plts[2] = {z_elf_get_shdr_plt(e), z_elf_get_shdr_plt_got(e)};
    for (size_t i = 0; i < 2; i++) {
        Elf64_Shdr *plt = plts[i];
        if (!plt) {
            // no PLT information
            continue;
        }

        addr_t plt_addr = plt->sh_addr;
        size_t plt_size = plt->sh_size;
        size_t plt_entsize = plt->sh_entsize;
        if (!plt_addr || !plt_size || !plt_entsize) {
            // invalid information
            continue;
        }

        z_info(
            "find PLT from %#lx, with %#lx bytes size and %#lx bytes entry "
            "size",
            plt_addr, plt_size, plt_entsize);

        for (size_t off = 0; off < plt_size; off += plt_entsize) {
            // XXX: note that the first entry of PLT is not a library call
            // target, but here we regard it as normal library call for easy
            // coding.
            g_hash_table_insert(e->plt, GSIZE_TO_POINTER(plt_addr + off),
                                GSIZE_TO_POINTER(1));
            e->plt_n += 1;
        }
    }
}

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
        }
    }

    assert(z_elf_get_shdr_text(e) != NULL);
    assert(z_elf_get_shdr_init(e) != NULL);
    assert(z_elf_get_shdr_fini(e) != NULL);

    // in some cases, init_/fini_array does not exist
    // assert(z_elf_get_shdr_init_array(e) != NULL);
    // assert(z_elf_get_shdr_fini_array(e) != NULL);

    // static-linked binary may not have PLT
    // assert(z_elf_get_shdr_plt(e) != NULL);
    // assert(z_elf_get_shdr_plt_got(e) != NULL);

    z_info("find .text section @ %#lx", z_elf_get_shdr_text(e)->sh_addr);
    z_info("find .init section @ %#lx", z_elf_get_shdr_init(e)->sh_addr);
    z_info("find .fini section @ %#lx", z_elf_get_shdr_fini(e)->sh_addr);

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

Z_PRIVATE void __elf_set_virtual_mapping(ELF *e) {
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
        if (e->max_addr < vaddr + memsz - 1) {
            e->max_addr = vaddr + memsz - 1;
        }

        // TODO: to support shared .text, add code here to split the segments
        // containing .text section.
        // Note that the .text section should be page-aligned

        fc = z_fchunk_create(e->stream, offset, filesz);
        node = z_snode_create(vaddr, memsz, (void *)fc,
                              (void (*)(void *))(&z_fchunk_destroy));
        if (!z_splay_insert(e->vmapping, node)) {
            EXITME("update virtual address");
        }

        // For non-exec segment, we need to insert virtual uTP.
        // XXX: I totally forget what the following code does...
        if (!(phdr->p_flags & PF_X)) {
            addr_t gap_1_addr = (vaddr >> PAGE_SIZE_POW2) << PAGE_SIZE_POW2;
            size_t gap_1_size = vaddr - gap_1_addr;
            if (gap_1_size > 0) {
                node = z_snode_create(gap_1_addr, gap_1_size, NULL, NULL);
                if (!z_splay_insert(e->vmapping, node)) {
                    EXITME("update virtual uTP");
                }
            }

            addr_t gap_2_addr = vaddr + memsz;
            size_t gap_2_size =
                PAGE_SIZE - (gap_2_addr & ((1 << PAGE_SIZE_POW2) - 1));
            if (gap_2_size > 0) {
                node = z_snode_create(gap_2_addr, gap_2_size, NULL, NULL);
                if (!z_splay_insert(e->vmapping, node)) {
                    EXITME("update virtual uTP");
                }
            }
        }

        // Update mmapped pages
        assert(memsz != 0);
        addr_t mmap_addr = ((vaddr >> PAGE_SIZE_POW2) << PAGE_SIZE_POW2);
        size_t mmap_size = vaddr + memsz - mmap_addr;
        mmap_size =
            ((((mmap_size - 1) >> PAGE_SIZE_POW2) + 1) << PAGE_SIZE_POW2);
        node = z_snode_create(mmap_addr, mmap_size, NULL, NULL);
        if (!z_splay_insert(e->mmapped_pages, node)) {
            EXITME("update mapped address");
        }

        z_trace("find segment [%#lx, %#lx] @ %#lx", vaddr, vaddr + filesz - 1,
                offset);
    }

    // Add constant address into vmmaping
    if (!e->is_pie) {
        // For PIE binary, it is almost impossible to touch the constant address
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

    z_trace("max address for original ELF: %#lx", e->max_addr);
}

Z_PRIVATE void __elf_parse_other_info(ELF *e) {
    assert(e != NULL);

    // Try to identify the address of main function.
    // TODO: in the future, if failed, let the user configure the main address.
    Rptr *cur_ptr = z_elf_vaddr2ptr(e, e->ori_entry);
    addr_t cur_addr = e->ori_entry;

    while (true) {
        if (RPTR_IS_NULL(cur_ptr)) {
            EXITME("invalid entrypoint or run out of segment");
        }

        CS_DISASM(cur_ptr, cur_addr, 1);

        // If searching all instructions in _start
        if ((cs_count == 0) || (cs_inst[0].id == X86_INS_CALL)) {
            EXITME("no main function found, please manually configure it");
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
        RPTR_INCR(cur_ptr, uint8_t, cs_inst[0].size);
    }
LOOP_DONE:

    z_rptr_destroy(cur_ptr);
    z_info("find main function: %#lx", e->main);
    z_info("find init function: %#lx", e->init);
    z_info("find fini function: %#lx", e->fini);
}

Z_API ELF *z_elf_open(const char *ori_filename) {
    ELF *e = STRUCT_ALLOC(ELF);

    memset(e->tmpnam, 0, TMPNAME_LEN);
    z_snprintf(e->tmpnam, TMPNAME_LEN, TMPNAME_FMT, z_rand());
    z_info("use temp file: %s", e->tmpnam);

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
    __elf_set_virtual_mapping(e);

    // Step (5). Extend loader/Trampolines zones onto file
    __elf_extend_zones(e);

    // Step (6). Setup lookup table
    __elf_setup_lookup_table(e, ori_filename);

    // Step (7). Setup trampolines (shadow code)
    __elf_setup_trampolines(e, ori_filename);

    // Step (8). Setup pipe file
    __elf_setup_pipe(e, ori_filename);

    // Step (9). Get other information
    __elf_parse_other_info(e);

    // Step (10). Rewrite PT_NOTE meta info
    __elf_rewrite_pt_note(e);

    // Step (11). Set RELRO for elf (REMOVE to allow gdb load library symbols)
    // __elf_set_relro(e);

    // step (12). Get PLT information
    __elf_parse_plt(e);

    // step (13). link patched file
    char *patched_filename = z_strcat(ori_filename, PATCHED_FILE_SUFFIX);
    z_elf_save(e, patched_filename);
    z_free(patched_filename);

    // step (14). set state
    e->state = ELFSTATE_CONNECTED;

    return e;
}

Z_API Rptr *z_elf_vaddr2ptr(ELF *e, addr_t vaddr) {
    assert(e != NULL);

    // Get corresponding segment
    Snode *segment = z_splay_search(e->vmapping, vaddr);
    if (segment == NULL)
        return NULL;
    assert(vaddr >= z_snode_get_lower_bound(segment));
    assert(vaddr <= z_snode_get_upper_bound(segment));

    // Create Rptr
    FChunk *fc = (FChunk *)z_snode_get_data(segment);
    if (z_strcmp(STRUCT_TYPE(fc), "FChunk")) {
        z_trace("get address into trampoline");
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

    g_hash_table_destroy(e->plt);

    z_free(e->lookup_tabname);
    z_free(e->trampolines_name);
    z_free(e->pipe_filename);

    z_mem_file_fclose(e->lookup_table_stream);
    z_mem_file_fclose(e->trampolines_stream);
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
    z_mem_file_fsync(e->stream);
}

Z_API void z_elf_save(ELF *e, const char *pathname) {
    // curently no need to update PT_NOTE, because trampolines are putting in
    // an individual file.

    // fsync
    z_mem_file_fsync(e->stream);

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
    z_mem_file_fsync(e->stream);
    z_mem_file_save_as(e->stream, pathname);
}

Z_API size_t z_elf_read(ELF *e, addr_t addr, size_t n, void *buf) {
    assert(e != NULL);

    Rptr *rptr = z_elf_vaddr2ptr(e, addr);
    if (RPTR_IS_NULL(rptr)) {
        z_error("invalid address: %#lx", addr);
        return 0;
    }

    size_t n_ = n < z_rptr_get_size(rptr) ? n : z_rptr_get_size(rptr);

    RPTR_MEMCPY(buf, rptr, n_);
    z_rptr_destroy(rptr);
    return n_;
}

Z_API size_t z_elf_write(ELF *e, addr_t addr, size_t n, const void *buf) {
    assert(e != NULL);

    if (addr >= e->trampolines_addr && addr < LOOKUP_TABLE_ADDR) {
        // write on trampolines, which is extensive.

        size_t tp_off = __elf_stream_vaddr2off(e, e->trampolines_addr);
        assert(tp_off == 0);

        size_t write_off = addr - e->trampolines_addr + tp_off;
        if (z_mem_file_get_size(e->trampolines_stream) < write_off) {
            EXITME("write on too bigger address: %#lx", addr);
        }

        // get old size
        size_t old_size = z_mem_file_get_size(e->trampolines_stream) - tp_off;

        // We cannot directly use __elf_stream_vaddr2off here, as addr may not
        // in current virtual memroy.
        z_mem_file_pwrite(e->trampolines_stream, buf, n, write_off);

        // calculate new node
        size_t new_size = z_mem_file_get_size(e->trampolines_stream) - tp_off;

        // update if new_size is not equal to old_size
        if (new_size != old_size) {
            assert(new_size > old_size);

            // delete previous node
            Snode *node = z_splay_delete(e->vmapping, e->trampolines_addr);
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

        Rptr *rptr = z_elf_vaddr2ptr(e, addr);
        RPTR_MEMCPY(rptr, buf, n);
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
        ((z_snode_get_lower_bound(utp) >> PAGE_SIZE_POW2) << PAGE_SIZE_POW2);
    addr_t utp_mmap_up =
        ((z_snode_get_upper_bound(utp) >> PAGE_SIZE_POW2) << PAGE_SIZE_POW2);

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

Z_API bool z_elf_check_plt(ELF *e, addr_t addr) {
    return (bool)(!!g_hash_table_lookup(e->plt, GSIZE_TO_POINTER(addr)));
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
