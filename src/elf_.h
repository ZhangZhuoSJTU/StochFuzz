#ifndef __ELF__H
#define __ELF__H

#include "config.h"
#include "interval_splay.h"
#include "library_functions/library_functions.h"
#include "mem_file.h"
#include "restricted_ptr.h"

#include <elf.h>
#include <gmodule.h>

#define TMPNAME_FMT TEMPFILE_NAME_PREFIX "%08x"
#define TMPNAME_LEN 0x20

typedef enum elf_state_t {
    ELFSTATE_NONE = 0x0,             // none
    ELFSTATE_CONNECTED = 0x1,        // disconnect ELF from underlying file
    ELFSTATE_SHADOW_EXTENDED = 0x2,  // shadow file is extended
    ELFSTATE_DISABLE = 0x100,        // flag for disable state
    ELFSTATE_MASK = 0xffff,          // mask
} ELFState;

/*
 * ELF info for binary rewrite (Key Structure)
 */
STRUCT(ELF, {
    char tmpnam[TMPNAME_LEN];
    _MEM_FILE *stream;
    bool detect_main;

    /*
     *         new                     original
     *      entrypoint                   main
     *          |     original          ^
     *          |    entrypoint         |
     *          |         ^             |
     *          V         |             |
     * |-----|.|-----------|-------------|--------------|.|--------|.|-------|
     * | ELF |.| TP loader | fork server | random patch |.| BB Tab |.|  TPs  |
     * |-----|.|-----------|-------------|--------------|.|--------|.|-------|
     *         ^            ^
     *         |            |
     *      PT_NOTE      new main
     *
     * |  ELF  |  LOADER and FORK SEVER                   | BB Tab | |  TPs  |
     *
     *         ^                                          ^          ^
     *    PAGE-ALIGNED                              PAGE-ALIGNED PAGE-ALIGNED
     */

    /*
     * ELF Header
     */
    size_t ehdr_off;  // EHDR (Elf header)

    /*
     * Program Header
     */
    size_t phdr_note_off;     // PHDR PT_NOTE to be used for loader.
    size_t phdr_dynamic_off;  // PHDR PT_DYNAMIC else nullptr.

    /*
     * Section Header
     */
    size_t shdr_shstrtab_off;    // SHDR SHT_STRTAB for strings.
    size_t shdr_text_off;        // SHDR .text section.
    size_t shdr_init_off;        // SHDR .init section.
    size_t shdr_fini_off;        // SHDR .fini section.
    size_t shdr_init_array_off;  // SHDR .init_array
    size_t shdr_fini_array_off;  // SHDR .fini_array
    size_t shdr_plt_off;         // SHDR .plt
    size_t shdr_plt_got_off;     // SHDR .plt.got

    /*
     * Dynamic information
     */
    addr_t fini_array;    // .fini_array
    size_t fini_arraysz;  // size of .fini_array
    addr_t init_array;    // .init_array
    size_t init_arraysz;  // size of .init_array

    /*
     * Virtual Memory
     */
    // vmapping is the actually mappings, while mapped_pages is the thing at
    // paging level. For example, an actual mapping [0x1010, 0x1020] has a
    // mapped page [0x1000, 0x2000). We use mapped_pages to support multiple
    // uTPs which fall into the same page (e.g., [0x1010, 0x1020] and [0x1100,
    // 0x1110]).
    Splay *vmapping;           // Virtual memory
    Splay *mmapped_pages;      // Mmapped pages
    addr_t max_addr;           // Max virtual address (XXX: excluding endpoint)
    addr_t loader_addr;        // Base address of loader
    addr_t trampolines_addr;   // Base address of trampolines(TP)
    addr_t lookup_table_addr;  // Base address of lookup table
    addr_t shared_text_addr;   // Base address of shared .text (page-aligned)
    addr_t
        retaddr_mapping_addr;  // Base address of retaddr mapping (page-aligned)

    /*
     * Lookup table
     */
    char *lookup_tabname;            // Name of mmapped lookup table
    _MEM_FILE *lookup_table_stream;  //_MEM_FILE of lookup table

    /*
     * Trampolines
     */
    char *trampolines_name;         // Name of mmapped trampolines
    _MEM_FILE *trampolines_stream;  // _MEM_FILE of trampolines

    /*
     * Shared .text section;
     */
    char *shared_text_name;         // Name of shared .text section
    _MEM_FILE *shared_text_stream;  // _MEM_FILE of shared .text section

    /*
     * Pipeline
     */
    char *pipe_filename;  // Name of pipe communicated with daemon

    /*
     * Return address mapping
     */
    char *retaddr_mapping_name;  // Name of the mapping of return addreseses
    _MEM_FILE *retaddr_mapping_stream;  // _MEM_FILE of retaddr mapping

    /*
     * ELF state
     */
    ELFState state;

    /*
     * Relocation information
     */
    GHashTable *got;  // GOT information
    GHashTable *plt;  // PLT information

    /*
     * Other basic information
     */
    bool is_pie;       // Whether the binary is compiled as PIE
    addr_t ori_entry;  // Address of original Entry Point
    addr_t main;       // Address of main
    addr_t init;       // Address of init
    addr_t fini;       // Address of fini
    addr_t load_main;  // Address of the instruction loading main address
    addr_t load_init;  // Address of the instruction loading init address
    addr_t load_fini;  // Address of the instruction loading fini address
});

/*
 * Setter and Getter
 */
DECLARE_SETTER(ELF, elf, Elf64_Ehdr *, ehdr);
DECLARE_SETTER(ELF, elf, Elf64_Phdr *, phdr_note);
DECLARE_SETTER(ELF, elf, Elf64_Phdr *, phdr_dynamic);
DECLARE_SETTER(ELF, elf, Elf64_Shdr *, shdr_shstrtab);
DECLARE_SETTER(ELF, elf, Elf64_Shdr *, shdr_text);
DECLARE_SETTER(ELF, elf, Elf64_Shdr *, shdr_init);
DECLARE_SETTER(ELF, elf, Elf64_Shdr *, shdr_fini);
DECLARE_SETTER(ELF, elf, Elf64_Shdr *, shdr_init_array);
DECLARE_SETTER(ELF, elf, Elf64_Shdr *, shdr_fini_array);
DECLARE_SETTER(ELF, elf, Elf64_Shdr *, shdr_plt);
DECLARE_SETTER(ELF, elf, ELFState, state);

DECLARE_GETTER(ELF, elf, Elf64_Ehdr *, ehdr);
DECLARE_GETTER(ELF, elf, Elf64_Phdr *, phdr_note);
DECLARE_GETTER(ELF, elf, Elf64_Phdr *, phdr_dynamic);
DECLARE_GETTER(ELF, elf, Elf64_Shdr *, shdr_shstrtab);
DECLARE_GETTER(ELF, elf, Elf64_Shdr *, shdr_text);
DECLARE_GETTER(ELF, elf, Elf64_Shdr *, shdr_init);
DECLARE_GETTER(ELF, elf, Elf64_Shdr *, shdr_fini);
DECLARE_GETTER(ELF, elf, Elf64_Shdr *, shdr_init_array);
DECLARE_GETTER(ELF, elf, Elf64_Shdr *, shdr_fini_array);
DECLARE_GETTER(ELF, elf, Elf64_Shdr *, shdr_plt);
DECLARE_GETTER(ELF, elf, addr_t, loader_addr);
DECLARE_GETTER(ELF, elf, addr_t, trampolines_addr);
DECLARE_GETTER(ELF, elf, addr_t, lookup_table_addr);
DECLARE_GETTER(ELF, elf, addr_t, shared_text_addr);
DECLARE_GETTER(ELF, elf, addr_t, retaddr_mapping_addr);
DECLARE_GETTER(ELF, elf, bool, is_pie);
DECLARE_GETTER(ELF, elf, addr_t, ori_entry);
DECLARE_GETTER(ELF, elf, addr_t, main);
DECLARE_GETTER(ELF, elf, addr_t, init);
DECLARE_GETTER(ELF, elf, addr_t, fini);
DECLARE_GETTER(ELF, elf, addr_t, load_main);
DECLARE_GETTER(ELF, elf, addr_t, load_init);
DECLARE_GETTER(ELF, elf, addr_t, load_fini);
DECLARE_GETTER(ELF, elf, const char *, lookup_tabname);
DECLARE_GETTER(ELF, elf, const char *, trampolines_name);
DECLARE_GETTER(ELF, elf, const char *, shared_text_name);
DECLARE_GETTER(ELF, elf, const char *, pipe_filename);
DECLARE_GETTER(ELF, elf, const char *, retaddr_mapping_name);
DECLARE_GETTER(ELF, elf, size_t, plt_n);

/*
 * Open an ELF file.
 */
Z_API ELF *z_elf_open(const char *ori_filename, bool detect_main);

/*
 * Destructor of ELF
 */
Z_API void z_elf_destroy(ELF *e);

/*
 * Save ELF to pathname
 */
Z_API void z_elf_save(ELF *e, const char *pathname);

/*
 * Return a pointer pointed to given virtual address, NULL if the virtual
 * address is invalid.
 */
Z_API Rptr *z_elf_vaddr2ptr(ELF *e, addr_t vaddr);

/*
 * Read data from given virtual address.
 * z_elf_read only reads data from a stream, which means if the requested bytes
 * are cross-stream, z_elf_read only returns the first k bytes in the same
 * stream.
 */
Z_API size_t z_elf_read(ELF *e, addr_t addr, size_t n, void *buf);

/*
 * Forcely read data from given virtual address.
 * Different from z_elf_read, z_elf_read_all forcely read all requested bytes
 * even if they are cross-stream.
 */
Z_API size_t z_elf_read_all(ELF *e, addr_t addr, size_t n, void *buf);

/*
 * Write data to given virtual address.
 * z_elf_write only writes data on a stream, like z_elf_read.
 */
// XXX: note that the z_elf_write only supports writing on data stored in file
// but not those dynamically alloced segments.
Z_API size_t z_elf_write(ELF *e, addr_t addr, size_t n, const void *buf);

// TODO: add z_elf_write_all if necessart

/*
 * Check whether the ELF is statically-linked
 */
Z_API bool z_elf_is_statically_linked(ELF *e);

/*
 * Get PLT information
 */
Z_API const LFuncInfo *z_elf_get_plt_info(ELF *e, addr_t addr);

/*
 * Get GOT information
 */
Z_API const LFuncInfo *z_elf_get_got_info(ELF *e, addr_t addr);

/*
 * Check where region is free.
 */
Z_API bool z_elf_check_region_free(ELF *e, Snode *region);

/*
 * Insert a utp into vmapping.
 */
Z_API bool z_elf_insert_utp(ELF *e, Snode *utp, addr_t *mmap_addr,
                            size_t *mmap_size);

/*
 * Sync all mapping file
 */
Z_API void z_elf_fsync(ELF *e);

/*
 * Create a snapshot for current ELF.
 * Differnt from z_elf_save, this ELF's main body (except loookup tabel and
 * shadow) will remain unchanged even future patches are applied.
 */
Z_API void z_elf_create_snapshot(ELF *e, const char *pathname);

/*
 * Check ELF state
 */
Z_API bool z_elf_check_state(ELF *e, ELFState state);

#endif
