#define __GET_PDISASM(d) ((Splay *)((d)->prob_disasm))
#define __SET_PDISASM(d, v)                    \
    do {                                       \
        (d)->prob_disasm = (PhantomType *)(v); \
    } while (0)

typedef struct code_segment_t {
    addr_t addr;
    size_t size;
} CodeSegment;

Z_PRIVATE void __disassembler_pdisasm_create_S(Disassembler *d) {
    const char *original_filename = z_binary_get_original_filename(d->binary);
    const char *codeseg_filename =
        z_strcat(original_filename, CODE_SEGMENT_FILE_SUFFIX);

    __SET_PDISASM(d, z_splay_create(NULL));

    // XXX: code segment file is mainly used for debugging purpose.
    if (!z_access(codeseg_filename, F_OK)) {
        // code segment file exits
        z_info(
            "code segment file (for linear disassembly) is persent, and we will"
            "use those pre-defined code segments");

        Buffer *buf = z_buffer_read_file(codeseg_filename);

        // tail (virtual) code segment
        assert(INVALID_ADDR > 0);
        CodeSegment virtual_code_segment = {
            .addr = INVALID_ADDR,
            .size = 0,
        };
        z_buffer_append_raw(buf, (uint8_t *)&virtual_code_segment,
                            sizeof(virtual_code_segment));

        size_t n = z_buffer_get_size(buf) / sizeof(CodeSegment);
        CodeSegment *codes = (CodeSegment *)z_buffer_get_raw_buf(buf);

        addr_t cur_addr = codes[0].addr;
        size_t cur_size = codes[0].size;
        for (int i = 1; i < n; i++) {
            CodeSegment *code = &(codes[i]);

            if (code->addr <= cur_addr) {
                EXITME("pre-defined code segments are not in increasing order");
            }

            if (code->addr <= cur_addr + cur_size &&
                code->addr != INVALID_ADDR) {
                size_t tmp_size = code->addr + code->size - cur_addr;
                cur_size = (cur_size >= tmp_size ? cur_size : tmp_size);
            } else {
                z_info("pre-defined code segment: [%#lx, %#lx]", cur_addr,
                       cur_addr + cur_size - 1);
                Snode *node = z_snode_create(cur_addr, cur_size, NULL, NULL);
                z_splay_insert(__GET_PDISASM(d), node);

                cur_addr = code->addr;
                cur_size = code->size;
            }
        }

        z_buffer_destroy(buf);
    } else {
        z_info("no code segment file found, patch the whole .text section");
        Snode *node = z_snode_create(d->text_addr, d->text_size, NULL, NULL);
        z_splay_insert(__GET_PDISASM(d), node);
    }

    z_free((char *)codeseg_filename);
}

Z_PRIVATE void __disassembler_pdisasm_destroy_S(Disassembler *d) {
    z_splay_destroy(__GET_PDISASM(d));
}

Z_PRIVATE void __disassembler_pdisasm_start_S(Disassembler *d) {
    /*
     * leave it blank
     */
}

Z_PRIVATE double128_t __disassembler_pdisasm_get_inst_prob_S(Disassembler *d,
                                                             addr_t addr) {
    if (z_splay_search(__GET_PDISASM(d), addr)) {
        return 1.0;
    } else {
        return 0.0;
    }
}

Z_PRIVATE void __disassembler_pdisasm_get_internal_S(
    Disassembler *d, addr_t addr, cs_insn **inst, uint32_t *scc_id,
    double128_t *inst_hint, double128_t *inst_lost, double128_t *data_hint,
    double128_t *D, double128_t *P) {
    EXITME("Probabilisitic Disassembly is not fully supported");
}

Z_PRIVATE void __disassembler_pdisasm_update_S(Disassembler *d, addr_t addr,
                                               bool is_inst) {
    /*
     * leave it blank
     */
}

#undef __GET_PDISASM
#undef __SET_PDISASM
