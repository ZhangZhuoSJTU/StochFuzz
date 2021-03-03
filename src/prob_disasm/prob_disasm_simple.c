#define GET_PDISASM(d) ((Splay *)((d)->prob_disasm))
#define SET_PDISASM(d, v)                      \
    do {                                       \
        (d)->prob_disasm = (PhantomType *)(v); \
    } while (0)

Z_PRIVATE void __disassembler_pdisasm_create(Disassembler *d) {
    const char *original_filename = z_binary_get_original_filename(d->binary);
    const char *pdisasm_filename =
        z_strcat(PDISASM_FILENAME_PREFIX, original_filename);

    SET_PDISASM(d, z_splay_create(NULL));

    if (!z_access(pdisasm_filename, F_OK)) {
        // pdisasm file exits
        z_info(
            "p-disam file is persent, and we will use its pre-defined code "
            "segments");

        Buffer *buf = z_buffer_read_file(pdisasm_filename);

        // tail (virtual) code segment
        assert(INVALID_ADDR > 0);
        PDisasmResult virtual_code_segment = {
            .addr = INVALID_ADDR,
            .size = 0,
        };
        z_buffer_append_raw(buf, (uint8_t *)&virtual_code_segment,
                            sizeof(virtual_code_segment));

        size_t n = z_buffer_get_size(buf) / sizeof(PDisasmResult);
        PDisasmResult *codes = (PDisasmResult *)z_buffer_get_raw_buf(buf);

        addr_t cur_addr = codes[0].addr;
        size_t cur_size = codes[0].size;
        for (int i = 1; i < n; i++) {
            PDisasmResult *code = &(codes[i]);

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
                z_splay_insert(GET_PDISASM(d), node);

                cur_addr = code->addr;
                cur_size = code->size;
            }
        }

        z_buffer_destroy(buf);
    } else {
        z_info("no p-disam file found, patch the whole .text section");
        Snode *node = z_snode_create(d->text_addr, d->text_size, NULL, NULL);
        z_splay_insert(GET_PDISASM(d), node);
    }

    z_free((char *)pdisasm_filename);
}

Z_PRIVATE void __disassembler_pdisasm_destroy(Disassembler *d) {
    z_splay_destroy(GET_PDISASM(d));
}

Z_PRIVATE void __disassembler_pdisasm_start(Disassembler *d) {
    /*
     * leave it blank
     */
}

Z_PRIVATE double128_t __disassembler_pdisasm_get_inst_prob(Disassembler *d,
                                                           addr_t addr) {
    if (z_splay_search(GET_PDISASM(d), addr)) {
        return 1.0;
    } else {
        return 0.0;
    }
}

Z_PRIVATE void __disassembler_pdisasm_get_internal(
    Disassembler *d, addr_t addr, cs_insn **inst, uint32_t *scc_id,
    double128_t *inst_hint, double128_t *inst_lost, double128_t *data_hint,
    double128_t *D, double128_t *P) {
    EXITME("Probabilisitic Disassembly is not fully supported");
}
