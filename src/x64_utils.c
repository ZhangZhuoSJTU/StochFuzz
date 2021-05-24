/*
 * x64_utils.c
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

#ifndef __X64_UTILS_C
#define __X64_UTILS_C

// XXX: this file is always included into .c file to benifit compiler
// optimization

Z_PRIVATE const uint8_t *z_x64_gen_nop(size_t n) {
    static const char *nop_bufs[15] = {
        "\x90",
        "\x66\x90",
        "\x0F\x1F\x00",
        "\x0F\x1F\x40\x00",
        "\x0F\x1F\x44\x00\x00",
        "\x66\x0F\x1F\x44\x00\x00",
        "\x0F\x1F\x80\x00\x00\x00\x00",
        "\x0F\x1F\x84\x00\x00\x00\x00\x00",
        "\x66\x0F\x1F\x84\x00\x00\x00\x00\x00",
        "\x0F\x1F\x44\x00\x00\x0F\x1F\x44\x00\x00",
        "\x0F\x1F\x44\x00\x00\x66\x0F\x1F\x44\x00\x00",
        "\x66\x0F\x1F\x44\x00\x00\x66\x0F\x1F\x44\x00\x00",
        "\x66\x0F\x1F\x44\x00\x00\x0F\x1F\x80\x00\x00\x00\x00",
        "\x0F\x1F\x80\x00\x00\x00\x00\x0F\x1F\x80\x00\x00\x00\x00",
        "\x0F\x1F\x80\x00\x00\x00\x00\x0F\x1F\x84\x00\x00\x00\x00\x00",
    };

    if (n > 15) {
        EXITME("invalid size for a nop instruction: %d", n);
        return NULL;
    } else {
        return (const uint8_t *)nop_bufs[n - 1];
    }
}

Z_PRIVATE const uint8_t *z_x64_gen_invalid(size_t n) {
    if (n > 15) {
        EXITME("invalid size for an invalid instruction: %d", n);
        return NULL;
    } else {
        const char *buf =
            "\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F";
        return (const uint8_t *)buf;
    }
}

#endif
