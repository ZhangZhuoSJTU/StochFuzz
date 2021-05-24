/*
 * buffer.h
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

#ifndef __BUFFER_H
#define __BUFFER_H

#include "config.h"

/*
 * Buffer structure for all heap-allocated data
 */
STRUCT(Buffer, {
    uint8_t *raw_buf;
    size_t size;
    size_t chunk_size;
});

/*
 * Setter and Getter
 */
DECLARE_GETTER(Buffer, buffer, size_t, size);
DECLARE_GETTER(Buffer, buffer, uint8_t *, raw_buf);

/*
 * Create a buffer from a raw pointer.
 * If ptr == NULL and size == 0, return an empty buffer
 */
Z_API Buffer *z_buffer_create(const uint8_t *ptr, size_t size);

/*
 * Push a ch into buffer
 */
Z_API void z_buffer_push(Buffer *buf, uint8_t ch);

/*
 * Append src buffer into the end of buffer dst
 */
Z_API void z_buffer_append(Buffer *dst, Buffer *src);

/*
 * Append raw pointer into the end of buffer
 */
Z_API void z_buffer_append_raw(Buffer *buf, const uint8_t *ptr, size_t size);

/*
 * Fill buffer with ch to size bytes
 */
Z_API void z_buffer_fill(Buffer *buf, uint8_t ch, size_t size);

/*
 * Create a buffer and read content from pathname
 */
Z_API Buffer *z_buffer_read_file(const char *pathname);

/*
 * Create a file and write content to pathname
 */
Z_API void z_buffer_write_file(Buffer *buf, const char *pathname);

/*
 * Duplicate a buffer
 */
Z_API Buffer *z_buffer_dup(Buffer *src);

/*
 * Destructor of Buffer
 */
Z_API void z_buffer_destroy(Buffer *buf);

/*
 * Seek an offset, return a pointer to that offset.
 * Return NULL if the offset is invalid.
 */
Z_API uint8_t *z_buffer_seek(Buffer *buf, size_t offset, int whence);

/*
 * Tell an pointer, return the pointer's offset on the buffer.
 * Return MAX of size_t if the pointer is not on the buffer.
 */
Z_API size_t z_buffer_tell(Buffer *buf, const uint8_t *ptr, int whence);

/*
 * Truncate all content after index (included).
 */
Z_API void z_buffer_truncate(Buffer *buf, size_t index);

#endif
