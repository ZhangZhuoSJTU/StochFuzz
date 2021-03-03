#include "buffer.h"
#include "utils.h"

/*
 * Extend buffer's chunk so that it can contain at lease new_chunk_size bytes
 */
Z_PRIVATE void __buffer_extend(Buffer *buf, size_t new_chunk_size);

/*
 * Create an empty buffer whose chunk can contain at lease size bytes
 */
Z_PRIVATE Buffer *__buffer_new(size_t size);

Z_PRIVATE Buffer *__buffer_new(size_t size) {
    // Get chunk_size
    size_t chunk_size = 8;
    if (size >= 1) {
        chunk_size = size;
        chunk_size |= (chunk_size >> 1);
        chunk_size |= (chunk_size >> 2);
        chunk_size |= (chunk_size >> 4);
        chunk_size |= (chunk_size >> 8);
        chunk_size |= (chunk_size >> 16);
        chunk_size |= (chunk_size >> 32);
        chunk_size += 1;
    }
    assert(chunk_size > size);

    z_trace("get chunk_size (%#lx) for requested size (%#lx)", chunk_size,
            size);

    // Create a buffer
    Buffer *buf = STRUCT_ALLOC(Buffer);
    buf->raw_buf = (uint8_t *)z_alloc(chunk_size, sizeof(uint8_t));
    buf->size = 0;
    buf->chunk_size = chunk_size;

    return buf;
}

Z_PRIVATE void __buffer_extend(Buffer *buf, size_t new_chunk_size) {
    assert(buf != NULL);
    z_trace("extend to %#lx bytes, original one is %#lx bytes", new_chunk_size,
            buf->chunk_size);
    while (new_chunk_size >= buf->chunk_size) {
        if (buf->chunk_size * 2 <= buf->chunk_size) {
            EXITME("too big chunk size (%#lx)", buf->chunk_size);
        }
        buf->raw_buf = z_realloc(buf->raw_buf, buf->chunk_size * 2);
        buf->chunk_size *= 2;
    }
}

/*
 * Setter and Getter
 */
DEFINE_GETTER(Buffer, buffer, size_t, size);
DEFINE_GETTER(Buffer, buffer, uint8_t *, raw_buf);

Z_API Buffer *z_buffer_create(const uint8_t *ptr, size_t size) {
    Buffer *buf = __buffer_new(size);
    if (ptr != NULL) {
        memcpy(buf->raw_buf, ptr, size);
    } else {
        assert(size == 0);
    }
    buf->size = size;
    return buf;
}

Z_API void z_buffer_push(Buffer *buf, uint8_t ch) {
    assert(buf != NULL);
    __buffer_extend(buf, buf->size + 1);
    buf->raw_buf[buf->size] = ch;
    buf->size += 1;
}

Z_API void z_buffer_append(Buffer *dst, Buffer *src) {
    assert(dst != NULL && src != NULL);
    __buffer_extend(dst, dst->size + src->size);
    memcpy(dst->raw_buf + dst->size, src->raw_buf, src->size);
    dst->size += src->size;
}

Z_API void z_buffer_append_raw(Buffer *buf, const uint8_t *ptr, size_t size) {
    assert(buf != NULL);
    if (ptr != NULL) {
        __buffer_extend(buf, buf->size + size);
        memcpy(buf->raw_buf + buf->size, ptr, size);
        buf->size += size;
    }
}

Z_API Buffer *z_buffer_read_file(const char *pathname) {
    FILE *f = z_fopen(pathname, "rb");

    // Get file size
    z_fseek(f, 0L, SEEK_END);
    size_t f_size = (size_t)z_ftell(f);

    // Create a buffer
    Buffer *buf = (Buffer *)__buffer_new(f_size);

    // Read file
    z_fseek(f, 0L, SEEK_SET);
    size_t r_size = z_fread(buf->raw_buf, sizeof(uint8_t), f_size, f);
    if (r_size < f_size) {
        EXITME("read %lu bytes from \"%s\", but %lu bytes expected", r_size,
               pathname, f_size);
    }
    buf->size = r_size;

    z_fclose(f);

    z_trace("successfully read %lu bytes from \"%s\"", f_size, pathname);
    return buf;
}

Z_API void z_buffer_write_file(Buffer *buf, const char *pathname) {
    assert(buf != NULL);
    FILE *f = z_fopen(pathname, "wb");

    size_t size = z_fwrite(buf->raw_buf, sizeof(uint8_t), buf->size, f);
    if (size != buf->size) {
        EXITME(
            "fail when writing content to \"%s\", expect %ld bytes, but only "
            "%ld bytes",
            pathname, buf->size, size);
    }

    z_fclose(f);
}

Z_API Buffer *z_buffer_dup(Buffer *src) {
    assert(src != NULL);
    Buffer *dst = STRUCT_ALLOC(Buffer);
    dst->size = src->size;
    dst->chunk_size = src->chunk_size;
    dst->raw_buf = z_alloc(dst->chunk_size, sizeof(uint8_t));
    memcpy(dst->raw_buf, src->raw_buf, dst->size);
    return dst;
}

Z_API void z_buffer_destroy(Buffer *buf) {
    assert(buf != NULL);
    // Free Buffer.buf
    memset(buf->raw_buf, 0, buf->size);
    z_free((void *)buf->raw_buf);

    // Free Buffer itself
    memset(buf, 0, sizeof(Buffer));
    z_free((void *)buf);
}

Z_API uint8_t *z_buffer_seek(Buffer *buf, size_t offset, int whence) {
    assert(buf != NULL);
    if (offset >= buf->size) {
        z_warn("offset (%lu) is bigger than buffer size (%lu)", offset,
               buf->size);
        return NULL;
    }

    size_t st_offset;
    if (whence == SEEK_END) {
        // The last byte should be 0 from SEEK_END
        st_offset = buf->size - offset - 1;
    } else if (whence == SEEK_SET) {
        st_offset = offset;
    } else {
        z_warn("invalid whence (%d)", whence);
        return NULL;
    }

    return (buf->raw_buf + st_offset);
}

Z_API size_t z_buffer_tell(Buffer *buf, const uint8_t *ptr, int whence) {
    assert(buf != NULL);
    if (ptr < buf->raw_buf) {
        z_warn("ptr is smaller than buf->raw_buf");
        return SIZE_MAX;
    }

    if (ptr - buf->raw_buf >= buf->size) {
        z_warn("ptr is bigger than buf->raw_buf + buf->size");
        return SIZE_MAX;
    }

    if (whence == SEEK_END) {
        return (buf->size - (ptr - buf->raw_buf) - 1);
    } else if (whence == SEEK_SET) {
        return (ptr - buf->raw_buf);
    } else {
        z_warn("invalid whence (%d)", whence);
        return SIZE_MAX;
    }
}

Z_API void z_buffer_truncate(Buffer *buf, size_t index) {
    assert(buf != NULL);
    if (index >= buf->size) {
        z_trace("index is out of buffer (%lu >= %lu)", index, buf->size);
        return;
    }

    buf->size = index;
}

Z_API void z_buffer_fill(Buffer *buf, uint8_t ch, size_t size) {
    assert(buf != NULL);
    if (size < buf->size) {
        z_warn(
            "buffer's original size (%lu) is bigger than requested size (%lu)",
            buf->size, size);
        return;
    }
    __buffer_extend(buf, size);
    if (ch != 0) {
        // Little optimization
        memset(buf->raw_buf + buf->size, ch, size - buf->size);
    }
    buf->size = size;
}
