/*
 * mem_file.c
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

#include "mem_file.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>

#define INIT_SIZE PAGE_SIZE
// XXX: will a small INC_SIZE_POW2 helps reduce fork overhead?
#define INC_SIZE_POW2 (PAGE_SIZE_POW2 + 6)
#define INC_SIZE (1 << INC_SIZE_POW2)

#define _MEM_FILE_DEFINE_GETTER(OTYPE, ONAME, FTYPE, FNAME) \
    Z_API FTYPE z_##ONAME##_##get_##FNAME(OTYPE *ONAME) {   \
        assert(ONAME != NULL);                              \
        __mem_file_check_state(ONAME);                      \
        return ONAME->FNAME;                                \
    }

// Stretch the file size to size.
Z_PRIVATE int __mem_file_stretch_to_size(_MEM_FILE *stream, size_t size);

// Open stream.
Z_PRIVATE void __mem_file_open_stream(_MEM_FILE *stream, bool is_resumed);

// Check the state of _MEM_FILE, to identify whether it is suitable to operate
// on it.
Z_PRIVATE void __mem_file_check_state(_MEM_FILE *stream);

/*
 * Setter and Getter
 */
_MEM_FILE_DEFINE_GETTER(_MEM_FILE, mem_file, const char *, filename);
_MEM_FILE_DEFINE_GETTER(_MEM_FILE, mem_file, uint8_t *, raw_buf);
_MEM_FILE_DEFINE_GETTER(_MEM_FILE, mem_file, uint8_t *, cur_ptr);
_MEM_FILE_DEFINE_GETTER(_MEM_FILE, mem_file, size_t, size);

Z_PRIVATE void __mem_file_check_state(_MEM_FILE *stream) {
    if (!stream) {
        EXITME("try to operate on an empty _MEM_FILE");
    }
    if (stream->fd == INVALID_FD) {
        EXITME("try to operate on a disconnected _MEM_FILE");
    }
}

// XXX: all possible cases when invoking __mem_file_stretch_to_size
//  case 1: stream->size == 0, stream->raw_buf == NULL (open a new file)
//  case 2: stream->size >  0, stream->raw_buf == NULL (resume a file)
//  case 3: stream->size >  0, stream->raw_buf != NULL (update a file)
Z_PRIVATE int __mem_file_stretch_to_size(_MEM_FILE *stream, size_t size) {
    // step (0). valid size
    if (stream->size_fixed) {
        if (size != stream->size) {
            EXITME("try to resize a size-fixed file");
        }
    } else {
        if (size < stream->size) {
            EXITME("the given _MEM_FILE is too large");
        }
    }

    if (!size) {
        EXITME("cannot stretch to 0");
    }

    if (!stream->size && (stream->raw_buf || stream->cur_ptr)) {
        EXITME("impossible case when stream->size == 0");
    }

    // step (1). update the size of underlying file
    // XXX: avoid write on existing data
    if (size > stream->size) {
        if (lseek(stream->fd, size - 1, SEEK_SET) == -1) {
            return -1;
        }

        if (write(stream->fd, "", 1) == -1) {
            return -1;
        }
    }

    // step (2). update memory mapping
    size_t old_size = stream->size;
    size_t new_size = size;

    if (stream->raw_buf) {
        // the raw_ptr exists
        if (new_size != old_size) {
            assert(stream->cur_ptr >= stream->raw_buf);
            size_t cur_offset = stream->cur_ptr - stream->raw_buf;
            if ((stream->raw_buf = mremap(stream->raw_buf, old_size, new_size,
                                          MREMAP_MAYMOVE)) == MAP_FAILED) {
                EXITME("failed to mremap");
            }
            stream->cur_ptr = stream->raw_buf + cur_offset;
        }
    } else {
        // the raw_ptr does not exist
        if ((stream->raw_buf = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, stream->fd, 0)) == MAP_FAILED) {
            EXITME("failed to mmap");
        }
        stream->cur_ptr = stream->raw_buf;
    }

    stream->size = new_size;

    return 0;
}

Z_PRIVATE void __mem_file_open_stream(_MEM_FILE *stream, bool is_resumed) {
    assert(stream != NULL && stream->filename != NULL);

    int flag = (is_resumed ? O_RDWR : O_RDWR | O_CREAT | O_TRUNC);
    size_t file_size = (is_resumed ? stream->size : INIT_SIZE);

    if ((stream->fd = open(stream->filename, flag, (mode_t)0755)) == -1) {
        goto ERROR;
    }

    // XXX: here we can have two cases:
    //  case 1: a new file, where stream->size = 0, stream->raw_buf = NULL
    //  case 2: an old file, where stream->size > 0, stream->raw_buf = NULL
    if (__mem_file_stretch_to_size(stream, file_size) == -1) {
        goto ERROR;
    }

    return;

ERROR:
    z_error("_MEM_FILE open stream: %d(%s)", errno, strerror(errno));
    z_free((void *)stream->filename);
    z_free(stream);
    z_exit(errno);
    return;
}

Z_API _MEM_FILE *z_mem_file_fopen(const char *pathname, const char *mode) {
    if (z_strcmp(mode, "w+")) {
        EXITME("for _MEM_FILE, we only support \"w+\" mode");
    }

    _MEM_FILE *stream = STRUCT_ALLOC(_MEM_FILE);

    stream->filename = z_strdup(pathname);
    stream->raw_buf = stream->cur_ptr = NULL;
    stream->size_fixed = false;

    __mem_file_open_stream(stream, false);

    return stream;
}

Z_API void z_mem_file_fsync(_MEM_FILE *stream) {
    __mem_file_check_state(stream);

    assert(stream != NULL);

    z_trace("fsync _MEM_FILE");
    if (msync(stream->raw_buf, stream->size, MS_SYNC) == -1) {
        z_error("_MEM_FILE fsync: %d(%s)", errno, strerror(errno));
        munmap(stream->raw_buf, stream->size);
        close(stream->fd);
        z_free(stream);
        z_exit(errno);
    }
}

Z_API void z_mem_file_fclose(_MEM_FILE *stream) {
    __mem_file_check_state(stream);

    assert(stream != NULL);

    z_mem_file_fsync(stream);

    if (munmap(stream->raw_buf, stream->size) == -1) {
        z_error("_MEM_FILE fclose: %d(%s)", errno, strerror(errno));
        close(stream->fd);
        z_free(stream);
        z_exit(errno);
    }

    if (close(stream->fd) == -1) {
        z_error("_MEM_FILE fclose: %d(%s)", errno, strerror(errno));
        z_free(stream);
        z_exit(errno);
    }

    z_free((void *)stream->filename);
    z_free(stream);
}

Z_API size_t z_mem_file_pwrite(_MEM_FILE *stream, const void *buf, size_t count,
                               size_t offset) {
    __mem_file_check_state(stream);

    assert(stream != NULL);

    if (stream->size < count + offset) {
        // stretch file size
        size_t new_size = BITS_ALIGN_CELL(count + offset, INC_SIZE_POW2);
        assert(new_size >= count + offset);

        if (__mem_file_stretch_to_size(stream, new_size) == -1) {
            goto ERROR;
        }
    }

    memcpy(stream->raw_buf + offset, buf, count);

    return count;

ERROR:
    z_error("_MEM_FILE pwrite: %d(%s)", errno, strerror(errno));
    close(stream->fd);
    z_free(stream);
    z_exit(errno);
    return SIZE_MAX;
}

Z_API size_t z_mem_file_pread(_MEM_FILE *stream, void *buf, size_t count,
                              size_t offset) {
    __mem_file_check_state(stream);

    assert(stream != NULL);

    if (stream->size < count + offset) {
        EXITME("read too much from _MEM_FILE");
    }

    memcpy(buf, stream->raw_buf + offset, count);
    return count;
}

Z_API size_t z_mem_file_fwrite(void *ptr, size_t size, size_t nmemb,
                               _MEM_FILE *stream) {
    __mem_file_check_state(stream);

    size_t n = z_mem_file_pwrite(stream, ptr, nmemb * size,
                                 stream->cur_ptr - stream->raw_buf);
    stream->cur_ptr += n;
    return n;
}

Z_API void z_mem_file_fix_size(_MEM_FILE *stream, size_t size) {
    __mem_file_check_state(stream);

    if (size < stream->size) {
        EXITME("the size of the given _MEM_FILE is too large");
    }

    if (size % PAGE_SIZE) {
        EXITME("the given size is not page-aligned");
    }

    if (__mem_file_stretch_to_size(stream, size) == -1) {
        EXITME("failed to set size for the underlying file");
    }

    stream->size_fixed = true;
}

Z_API size_t z_mem_file_fread(void *ptr, size_t size, size_t nmemb,
                              _MEM_FILE *stream) {
    __mem_file_check_state(stream);

    size_t n = z_mem_file_pread(stream, ptr, nmemb * size,
                                stream->cur_ptr - stream->raw_buf);
    stream->cur_ptr += n;
    return n;
}

Z_API void z_mem_file_fseek(_MEM_FILE *stream, long offset, int whence) {
    __mem_file_check_state(stream);

    assert(stream != NULL);

    if (whence != SEEK_SET) {
        EXITME("for _MEM_FILE seek, we only support SEEK_SET");
    }

    if (offset >= stream->size) {
        EXITME("offset is out of boundary");
    }

    stream->cur_ptr = stream->raw_buf + offset;
}

Z_API long z_mem_file_ftell(_MEM_FILE *stream) {
    __mem_file_check_state(stream);

    assert(stream != NULL);

    return (long)(stream->cur_ptr - stream->raw_buf);
}

Z_API void z_mem_file_suspend(_MEM_FILE *stream) {
    __mem_file_check_state(stream);

    z_trace("suspend file %s", stream->filename);
    if (stream->fd == INVALID_FD && stream->raw_buf == NULL &&
        stream->cur_ptr == NULL) {
        // XXX: a good place to debug by changing return to EXITME
        z_warn("try to suspend a disconnected file, ignore");
        return;
    }

    z_mem_file_fsync(stream);

    if (close(stream->fd) == -1) {
        z_error("_MEM_FILE suspend: %d(%s)", errno, strerror(errno));
        z_free(stream);
        z_exit(errno);
    }
    stream->fd = INVALID_FD;

    if (munmap(stream->raw_buf, stream->size) == -1) {
        z_error("_MEM_FILE suspend: %d(%s)", errno, strerror(errno));
        close(stream->fd);
        z_free(stream);
        z_exit(errno);
    }
    stream->raw_buf = stream->cur_ptr = NULL;
}

Z_API void z_mem_file_resume(_MEM_FILE *stream) {
    z_trace("resume file %s", stream->filename);
    if (stream->fd != INVALID_FD && stream->raw_buf != NULL &&
        stream->cur_ptr != NULL) {
        // XXX: a good place to debug by changing return to EXITME
        z_warn("try to resume a connected file, ignore");
        return;
    }
    __mem_file_open_stream(stream, true);
}

Z_API void z_mem_file_save_as(_MEM_FILE *stream, const char *pathname) {
    __mem_file_check_state(stream);
    assert(stream != NULL);

    // check whether pathname exists. if so, remove it.
    // Note that we have to remove pathname first. Otherwise, if pathname is
    // linked with any important file (e.g., patched file), directly
    // fopen(pathname, "wb") will rewrite the important file.
    if (!z_access(pathname, F_OK)) {
        if (remove(pathname)) {
            EXITME("failed on remove: %s (error: %s)", pathname,
                   strerror(errno));
        }
    }

    FILE *f = z_fopen(pathname, "wb");
    if (!f) {
        EXITME("fail to open %s", pathname);
    }

    size_t size = z_fwrite(stream->raw_buf, sizeof(uint8_t), stream->size, f);
    if (size != stream->size) {
        EXITME(
            "fail when writing content to \"%s\", expect %ld bytes, but only "
            "%ld bytes (error: %s)",
            pathname, stream->size, size, strerror(errno));
    }

    z_fclose(f);
    if (z_chmod(pathname, 0755)) {
        EXITME("fail when chmod snapshot");
    }
}
