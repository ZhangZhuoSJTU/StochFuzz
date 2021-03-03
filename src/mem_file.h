#ifndef __MEM_FILE_H
#define __MEM_FILE_H

#include "config.h"

/*
 * Use mmap to speed up FILE operations (similar with _IO_FILE)
 */

STRUCT(_MEM_FILE, {
    int fd;
    const char *filename;
    uint8_t *raw_buf;
    uint8_t *cur_ptr;
    size_t size;  // Page-aligned
});

/*
 * Setter and Getter
 */
DECLARE_GETTER(_MEM_FILE, mem_file, const char *, filename);
DECLARE_GETTER(_MEM_FILE, mem_file, uint8_t *, raw_buf);
DECLARE_GETTER(_MEM_FILE, mem_file, uint8_t *, cur_ptr);
DECLARE_GETTER(_MEM_FILE, mem_file, size_t, size);

/*
 * Open a _MEM_FILE with pathname.
 * Currently, we only support "w+" mode.
 */
Z_API _MEM_FILE *z_mem_file_fopen(const char *pathname, const char *mode);

/*
 * Synchronize a _MEM_FILE with its memory mapping.
 */
Z_API void z_mem_file_fsync(_MEM_FILE *stream);

/*
 * Close a _MEM_FILE.
 */
Z_API void z_mem_file_fclose(_MEM_FILE *stream);

/*
 * Write to a _MEM_FILE.
 * Note that only pwrite can extend file.
 */
Z_API size_t z_mem_file_pwrite(_MEM_FILE *stream, const void *buf, size_t count,
                               size_t offset);

/*
 * Read from a _MEM_FILE.
 */
Z_API size_t z_mem_file_pread(_MEM_FILE *stream, void *buf, size_t count,
                              size_t offset);

/*
 * fread for _MEM_FILE.
 */
Z_API size_t z_mem_file_fread(void *ptr, size_t size, size_t nmemb,
                              _MEM_FILE *stream);

/*
 * fwrite for _MEM_FILE.
 */
Z_API size_t z_mem_file_fwrite(void *ptr, size_t size, size_t nmemb,
                               _MEM_FILE *stream);

/*
 * fseek for _MEM_FILE.
 * Currently, we only support SEEK_SET.
 */
Z_API void z_mem_file_fseek(_MEM_FILE *stream, long offset, int whence);

/*
 * ftell for _MEM_FILE.
 */
Z_API long z_mem_file_ftell(_MEM_FILE *stream);

/*
 * suspend a _MEM_FILE, to allow other processes access the underlaying file.
 */
Z_API void z_mem_file_suspend(_MEM_FILE *stream);

/*
 * resume a _MEM_FILE.
 */
Z_API void z_mem_file_resume(_MEM_FILE *stream);

/*
 * save _MEM_FILE as pathname
 */
Z_API void z_mem_file_save_as(_MEM_FILE *stream, const char *pathname);

#endif
