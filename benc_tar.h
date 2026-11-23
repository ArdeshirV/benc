#ifndef BENC_TAR_H
#define BENC_TAR_H

/* Minimal built-in tar (create + extract) for directory payloads.
 * No external library or command line tool is used. */

/* Progress callback invoked periodically while tar runs.
 * done/total are byte counts (total may be 0 if unknown). */
typedef void (*benc_tar_progress_fn)(unsigned long long done,
                                     unsigned long long total, void *ctx);

int benc_tar_create(const char *dir, const char *name, const char *dst,
                    benc_tar_progress_fn cb, void *cb_ctx);
int benc_tar_extract(const char *src, const char *dest,
                     benc_tar_progress_fn cb, void *cb_ctx);

#endif
