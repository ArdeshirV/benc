#ifndef BENC_CODECS_H
#define BENC_CODECS_H

/* Progress callback invoked periodically while a codec runs.
 * done/total are byte counts (total may be 0 if unknown). */
typedef void (*benc_progress_fn)(unsigned long long done,
                                 unsigned long long total, void *ctx);

int benc_lzma2_encode(const char *src, const char *dst, int preset, int threads,
                      benc_progress_fn cb, void *cb_ctx);
int benc_lzma2_decode(const char *src, const char *dst,
                      benc_progress_fn cb, void *cb_ctx);
int benc_zstd_encode(const char *src, const char *dst, int level, int threads,
                     benc_progress_fn cb, void *cb_ctx);
int benc_zstd_decode(const char *src, const char *dst,
                     benc_progress_fn cb, void *cb_ctx);

#endif
